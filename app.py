from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import logging
import socket
import ssl
import re
import time
import os
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import requests

# Optional import; only used if present
try:
    import whois as pywhois  # type: ignore
except Exception:
    pywhois = None

# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, origins=[
    "https://dnx.bedouiadem.tech",
    "http://localhost",
    "https://dnx.tn",
    "https://localhost",
    "http://127.0.0.1",
    "https://127.0.0.1"
])

# Configuration
MAX_WORKERS = 4
# detect Vercel / serverless env -> reduce concurrency to keep cold-start small
if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    MAX_WORKERS = min(MAX_WORKERS, 2)

SOCKET_TIMEOUT = 8.0
WHOIS_TIMEOUT = 6
CACHE_TTL = 3600  # seconds, 1 hour

_cache: Dict[str, Tuple[Any, float]] = {}

# Cloudflare DNS-over-HTTPS base (JSON)
DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_HEADERS = {"Accept": "application/dns-json", "User-Agent": "dnxapi/1.0"}


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def clean_domain(domain: str) -> str:
    domain = re.sub(r"^https?://", "", domain, flags=re.IGNORECASE)
    domain = domain.split("/")[0].split(":")[0]
    domain = re.sub(r"^www\.", "", domain, flags=re.IGNORECASE)
    return domain.strip().lower()


def get_cached(key: str) -> Optional[Any]:
    if key in _cache:
        data, ts = _cache[key]
        if time.time() - ts < CACHE_TTL:
            logger.debug(f"Cache hit for {key}")
            return data
        else:
            del _cache[key]
    return None


def set_cache(key: str, value: Any) -> None:
    _cache[key] = (value, time.time())


def clear_cache() -> None:
    _cache.clear()


# -----------------------------------------------------------------------------
# DNS (DoH fallback to avoid system-level deps)
# -----------------------------------------------------------------------------
def doh_query(name: str, rtype: str) -> List[str]:
    """Query Cloudflare DNS-over-HTTPS for a specific record type. Returns list of strings (answers)."""
    try:
        params = {"name": name, "type": rtype}
        resp = requests.get(DOH_URL, params=params, headers=DOH_HEADERS, timeout=3.0)
        if resp.status_code != 200:
            logger.debug(f"DoH {rtype} {name} returned status {resp.status_code}")
            return []
        data = resp.json()
        answers = data.get("Answer") or []
        out: List[str] = []
        for a in answers:
            # 'data' value depends on type (TXT quoted, MX includes priority, etc.)
            val = a.get("data", "")
            if not val:
                continue
            # For TXT, Cloudflare returns like '"v=spf1 ..."' — strip quotes
            if rtype.upper() == "TXT":
                # remove leading/trailing quotes if present
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
            out.append(val)
        return out
    except Exception as e:
        logger.debug(f"DoH query failed for {name} {rtype}: {e}")
        return []


def get_ip_via_socket(domain: str) -> Optional[str]:
    """Quick IPv4 prefered resolution via socket. Very fast and available in stdlib."""
    try:
        info = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        for fam, _type, _proto, _name, sockaddr in info:
            if fam == socket.AF_INET:
                return sockaddr[0]
        if info:
            return info[0][4][0]
    except Exception as e:
        logger.debug(f"socket getaddrinfo failed for {domain}: {e}")
    return None


def get_reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as e:
        logger.debug(f"reverse DNS failed for {ip}: {e}")
        return None


# -----------------------------------------------------------------------------
# WHOIS (optional)
# -----------------------------------------------------------------------------
def whois_lookup(domain: str) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """
    Try python-whois if available. If not installed, return (None, None, None)
    """
    if pywhois is None:
        return None, None, None

    try:
        w = pywhois.whois(domain)
        raw = str(w)
        creation = None
        created = getattr(w, "creation_date", None)
        if created:
            if isinstance(created, list) and created:
                d0 = created[0]
                if hasattr(d0, "strftime"):
                    creation = d0.strftime("%Y-%m-%d")
            elif hasattr(created, "strftime"):
                creation = created.strftime("%Y-%m-%d")

        statuses: List[str] = []
        st = getattr(w, "status", None)
        if isinstance(st, list):
            statuses = [str(s).split()[0].upper() for s in st if s]
        elif isinstance(st, str):
            statuses = [st.split()[0].upper()]

        registrar = None
        if hasattr(w, "registrar") and w.registrar:
            registrar = str(w.registrar).strip()

        data = {"creation_date": creation, "domain_status": list(set([s for s in statuses if s and s != "ACTIVE"]))}
        return data, registrar, raw
    except Exception as e:
        logger.debug(f"python-whois lookup failed for {domain}: {e}")
        return None, None, None


# -----------------------------------------------------------------------------
# SSL (use stdlib)
# -----------------------------------------------------------------------------
def get_ssl_info(domain: str, port: int = 443) -> Dict[str, Any]:
    """Use SSL socket to get cert information via getpeercert (no PyOpenSSL required)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, port), timeout=SOCKET_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()  # parsed cert (dict)
    except Exception as e:
        logger.debug(f"SSL handshake failed for {domain}: {e}")
        return {"status": "Error", "error": str(e)}

    # cert is a dict with keys like subject, issuer, notBefore, notAfter, subjectAltName
    try:
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        # convert to datetime if strings present in format 'Jun  1 12:00:00 2024 GMT'
        def parse_openssl_date(s: Optional[str]) -> Optional[str]:
            if not s:
                return None
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
                try:
                    dt = datetime.strptime(s, fmt)
                    return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
                except Exception:
                    continue
            return s

        valid_from = parse_openssl_date(not_before)
        valid_until = parse_openssl_date(not_after)

        issuer = "Unknown"
        try:
            issuer_t = cert.get("issuer")
            if issuer_t:
                # issuer is a tuple of tuples like ((('commonName', 'Let's Encrypt'),), ...)
                parts = []
                for rdn in issuer_t:
                    for kv in rdn:
                        parts.append(f"{kv[0]}={kv[1]}")
                issuer = ", ".join(parts)
        except Exception:
            pass

        subject_cn = "Unknown"
        try:
            subject = cert.get("subject")
            if subject:
                for rdn in subject:
                    for kv in rdn:
                        if kv[0].lower() in ("commonname", "cn"):
                            subject_cn = kv[1]
                            break
        except Exception:
            pass

        san = None
        try:
            san = [v for (k, v) in cert.get("subjectAltName", [])] if cert.get("subjectAltName") else None
        except Exception:
            san = None

        # days left
        days_left = None
        try:
            if valid_until:
                # try parse
                dt = datetime.strptime(valid_until, "%Y-%m-%d %H:%M:%S %Z")
                days_left = max(0, (dt - datetime.now(timezone.utc)).days)
        except Exception:
            days_left = None

        status = "Valid"
        try:
            if valid_from and valid_until:
                dt_from = datetime.strptime(valid_from, "%Y-%m-%d %H:%M:%S %Z")
                dt_to = datetime.strptime(valid_until, "%Y-%m-%d %H:%M:%S %Z")
                now = datetime.now(timezone.utc)
                if not (dt_from <= now <= dt_to):
                    status = "Invalid"
        except Exception:
            pass

        return {
            "status": status,
            "issuer": issuer,
            "subject": subject_cn,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "days_until_expiry": days_left,
            "subject_alt_names": san,
        }
    except Exception as e:
        logger.debug(f"Error parsing SSL cert for {domain}: {e}")
        return {"status": "Error", "error": "parsing failed", "raw_error": str(e)}


# -----------------------------------------------------------------------------
# Domain check orchestration
# -----------------------------------------------------------------------------
def get_domain_status_from_whois(whois_data: Optional[Dict[str, Any]], domain_statuses: List[str]) -> str:
    if whois_data is None:
        return "Available"
    if domain_statuses:
        statuses_lower = [s.lower() for s in domain_statuses]
        if any("hold" in s for s in statuses_lower):
            return "Registered (On Hold)"
        if any("pending" in s for s in statuses_lower):
            return "Registered (Pending)"
        if any("redemption" in s for s in statuses_lower):
            return "Registered (Redemption Period)"
    return "Registered"


def check_domain_data(domain: str) -> Dict[str, Any]:
    start_ts = time.time()
    warnings: List[str] = []
    domain = clean_domain(domain)
    if not domain:
        return {"error": "Domain is required"}

    cache_key = f"domain:{domain}"
    cached = get_cached(cache_key)
    if cached:
        return cached

    # Basic IP lookup
    ip = get_ip_via_socket(domain)
    reverse_dns = get_reverse_dns(ip) if ip else None

    # Prepare concurrent tasks that are safe in serverless
    results: Dict[str, Any] = {}

    def task_dns(rtype: str):
        return doh_query(domain, rtype)

    def task_whois():
        return whois_lookup(domain)

    def task_ssl():
        if ip:
            return get_ssl_info(domain)
        return {"status": "Unavailable", "error": "Domain does not resolve"}

    # Launch tasks (DNS records and optional whois/ssl)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            "A": pool.submit(task_dns, "A"),
            "MX": pool.submit(task_dns, "MX"),
            "NS": pool.submit(task_dns, "NS"),
            "TXT_ALL": pool.submit(task_dns, "TXT"),
            "DKIM": pool.submit(task_dns, "TXT"),   # DKIM commonly under selector._domainkey; we keep general TXT fallback
            "DMARC": pool.submit(task_dns, "TXT"),
            "WHOIS": pool.submit(task_whois),
            "SSL": pool.submit(task_ssl),
        }

        # collect
        for name, fut in futures.items():
            try:
                results[name] = fut.result(timeout=15)
            except Exception as e:
                logger.debug(f"Task {name} failed: {e}")
                if name in ("A", "MX", "NS", "TXT_ALL", "DKIM", "DMARC"):
                    results[name] = []
                elif name == "WHOIS":
                    results[name] = (None, None, None)
                elif name == "SSL":
                    results[name] = {"status": "Error", "error": str(e)}

    # Postprocess TXT, DMARC, DKIM
    txt_all: List[str] = results.get("TXT_ALL", []) or []
    spf = [r for r in txt_all if "v=spf1" in r.lower()]
    dmarc_candidates = results.get("DMARC", []) or []
    dmarc_filtered = [r for r in dmarc_candidates if "v=dmarc1" in r.lower()]

    # For DKIM: look for default selector pattern if available in TXT answers
    dkim_candidates = []
    try:
        # check TXT under default._domainkey.<domain> via separate DoH call (cheap)
        dkim_candidates = doh_query(f"default._domainkey.{domain}", "TXT")
    except Exception:
        dkim_candidates = []
    if not dkim_candidates:
        # fallback: try to detect 'v=DKIM1' in TXT_ALL
        dkim_candidates = [r for r in txt_all if "v=dkim1" in r.lower()]

    whois_data, registrar_name, raw_whois = results.get("WHOIS", (None, None, None))
    domain_statuses = (whois_data or {}).get("domain_status", []) if whois_data else []
    status = get_domain_status_from_whois(whois_data, domain_statuses)

    response = {
        "domain": domain,
        "status": status,
        "ip_address": ip,
        "reverse_dns": reverse_dns,
        "A": results.get("A", []),
        "MX": [m.split()[-1].rstrip(".") for m in (results.get("MX") or [])],  # MX entries often '10 mail.example.'
        "nameservers": [n.rstrip(".") for n in (results.get("NS") or [])],
        "SPF": spf,
        "DKIM": dkim_candidates,
        "DMARC": dmarc_filtered,
        "domain_status": domain_statuses,
        "registration_date": (whois_data or {}).get("creation_date") if whois_data else None,
        "registrar_name": registrar_name,
        "ssl": results.get("SSL"),
    }

    # Add WHOIS raw or warnings if WHOIS unavailable
    if pywhois is None:
        warnings.append("python-whois not installed; WHOIS data unavailable.")
    else:
        if whois_data is None:
            warnings.append("WHOIS lookup returned no data or failed.")

    # If DNS DoH returned no answers at all for A/MX/NS/TXT, warn
    if not any(results.get(k) for k in ("A", "MX", "NS", "TXT_ALL")):
        warnings.append("DNS lookups returned no records (possible network error or domain truly has no records).")

    if warnings:
        response["warnings"] = warnings

    # Clean empty values
    result = {k: v for k, v in response.items() if v not in (None, "", [], {})}

    # Only cache when we have meaningful non-empty data (avoid caching failure/no-data states)
    meaningful = bool(result.get("A") or result.get("MX") or result.get("nameservers") or result.get("registration_date") or result.get("ssl"))
    if meaningful:
        set_cache(cache_key, result)
    else:
        logger.debug(f"Not caching result for {domain} because it's not meaningful: {result}")

    logger.debug(f"Domain check for {domain} completed in {(time.time() - start_ts)*1000:.0f}ms")
    return result


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/api/check-domain", methods=["POST"])
def check_domain_post():
    try:
        data = request.get_json(silent=True) or {}
        raw_domain = (data.get("domain") or "").strip()
        if not raw_domain:
            return jsonify({"error": "Domain is required"}), 400
        result = check_domain_data(raw_domain)
        if "error" in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        logger.exception("Error in /api/check-domain POST")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/check-domain", methods=["GET"])
def check_domain_get():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    result = check_domain_data(domain)
    if "error" in result:
        return jsonify(result), 400
    resp = make_response(jsonify(result))
    # Let Vercel CDN cache this GET response briefly; safe for many lookups
    resp.headers["Cache-Control"] = "s-maxage=60, stale-while-revalidate=120"
    return resp


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "version": "3.0.0"})


@app.route("/api/cache/clear", methods=["POST"])
def clear_cache_route():
    clear_cache()
    return jsonify({"status": "cache cleared"})


if __name__ == "__main__":
    # Local dev server
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
