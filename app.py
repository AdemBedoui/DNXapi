from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import logging
import socket
import re
import subprocess
import ssl
import time
import os
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional dependencies stored as module-level placeholders and imported lazily
dns = None
crypto = None
pywhois = None

# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
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
# If running on serverless (Vercel), reduce concurrent workers to lower startup overhead
if os.environ.get("VERCEL") == "1" or os.environ.get("VERCEL") == "true":
    MAX_WORKERS = min(MAX_WORKERS, 2)

DNS_TIMEOUT = 2.0
DNS_LIFETIME = 3.0
SOCKET_TIMEOUT = 8.0
WHOIS_TIMEOUT = 6  # lower the fallback whois timeout on serverless

# Simple in-memory cache (consider Redis / Upstash for production)
_cache = {}
CACHE_TTL = 3600  # 1 hour

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def clean_domain(domain: str) -> str:
    """Normalize domain input."""
    domain = re.sub(r'^https?://', '', domain, flags=re.IGNORECASE)
    domain = domain.split('/')[0].split(':')[0]
    domain = re.sub(r'^www\.', '', domain, flags=re.IGNORECASE)
    return domain.strip().lower()


def get_cached(key: str) -> Optional[Any]:
    """Get from cache if not expired."""
    if key in _cache:
        data, timestamp = _cache[key]
        if time.time() - timestamp < CACHE_TTL:
            logger.debug(f"Cache hit for {key}")
            return data
        else:
            del _cache[key]
    return None


def set_cache(key: str, value: Any) -> None:
    """Store in cache."""
    _cache[key] = (value, time.time())


def get_ip(domain: str) -> Optional[str]:
    """Resolve A record (IPv4 preferred). Use socket.getaddrinfo as quick method."""
    try:
        info = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        for fam, _type, _proto, _name, sockaddr in info:
            if fam == socket.AF_INET:
                return sockaddr[0]
        return info[0][4][0] if info else None
    except Exception as e:
        logger.debug(f"IP resolution failed for {domain}: {e}")
        return None


def get_reverse_dns(ip: str) -> Optional[str]:
    """Get reverse DNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as e:
        logger.debug(f"Reverse DNS failed for {ip}: {e}")
        return None


# Improved: check if domain actually resolves
def get_domain_status_from_whois(whois_data: Optional[Dict[str, Any]], domain_statuses: List[str]) -> str:
    """
    Determine domain status from WHOIS data.
    WHOIS is the source of truth for domain registration.
    """
    if whois_data is None:
        # No WHOIS data = domain not found in registry
        return "Available"

    # Domain is in the registry (registered)
    if domain_statuses:
        statuses_lower = [s.lower() for s in domain_statuses]

        if any('hold' in s for s in statuses_lower):
            return "Registered (On Hold)"
        if any('pending' in s for s in statuses_lower):
            return "Registered (Pending)"
        if any('redemption' in s for s in statuses_lower):
            return "Registered (Redemption Period)"

    return "Registered"


# -----------------------------------------------------------------------------
# DNS with timeouts + caching (lazy dnspython import)
# -----------------------------------------------------------------------------
class DNSHelper:
    def __init__(self, warnings: List[str]):
        global dns
        self.warnings = warnings
        self.cache: Dict[Tuple[str, str], List[str]] = {}
        self.available = False

        # Lazy import dnspython only when DNS features are used
        if dns is None:
            try:
                import dns as _dns  # type: ignore
                dns = _dns
            except Exception:
                dns = None

        self.available = dns is not None and hasattr(dns, "resolver")

        if self.available:
            try:
                self.resolver = dns.resolver.Resolver()
                self.resolver.timeout = DNS_TIMEOUT
                self.resolver.lifetime = DNS_LIFETIME
                if hasattr(self.resolver, "retry_servfail"):
                    self.resolver.retry_servfail = 0
            except Exception as e:
                self.available = False
                self.warnings.append(f"DNS resolver init failed: {e}")

    def _query(self, name: str, rtype: str) -> List[str]:
        key = (name, rtype)
        if key in self.cache:
            return self.cache[key]

        if not self.available:
            # Fast warning; avoid trying network work if dnspython missing
            if "DNS lookups unavailable" not in self.warnings:
                self.warnings.append("DNS lookups unavailable (dnspython not installed).")
            self.cache[key] = []
            return []

        try:
            answers = self.resolver.resolve(name, rtype)
            out = [r.to_text() for r in answers]
            self.cache[key] = out
            return out
        except Exception as e:
            logger.debug(f"DNS {rtype} lookup failed for {name}: {e}")
            self.cache[key] = []
            return []

    def records(self, domain: str, rtype: str) -> List[str]:
        return self._query(domain, rtype)

    def specific(self, domain: str, rtype: str, host: str) -> List[str]:
        fqdn = f"{host}.{domain}".strip(".")
        return self._query(fqdn, rtype)


# -----------------------------------------------------------------------------
# WHOIS helpers (lazy import for python-whois, avoid subprocess on serverless)
# -----------------------------------------------------------------------------
def run_whois_subprocess(domain: str, timeout: int = WHOIS_TIMEOUT) -> Optional[str]:
    """Fallback WHOIS via system command — fast-fail on serverless platforms."""
    # if we are on Vercel or environment without whois binary, skip quickly
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        logger.debug("Skipping whois subprocess on serverless platform")
        return None

    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
        return None
    except subprocess.TimeoutExpired:
        logger.debug(f"whois subprocess timeout for {domain}")
        return None
    except Exception as e:
        logger.debug(f"whois subprocess error for {domain}: {e}")
        return None


def parse_generic_whois(text: str) -> Dict[str, Any]:
    """Parse common WHOIS fields."""
    domain_statuses = []
    creation = None

    for status in re.findall(r"Domain Status:\s*([^\n\r]+)", text, re.IGNORECASE):
        code = status.split()[0].strip().upper()
        if code and code != "ACTIVE":
            domain_statuses.append(code)

    patterns = [
        r"Creation Date:\s*([^\n\r]+)",
        r"Created On:\s*([^\n\r]+)",
        r"Created:\s*([^\n\r]+)",
        r"Registration Date:\s*([^\n\r]+)"
    ]
    for pattern in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            continue
        date_str = m.group(1).strip()
        for fmt in [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%d-%b-%Y",
            "%Y-%m-%d",
            "%Y-%m-%d %H:%M:%S %Z",
            "%b %d %H:%M:%S %Y %Z"
        ]:
            try:
                creation_dt = datetime.strptime(date_str, fmt)
                creation = creation_dt.strftime("%Y-%m-%d")
                break
            except ValueError:
                continue
        if creation:
            break

    return {
        "creation_date": creation,
        "domain_status": list(set(domain_statuses))
    }


def extract_registrar_name(whois_text: str, domain: str = "") -> Optional[str]:
    if not whois_text:
        return None
    patterns = [
        r"Registrar:\s*([^\n\r]+)",
        r"Registrar Name:\s*([^\n\r]+)",
        r"Sponsoring Registrar:\s*([^\n\r]+)",
        r"Registrar Organization:\s*([^\n\r]+)",
    ]
    for p in patterns:
        m = re.search(p, whois_text, re.IGNORECASE)
        if m:
            reg = m.group(1).strip()
            if reg and reg.lower() not in ("", "none", "n/a"):
                return reg
    return None


def parse_whois_tn(text: str) -> Optional[Dict[str, Any]]:
    match = re.search(r"# whois\.ati\.tn(.*)", text, re.DOTALL | re.IGNORECASE)
    if not match:
        return None

    section = match.group(1)
    creation = None
    domain_statuses = []
    registrar = None
    registrant = None
    admin_contact = None

    creation_match = re.search(r"Creation date\s*\.{7,}\s*:\s*(.+)", section, re.IGNORECASE)
    if creation_match:
        date_str = creation_match.group(1).strip()
        try:
            date_clean = re.match(r"(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})", date_str)
            if date_clean:
                creation = datetime.strptime(date_clean.group(1), "%d-%m-%Y %H:%M:%S").strftime("%Y-%m-%d")
        except Exception as e:
            logger.debug(f"Error parsing .tn creation date: {e}")

    status_matches = re.findall(r"Domain status\s*\.{7,}\s*:\s*([^\n\r]+)", section, re.IGNORECASE)
    for status in status_matches:
        clean_status = status.strip().upper().lstrip(":").strip()
        if clean_status and clean_status != "ACTIVE":
            domain_statuses.append(clean_status)

    registrar_match = re.search(r"Registrar\s*\.{7,}\s*:\s*(.+)", section, re.IGNORECASE)
    if registrar_match:
        registrar = registrar_match.group(1).strip()
        if registrar.lower() in ['', 'none', 'n/a']:
            registrar = "ATI (Agence Tunisienne d'Internet)"
    else:
        registrar = "ATI (Agence Tunisienne d'Internet)"

    registrant_name = None
    registrant_first_name = None
    owner_section_match = re.search(
        r"Owner Contact(.*?)(?:Administrativ contact|Technical contact|DNS servers|$)",
        section,
        re.IGNORECASE | re.DOTALL
    )
    if owner_section_match:
        owner_section = owner_section_match.group(1)
        name_match = re.search(r"Name\s*\.*\s*:\s*([^\n\r]+)", owner_section, re.IGNORECASE)
        if name_match:
            registrant_name = name_match.group(1).strip()
            if not registrant_name or registrant_name.lower() in ['address', 'none', 'n/a'] or 'address' in registrant_name.lower():
                registrant_name = None
        first_name_match = re.search(r"First name\s*\.*\s*:\s*([^\n\r]+)", owner_section, re.IGNORECASE)
        if first_name_match:
            registrant_first_name = first_name_match.group(1).strip()
            if not registrant_first_name or registrant_first_name.lower() in ['address', 'none', 'n/a'] or 'address' in registrant_first_name.lower():
                registrant_first_name = None

    if registrant_name and registrant_first_name:
        registrant = f"{registrant_name} {registrant_first_name}"
    elif registrant_name:
        registrant = registrant_name
    elif registrant_first_name:
        registrant = registrant_first_name

    admin_name = None
    admin_first_name = None
    admin_section_match = re.search(
        r"Administrativ contact(.*?)(?:Technical contact|DNS servers|$)",
        section,
        re.IGNORECASE | re.DOTALL
    )
    if admin_section_match:
        admin_section = admin_section_match.group(1)
        admin_name_match = re.search(r"Name\s*\.*\s*:\s*([^\n\r]+)", admin_section, re.IGNORECASE)
        if admin_name_match:
            admin_name = admin_name_match.group(1).strip()
            if not admin_name or admin_name.lower() in ['address', 'none', 'n/a'] or 'address' in admin_name.lower():
                admin_name = None
        admin_first_name_match = re.search(r"First name\s*\.*\s*:\s*([^\n\r]+)", admin_section, re.IGNORECASE)
        if admin_first_name_match:
            admin_first_name = admin_first_name_match.group(1).strip()
            if not admin_first_name or admin_first_name.lower() in ['address', 'none', 'n/a'] or 'address' in admin_first_name.lower():
                admin_first_name = None

    if admin_name and admin_first_name:
        admin_contact = f"{admin_name} {admin_first_name}"
    elif admin_name:
        admin_contact = admin_name
    elif admin_first_name:
        admin_contact = admin_first_name

    return {
        "creation_date": creation,
        "domain_status": list(set(domain_statuses)),
        "registrar": registrar,
        "registrant": registrant,
        "admin_contact": admin_contact
    }


def whois_lookup(domain: str, warnings: List[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """WHOIS lookup with fallbacks and lazy import of python-whois."""
    global pywhois
    raw = None
    data = None
    registrar = None

    try:
        # Try python-whois if available (lazy import)
        if pywhois is None:
            try:
                import whois as _pywhois  # type: ignore
                pywhois = _pywhois
            except Exception:
                pywhois = None

        if pywhois:
            try:
                w = pywhois.whois(domain)
                raw = str(w)

                # Extract creation date
                creation = None
                created = getattr(w, "creation_date", None)
                if created:
                    if isinstance(created, list):
                        d0 = created[0]
                        if hasattr(d0, "strftime"):
                            creation = d0.strftime("%Y-%m-%d")
                    elif hasattr(created, "strftime"):
                        creation = created.strftime("%Y-%m-%d")

                statuses = []
                st = getattr(w, "status", None)
                if isinstance(st, list):
                    statuses = [str(s).split()[0].upper() for s in st if s]
                elif isinstance(st, str):
                    statuses = [st.split()[0].upper()]

                if hasattr(w, "registrar") and w.registrar:
                    registrar = str(w.registrar).strip()

                data = {
                    "creation_date": creation,
                    "domain_status": list(set([s for s in statuses if s and s != "ACTIVE"]))
                }
            except Exception as e:
                logger.debug(f"python-whois failed: {e}")
                raw = None

        # Fallback to subprocess whois if python-whois failed AND platform has whois available
        if raw is None:
            raw = run_whois_subprocess(domain)
            if raw:
                if domain.endswith(".tn"):
                    data = parse_whois_tn(raw)
                    if data and data.get("registrar"):
                        registrar = data.get("registrar")
                    else:
                        registrar = "ATI (Agence Tunisienne d'Internet)"
                else:
                    data = parse_generic_whois(raw)
                    registrar = extract_registrar_name(raw, domain)
    except Exception as e:
        warnings.append(f"WHOIS lookup error: {e}")
        logger.debug(f"WHOIS error for {domain}: {e}")

    return data, registrar, raw


# -----------------------------------------------------------------------------
# SSL Certificate Information (lazy OpenSSL import)
# -----------------------------------------------------------------------------
def _ctx_default() -> ssl.SSLContext:
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _ctx_tls12() -> ssl.SSLContext:
    c = _ctx_default()
    if hasattr(ssl, "TLSVersion"):
        c.minimum_version = ssl.TLSVersion.TLSv1_2
        c.maximum_version = ssl.TLSVersion.TLSv1_2
    return c


def _ctx_tls13() -> ssl.SSLContext:
    c = _ctx_default()
    if hasattr(ssl, "TLSVersion"):
        c.minimum_version = ssl.TLSVersion.TLSv1_3
        c.maximum_version = ssl.TLSVersion.TLSv1_3
    return c


def _ssl_try_connect(domain: str, port: int, ctx: ssl.SSLContext) -> bytes:
    with socket.create_connection((domain, port), timeout=SOCKET_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            return ssock.getpeercert(binary_form=True)


def get_ssl_info(domain: str, warnings: List[str]) -> Dict[str, Any]:
    """Get SSL certificate details. Lazy-import PyOpenSSL if available."""
    global crypto
    if crypto is None:
        try:
            from OpenSSL import crypto as _crypto  # type: ignore
            crypto = _crypto
        except Exception:
            crypto = None

    if crypto is None:
        warnings.append("PyOpenSSL not installed; SSL details unavailable.")
        return {"status": "Unavailable", "error": "pyOpenSSL not installed"}

    attempts = []
    for make_ctx, label in [(_ctx_default, "default"), (_ctx_tls13, "tls1_3"), (_ctx_tls12, "tls1_2")]:
        try:
            der = _ssl_try_connect(domain, 443, make_ctx())
            attempts.append((label, "ok"))
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der)

            issuer = dict(x509.get_issuer().get_components())
            subject = dict(x509.get_subject().get_components())

            issuer_name = (issuer.get(b'O') or issuer.get(b'CN') or b"Unknown").decode(errors="ignore")
            subject_cn = (subject.get(b'CN') or b"Unknown").decode(errors="ignore")

            not_before = datetime.strptime(
                x509.get_notBefore().decode("ascii"),
                "%Y%m%d%H%M%SZ"
            ).replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(
                x509.get_notAfter().decode("ascii"),
                "%Y%m%d%H%M%SZ"
            ).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)

            san_list: List[str] = []
            try:
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    if ext.get_short_name().decode() == "subjectAltName":
                        san_list = [x.strip() for x in str(ext).split(",")]
                        break
            except Exception:
                pass

            is_self_signed = x509.get_issuer().der() == x509.get_subject().der()

            key_bits = None
            try:
                key_bits = x509.get_pubkey().bits()
            except Exception:
                pass

            sig_alg = None
            try:
                sig_alg = x509.get_signature_algorithm().decode(errors="ignore")
            except Exception:
                pass

            status = "Valid" if (not_before <= now <= not_after) else "Invalid"
            days_left = max(0, (not_after - now).days)

            return {
                "status": status,
                "issuer": issuer_name,
                "subject": subject_cn,
                "valid_from": not_before.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "valid_until": not_after.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "days_until_expiry": days_left,
                "is_self_signed": is_self_signed,
                "key_size": key_bits,
                "signature_algorithm": sig_alg,
                "subject_alt_names": san_list or None,
                "handshake_context": label
            }
        except Exception as e:
            attempts.append((label, f"fail: {e}"))
            continue

    warnings.append(f"SSL handshake failed in all contexts")
    return {"status": "Error", "error": "SSL handshake failed", "attempts": attempts}


# -----------------------------------------------------------------------------
# Core domain check
# -----------------------------------------------------------------------------
def check_domain_data(domain: str) -> Dict[str, Any]:
    """
    Main domain checker.
    WHOIS is the source of truth: if WHOIS has no data, domain is Available.
    IP resolution is informational only.
    """
    start_ts = time.time()
    warnings: List[str] = []
    domain = clean_domain(domain)

    if not domain:
        return {"error": "Domain is required"}

    # Check cache
    cache_key = f"domain:{domain}"
    cached = get_cached(cache_key)
    if cached:
        logger.debug(f"Returning cached result for {domain} ({time.time() - start_ts:.1f}ms)")
        return cached

    # Quick IP check (fast)
    ip = get_ip(domain)
    reverse_dns = get_reverse_dns(ip) if ip else None

    dns_helper = DNSHelper(warnings)

    tasks = {}
    results: Dict[str, Any] = {}

    # Use ThreadPoolExecutor for blocking IO. MAX_WORKERS reduced on serverless.
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        tasks["A"] = pool.submit(dns_helper.records, domain, "A")
        tasks["MX"] = pool.submit(dns_helper.records, domain, "MX")
        tasks["NS"] = pool.submit(dns_helper.records, domain, "NS")
        tasks["TXT_ALL"] = pool.submit(dns_helper.records, domain, "TXT")
        tasks["DKIM"] = pool.submit(dns_helper.specific, domain, "TXT", "default._domainkey")
        tasks["DMARC"] = pool.submit(dns_helper.specific, domain, "TXT", "_dmarc")

        # WHOIS (source of truth)
        tasks["WHOIS"] = pool.submit(whois_lookup, domain, warnings)

        # SSL (only if IP is resolvable)
        if ip:
            tasks["SSL"] = pool.submit(get_ssl_info, domain, warnings)
        else:
            results["ssl"] = {"status": "Unavailable", "error": "Domain does not resolve"}

        # Collect results with timeout
        for name, fut in tasks.items():
            try:
                res = fut.result(timeout=15)
                results[name] = res
            except Exception as e:
                logger.debug(f"Task {name} failed: {e}")
                if name in ("A", "MX", "NS", "TXT_ALL", "DKIM", "DMARC"):
                    results[name] = []
                elif name == "SSL":
                    results[name] = {"status": "Error", "error": str(e)}
                elif name == "WHOIS":
                    results[name] = (None, None, None)

    txt_all: List[str] = results.get("TXT_ALL", []) or []
    spf = [r for r in txt_all if "v=spf1" in r.lower()]
    dmarc_raw: List[str] = results.get("DMARC", []) or []
    dmarc_filtered = [r for r in dmarc_raw if "v=dmarc1" in r.lower()]

    whois_data, registrar_name, _raw = results.get("WHOIS", (None, None, None))
    domain_statuses = (whois_data or {}).get("domain_status", [])
    status = get_domain_status_from_whois(whois_data, domain_statuses)

    response = {
        "domain": domain,
        "status": status,
        "ip_address": ip,
        "reverse_dns": reverse_dns,
        "A": results.get("A", []),
        "MX": results.get("MX", []),
        "nameservers": results.get("NS", []),
        "SPF": spf,
        "DKIM": results.get("DKIM", []),
        "DMARC": dmarc_filtered,
        "domain_status": domain_statuses,
        "registration_date": (whois_data or {}).get("creation_date"),
        "registrar_name": registrar_name,
        "ssl": results.get("SSL") or results.get("ssl")
    }

    if domain.endswith(".tn") and whois_data:
        if whois_data.get("registrant"):
            response["registrant"] = whois_data.get("registrant")
        if whois_data.get("admin_contact"):
            response["admin_contact"] = whois_data.get("admin_contact")

    if warnings:
        response["warnings"] = warnings

    result = {k: v for k, v in response.items() if v not in (None, "", [], {})}

    # Cache result
    set_cache(cache_key, result)
    logger.debug(f"Domain check for {domain} completed in {(time.time() - start_ts)*1000:.0f}ms")
    return result


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/api/check-domain", methods=["POST"])
def check_domain():
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
        logger.error(f"Error in /api/check-domain: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


# GET variant — useful for caching at CDN level (s-maxage)
@app.route("/api/check-domain", methods=["GET"])
def check_domain_get():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    result = check_domain_data(domain)
    if "error" in result:
        return jsonify(result), 400

    resp = make_response(jsonify(result))
    # Allow Vercel (CDN) to cache responses for 60s and serve while revalidating
    resp.headers["Cache-Control"] = "s-maxage=60, stale-while-revalidate=120"
    return resp


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "version": "2.0.1"})


@app.route("/api/cache/clear", methods=["POST"])
def clear_cache():
    global _cache
    _cache.clear()
    return jsonify({"status": "cache cleared"})


# Main (for local dev)
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
