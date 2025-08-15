from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import socket
import re
import subprocess
import ssl
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional dependencies (handled gracefully if missing)
try:
    import dns.resolver  # dnspython
except Exception:
    dns = None

try:
    from OpenSSL import crypto  # pyOpenSSL
except Exception:
    crypto = None

try:
    import whois as pywhois  # python-whois
except Exception:
    pywhois = None

# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, origins=[
    "https://dnx.bedouiadem.tech",
    "http://localhost",
    "https://localhost", 
    "http://127.0.0.1",
    "https://127.0.0.1"
])

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def clean_domain(domain: str) -> str:
    """Normalize domain input."""
    domain = re.sub(r'^https?://', '', domain, flags=re.IGNORECASE)
    domain = domain.split('/')[0].split(':')[0]
    domain = re.sub(r'^www\.', '', domain, flags=re.IGNORECASE)
    return domain.strip().lower()


def get_ip(domain: str) -> Optional[str]:
    """Resolve A/AAAA to an IP (prefers IPv4 if present)."""
    try:
        # Try IPv4 first
        info = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        # (family, type, proto, canonname, sockaddr)
        for fam, _type, _proto, _name, sockaddr in info:
            if fam == socket.AF_INET:
                return sockaddr[0]
        # Fallback to first result (may be IPv6)
        return info[0][4][0] if info else None
    except Exception as e:
        logger.warning(f"IP resolution failed for {domain}: {e}")
        return None


def get_reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as e:
        logger.warning(f"Reverse DNS failed for {ip}: {e}")
        return None


# -----------------------------------------------------------------------------
# DNS with timeouts + per-request cache
# -----------------------------------------------------------------------------
class DNSHelper:
    def __init__(self, warnings: List[str]):
        self.warnings = warnings
        self.cache: Dict[Tuple[str, str], List[str]] = {}

        self.available = dns is not None and hasattr(dns, "resolver")
        if self.available:
            try:
                self.resolver = dns.resolver.Resolver()
                # Keep lookups snappy
                self.resolver.timeout = 2.0
                self.resolver.lifetime = 3.0
                # Reduce retries to speed-up failure
                if hasattr(self.resolver, "retry_servfail") and self.resolver.retry_servfail:
                    self.resolver.retry_servfail = 0
            except Exception as e:
                self.available = False
                self.warnings.append(f"DNS resolver init failed: {e}")

    def _query(self, name: str, rtype: str) -> List[str]:
        key = (name, rtype)
        if key in self.cache:
            return self.cache[key]
        if not self.available:
            self.warnings.append("DNS lookups unavailable (dnspython not installed).")
            self.cache[key] = []
            return []

        try:
            answers = self.resolver.resolve(name, rtype)
            out = [r.to_text() for r in answers]
            self.cache[key] = out
            return out
        except Exception as e:
            self.warnings.append(f"DNS {rtype} lookup failed for {name}: {e}")
            self.cache[key] = []
            return []

    def records(self, domain: str, rtype: str) -> List[str]:
        return self._query(domain, rtype)

    def specific(self, domain: str, rtype: str, host: str) -> List[str]:
        fqdn = f"{host}.{domain}".strip(".")
        return self._query(fqdn, rtype)


# -----------------------------------------------------------------------------
# WHOIS helpers
# -----------------------------------------------------------------------------
def run_whois_subprocess(domain: str, timeout: int = 12) -> Optional[str]:
    """Fallback WHOIS via system command."""
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
        logger.warning(f"whois command non-zero or empty for {domain}: {result.stderr}")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"whois subprocess timeout for {domain}")
        return None
    except Exception as e:
        logger.warning(f"whois subprocess error for {domain}: {e}")
        return None


def parse_generic_whois(text: str) -> Dict[str, Any]:
    """Lightweight parser for common WHOIS fields."""
    domain_statuses = []
    creation = None

    # Domain Status
    for status in re.findall(r"Domain Status:\s*([^\n\r]+)", text, re.IGNORECASE):
        code = status.split()[0].strip().upper()
        if code and code != "ACTIVE":
            domain_statuses.append(code)

    # Creation Date
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
    """Extract registrar name from WHOIS output (non-.tn)."""
    if not whois_text:
        return None
    # Generic patterns
    patterns = [
        r"Registrar:\s*([^\n\r]+)",
        r"Registrar Name:\s*([^\n\r]+)",
        r"Sponsoring Registrar:\s*([^\n\r]+)",
        r"Registrar Organization:\s*([^\n\r]+)",
        r"Registrar\s*:\s*([^\n\r]+)"
    ]
    for p in patterns:
        m = re.search(p, whois_text, re.IGNORECASE)
        if m:
            reg = m.group(1).strip()
            if reg and reg.lower() not in ("", "none", "n/a"):
                return reg
    return None


# Keep your .tn WHOIS parser as-is (you said to exclude changing it)
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
            logger.warning(f"Error parsing creation date: {e}")

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

    registrant_name = None
    registrant_first_name = None
    owner_section_match = re.search(r"Owner Contact(.*?)(?:Administrativ contact|Technical contact|DNS servers|$)", section, re.IGNORECASE | re.DOTALL)
    if owner_section_match:
        owner_section = owner_section_match.group(1)
        name_match = re.search(r"Name\s*\.*\s*:\s*([^\n\r]+)", owner_section, re.IGNORECASE)
        if name_match:
            registrant_name = name_match.group(1).strip()
            if registrant_name.lower().startswith('address') or 'address' in registrant_name.lower():
                registrant_name = None
        first_name_match = re.search(r"First name\s*\.*\s*:\s*([^\n\r]+)", owner_section, re.IGNORECASE)
        if first_name_match:
            registrant_first_name = first_name_match.group(1).strip()
            if registrant_first_name.lower().startswith('address') or 'address' in registrant_first_name.lower():
                registrant_first_name = None
    if registrant_name and registrant_first_name:
        registrant = f"{registrant_name} {registrant_first_name}"
    elif registrant_name:
        registrant = registrant_name
    elif registrant_first_name:
        registrant = registrant_first_name

    admin_name = None
    admin_first_name = None
    admin_section_match = re.search(r"Administrativ contact(.*?)(?:Technical contact|DNS servers|$)", section, re.IGNORECASE | re.DOTALL)
    if admin_section_match:
        admin_section = admin_section_match.group(1)
        admin_name_match = re.search(r"Name\s*\.*\s*:\s*([^\n\r]+)", admin_section, re.IGNORECASE)
        if admin_name_match:
            admin_name = admin_name_match.group(1).strip()
            if admin_name.lower().startswith('address') or 'address' in admin_name.lower():
                admin_name = None
        admin_first_name_match = re.search(r"First name\s*\.*\s*:\s*([^\n\r]+)", admin_section, re.IGNORECASE)
        if admin_first_name_match:
            admin_first_name = admin_first_name_match.group(1).strip()
            if admin_first_name.lower().startswith('address') or 'address' in admin_first_name.lower():
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
    """
    Returns: (whois_data, registrar_name, raw_text)
    Uses python-whois first (if available), then subprocess fallback.
    """
    raw = None
    data = None
    registrar = None

    try:
        if pywhois:
            try:
                w = pywhois.whois(domain)  # may raise exceptions internally
                # python-whois returns a dict-like object; not standardized across TLDs
                raw = str(w)
                # Extract creation date
                creation = None
                created = w.creation_date
                # python-whois may give a datetime or list of datetimes
                if created:
                    if isinstance(created, list):
                        d0 = created[0]
                        if hasattr(d0, "strftime"):
                            creation = d0.strftime("%Y-%m-%d")
                    elif hasattr(created, "strftime"):
                        creation = created.strftime("%Y-%m-%d")
                # Extract status (could be various types)
                statuses = []
                st = w.status
                if isinstance(st, list):
                    statuses = [str(s).split()[0].upper() for s in st if s]
                elif isinstance(st, str):
                    statuses = [st.split()[0].upper()]
                # Registrar
                registrar = None
                if hasattr(w, "registrar") and w.registrar:
                    registrar = str(w.registrar).strip()
                data = {
                    "creation_date": creation,
                    "domain_status": list(set([s for s in statuses if s and s != "ACTIVE"]))
                }
            except Exception as e:
                warnings.append(f"python-whois failed: {e}")
                raw = None  # fall through
        if raw is None:
            raw = run_whois_subprocess(domain)
            if raw:
                if domain.endswith(".tn"):
                    data = parse_whois_tn(raw)
                    # Extract registrar for .tn (or default handled in parse if missing)
                    if data and data.get("registrar"):
                        registrar = data.get("registrar")
                    else:
                        registrar = "ATI (Agence Tunisienne d'Internet)"
                else:
                    data = parse_generic_whois(raw)
                    registrar = extract_registrar_name(raw, domain)
    except Exception as e:
        warnings.append(f"WHOIS lookup error: {e}")

    return data, registrar, raw


# -----------------------------------------------------------------------------
# SSL (precise) with TLS fallbacks
# -----------------------------------------------------------------------------
def _ssl_try_connect(domain: str, port: int, ctx: ssl.SSLContext) -> bytes:
    """Return leaf cert in DER or raise."""
    with socket.create_connection((domain, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            return ssock.getpeercert(binary_form=True)


def _ctx_default() -> ssl.SSLContext:
    c = ssl.create_default_context()
    # We don't verify to allow fetching certs even if chain is broken; this is an info tool
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _ctx_tls12() -> ssl.SSLContext:
    c = _ctx_default()
    # Force TLSv1.2 only (if available)
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


def get_ssl_info(domain: str, warnings: List[str]) -> Dict[str, Any]:
    """
    Precise SSL info using PyOpenSSL to parse the leaf certificate.
    Tries multiple TLS contexts for better compatibility.
    """
    if crypto is None:
        warnings.append("PyOpenSSL not installed; SSL details unavailable.")
        return {"status": "Unavailable", "error": "pyOpenSSL not installed"}

    attempts = []
    # Try default (negotiate), then TLS 1.3, then TLS 1.2
    for make_ctx, label in [(_ctx_default, "default"), (_ctx_tls13, "tls1_3"), (_ctx_tls12, "tls1_2")]:
        try:
            der = _ssl_try_connect(domain, 443, make_ctx())
            attempts.append((label, "ok"))
            # Parse with OpenSSL
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der)

            issuer = dict(x509.get_issuer().get_components())
            subject = dict(x509.get_subject().get_components())

            issuer_name = (issuer.get(b'O') or issuer.get(b'CN') or b"Unknown").decode(errors="ignore")
            subject_cn = (subject.get(b'CN') or b"Unknown").decode(errors="ignore")

            # Validity (UTC)
            not_before = datetime.strptime(x509.get_notBefore().decode("ascii"), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(x509.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)

            # SANs
            san_list: List[str] = []
            try:
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    if ext.get_short_name().decode() == "subjectAltName":
                        san_list = [x.strip() for x in str(ext).split(",")]
                        break
            except Exception:
                pass

            # Self-signed?
            is_self_signed = x509.get_issuer().der() == x509.get_subject().der()

            # Key size & sig algo
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

    # If all attempts failed
    warnings.append(f"SSL handshake failed in all contexts: {attempts}")
    return {"status": "Error", "error": "SSL handshake failed", "attempts": attempts}


# -----------------------------------------------------------------------------
# Core domain check (runs parts concurrently)
# -----------------------------------------------------------------------------
def check_domain_data(domain: str) -> Dict[str, Any]:
    warnings: List[str] = []
    domain = clean_domain(domain)
    if not domain:
        return {"error": "Domain is required"}

    ip = get_ip(domain)
    reverse_dns = get_reverse_dns(ip) if ip else None

    dns_helper = DNSHelper(warnings)

    # Prepare concurrent tasks
    tasks = {}
    results: Dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=6) as pool:
        # DNS in parallel
        tasks["A"] = pool.submit(dns_helper.records, domain, "A")
        tasks["MX"] = pool.submit(dns_helper.records, domain, "MX")
        tasks["NS"] = pool.submit(dns_helper.records, domain, "NS")
        tasks["TXT_ALL"] = pool.submit(dns_helper.records, domain, "TXT")
        tasks["DKIM"] = pool.submit(dns_helper.specific, domain, "TXT", "default._domainkey")
        tasks["DMARC"] = pool.submit(dns_helper.specific, domain, "TXT", "_dmarc")

        # WHOIS (single task)
        tasks["WHOIS"] = pool.submit(whois_lookup, domain, warnings)

        # SSL (only if we resolved an IP; still use domain for SNI)
        if ip:
            tasks["SSL"] = pool.submit(get_ssl_info, domain, warnings)
        else:
            results["ssl"] = {"status": "Unavailable", "error": "Domain does not resolve"}

        # Collect results
        for name, fut in tasks.items():
            try:
                res = fut.result(timeout=15)
                results[name] = res
            except Exception as e:
                warnings.append(f"Task {name} failed: {e}")
                if name in ("A", "MX", "NS", "TXT_ALL", "DKIM", "DMARC"):
                    results[name] = []
                elif name == "SSL":
                    results[name] = {"status": "Error", "error": str(e)}
                elif name == "WHOIS":
                    results[name] = (None, None, None)

    # Post-process DNS TXT to extract SPF/DMARC
    txt_all: List[str] = results.get("TXT_ALL", []) or []
    spf = [r for r in txt_all if "v=spf1" in r.lower()]
    dmarc_raw: List[str] = results.get("DMARC", []) or []
    dmarc_filtered = [r for r in dmarc_raw if "v=dmarc1" in r.lower()]

    # WHOIS unpack
    whois_data, registrar_name, _raw = results.get("WHOIS", (None, None, None))

    # Build response
    response = {
        "domain": domain,
        "status": "Registered" if ip else "Available",
        "ip_address": ip,
        "reverse_dns": reverse_dns,

        "A": results.get("A", []),
        "MX": results.get("MX", []),
        "nameservers": results.get("NS", []),

        "SPF": spf,
        "DKIM": results.get("DKIM", []),
        "DMARC": dmarc_filtered,

        "domain_status": (whois_data or {}).get("domain_status", []),
        "registration_date": (whois_data or {}).get("creation_date"),
        "registrar_name": registrar_name,

        "ssl": results.get("SSL") or results.get("ssl")
    }

    # Add .tn extras if present
    if domain.endswith(".tn") and whois_data:
        if whois_data.get("registrant"):
            response["registrant"] = whois_data.get("registrant")
        if whois_data.get("admin_contact"):
            response["admin_contact"] = whois_data.get("admin_contact")

    # Attach warnings only if any
    if warnings:
        response["warnings"] = warnings

    # Clean out empty/null values
    return {k: v for k, v in response.items() if v not in (None, "", [], {})}


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
        logger.error(f"Error processing /api/check-domain: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "version": "2.0.0"})


# No /api/check-multiple-domains (removed by request)

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # Keep debug True for development; set to False in production
    app.run(debug=True, host="0.0.0.0", port=5000)
