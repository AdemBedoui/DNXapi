from flask import Flask, request, jsonify
import socket
import re
import subprocess
import ssl
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from flask_cors import CORS
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, origins=["https://dnx.bedouiadem.tech"])

def clean_domain(domain: str) -> str:
    """Clean and normalize domain name."""
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    domain = domain.split(':')[0]
    domain = re.sub(r'^www\.', '', domain)
    return domain.strip().lower()

def get_ip(domain: str) -> Optional[str]:
    """Get IP address for a domain."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        logger.warning(f"Could not resolve IP for domain: {domain}")
        return None

def get_reverse_dns(ip: str) -> Optional[str]:
    """Get reverse DNS for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        logger.warning(f"Could not resolve reverse DNS for IP: {ip}")
        return None

def get_dns_records(domain: str, record_type: str) -> List[str]:
    """Get DNS records of a specific type for a domain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, record_type)
        return [rdata.to_text() for rdata in answers]
    except Exception as e:
        logger.warning(f"Could not get {record_type} records for {domain}: {e}")
        return []

def get_specific_record(domain: str, record_type: str, record_name: str) -> List[str]:
    """Get specific DNS record for a domain."""
    try:
        import dns.resolver
        query = f"{record_name}.{domain}"
        answers = dns.resolver.resolve(query, record_type)
        return [rdata.to_text() for rdata in answers]
    except Exception as e:
        logger.warning(f"Could not get {record_type} record {record_name} for {domain}: {e}")
        return []

def run_whois(domain: str) -> Optional[str]:
    """Run whois command for a domain."""
    try:
        result = subprocess.run(
            ['whois', domain], 
            capture_output=True, 
            text=True, 
            timeout=15
        )
        if result.returncode == 0:
            return result.stdout
        else:
            logger.warning(f"Whois command failed for {domain}: {result.stderr}")
            return None
    except subprocess.TimeoutExpired:
        logger.warning(f"Whois command timed out for {domain}")
        return None
    except Exception as e:
        logger.warning(f"Error running whois for {domain}: {e}")
        return None

def parse_whois_tn(text: str) -> Optional[Dict[str, Any]]:
    """Parse whois output for .tn domains."""
    match = re.search(r"# whois\.ati\.tn(.*)", text, re.DOTALL | re.IGNORECASE)
    if not match:
        return None
    
    section = match.group(1)
    creation = None
    domain_statuses = []
    registrar = None
    registrant = None
    admin_contact = None

    # Parse creation date
    creation_match = re.search(r"Creation date\s*\.{7,}\s*:\s*(.+)", section, re.IGNORECASE)
    if creation_match:
        date_str = creation_match.group(1).strip()
        try:
            date_clean = re.match(r"(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})", date_str)
            if date_clean:
                creation = datetime.strptime(date_clean.group(1), "%d-%m-%Y %H:%M:%S").strftime("%Y-%m-%d")
        except Exception as e:
            logger.warning(f"Error parsing creation date: {e}")

    # Parse domain statuses
    status_matches = re.findall(r"Domain status\s*\.{7,}\s*:\s*([^\n\r]+)", section, re.IGNORECASE)
    for status in status_matches:
        clean_status = status.strip().upper().lstrip(":").strip()
        if clean_status and clean_status != "ACTIVE":
            domain_statuses.append(clean_status)

    # Parse registrar information
    registrar_match = re.search(r"Registrar\s*\.{7,}\s*:\s*(.+)", section, re.IGNORECASE)
    if registrar_match:
        registrar = registrar_match.group(1).strip()
        if registrar.lower() in ['', 'none', 'n/a']:
            registrar = "ATI (Agence Tunisienne d'Internet)"

    # Parse registrant (Owner Contact) Name and First name
    registrant_name = None
    registrant_first_name = None
    # Try to find Owner Contact section
    owner_section_match = re.search(r"Owner Contact(.*?)(?:Administrativ contact|Technical contact|DNS servers|$)", section, re.IGNORECASE | re.DOTALL)
    if owner_section_match:
        owner_section = owner_section_match.group(1)
        name_match = re.search(r"Name\s*\.*\s*:\s*([^\n\r]+)", owner_section, re.IGNORECASE)
        if name_match:
            registrant_name = name_match.group(1).strip()
            # Ignore if value looks like a field label or address
            if registrant_name.lower().startswith('address') or 'address' in registrant_name.lower():
                registrant_name = None
        first_name_match = re.search(r"First name\s*\.*\s*:\s*([^\n\r]+)", owner_section, re.IGNORECASE)
        if first_name_match:
            registrant_first_name = first_name_match.group(1).strip()
            if registrant_first_name.lower().startswith('address') or 'address' in registrant_first_name.lower():
                registrant_first_name = None
    # Merge Name and First name for registrant
    if registrant_name and registrant_first_name:
        registrant = f"{registrant_name} {registrant_first_name}"
    elif registrant_name:
        registrant = registrant_name
    elif registrant_first_name:
        registrant = registrant_first_name

    # Parse admin contact (Administrativ contact) Name and First name
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
    # Merge Name and First name for admin contact
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

def parse_generic_whois(text: str) -> Dict[str, Any]:
    """Parse generic whois output."""
    domain_statuses = []
    creation = None

    # Parse domain statuses
    status_matches = re.findall(r"Domain Status:\s*([^\n\r]+)", text, re.IGNORECASE)
    for status in status_matches:
        code = status.split()[0].upper()
        if code and code != "ACTIVE":
            domain_statuses.append(code)

    # Parse creation date
    creation_patterns = [
        r"Creation Date:\s*([^\n\r]+)",
        r"Created On:\s*([^\n\r]+)",
        r"Created:\s*([^\n\r]+)",
        r"Registration Date:\s*([^\n\r]+)"
    ]
    
    for pattern in creation_patterns:
        creation_match = re.search(pattern, text, re.IGNORECASE)
        if creation_match:
            date_str = creation_match.group(1).strip()
            # Try multiple date formats
            date_formats = [
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
                "%d-%b-%Y",
                "%Y-%m-%d",
                "%Y-%m-%d %H:%M:%S %Z",
                "%b %d %H:%M:%S %Y %Z"
            ]
            
            for fmt in date_formats:
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

def get_ssl_info(domain: str) -> Dict[str, Any]:
    """Get SSL certificate information for a domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                
                if not cert or not cert_bin:
                    return {
                        "status": "Error",
                        "error": "No certificate data received"
                    }

                # Parse certificate dates
                not_before_str = cert.get('notBefore')
                not_after_str = cert.get('notAfter')
                
                if not not_before_str or not not_after_str:
                    return {
                        "status": "Error",
                        "error": "Certificate dates not found"
                    }

                try:
                    not_before = datetime.strptime(str(not_before_str), '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(str(not_after_str), '%b %d %H:%M:%S %Y %Z')
                except ValueError as e:
                    return {
                        "status": "Error",
                        "error": f"Invalid certificate date format: {e}"
                    }

                # Parse issuer information
                issuer_name = "Unknown"
                issuer_data = cert.get('issuer')
                if issuer_data:
                    # issuer_data is usually a tuple of tuples: ((('countryName', 'US'), ...), ...)
                    # We'll flatten and look for organizationName or commonName
                    issuer_fields = ['organizationName', 'commonName', 'organizationalUnitName']
                    found = False
                    if isinstance(issuer_data, tuple):
                        for field in issuer_fields:
                            for item in issuer_data:
                                if isinstance(item, tuple):
                                    # item can be (('organizationName', 'Let's Encrypt'),)
                                    for subitem in item:
                                        if isinstance(subitem, tuple) and len(subitem) == 2:
                                            if subitem[0] == field:
                                                issuer_name = subitem[1]
                                                found = True
                                                break
                                    if found:
                                        break
                            if found:
                                break
                        # If still unknown, try to extract from commonName with known patterns
                        if issuer_name == "Unknown":
                            for item in issuer_data:
                                for subitem in item:
                                    if isinstance(subitem, tuple) and len(subitem) == 2 and subitem[0] == 'commonName':
                                        cn_value = subitem[1]
                                        if "Let's Encrypt" in cn_value:
                                            issuer_name = "Let's Encrypt"
                                        elif "Sectigo" in cn_value or "COMODO" in cn_value:
                                            issuer_name = "Sectigo"
                                        elif "DigiCert" in cn_value:
                                            issuer_name = "DigiCert"
                                        elif "GlobalSign" in cn_value:
                                            issuer_name = "GlobalSign"
                                        elif "GoDaddy" in cn_value:
                                            issuer_name = "GoDaddy"
                                        elif "Amazon" in cn_value:
                                            issuer_name = "Amazon"
                                        elif "Cloudflare" in cn_value:
                                            issuer_name = "Cloudflare"
                                        elif "Google" in cn_value:
                                            issuer_name = "Google"
                                        elif "Microsoft" in cn_value:
                                            issuer_name = "Microsoft"
                                        else:
                                            issuer_name = cn_value
                                        break
                    elif isinstance(issuer_data, dict):
                        issuer_name = issuer_data.get('organizationName', 'Unknown')
                        if issuer_name == 'Unknown':
                            cn_value = issuer_data.get('commonName', 'Unknown')
                            if cn_value != 'Unknown':
                                if "Let's Encrypt" in cn_value:
                                    issuer_name = "Let's Encrypt"
                                elif "Sectigo" in cn_value or "COMODO" in cn_value:
                                    issuer_name = "Sectigo"
                                elif "DigiCert" in cn_value:
                                    issuer_name = "DigiCert"
                                elif "GlobalSign" in cn_value:
                                    issuer_name = "GlobalSign"
                                elif "GoDaddy" in cn_value:
                                    issuer_name = "GoDaddy"
                                elif "Amazon" in cn_value:
                                    issuer_name = "Amazon"
                                elif "Cloudflare" in cn_value:
                                    issuer_name = "Cloudflare"
                                elif "Google" in cn_value:
                                    issuer_name = "Google"
                                elif "Microsoft" in cn_value:
                                    issuer_name = "Microsoft"
                                else:
                                    issuer_name = cn_value

                now = datetime.now()
                is_valid = not_before <= now <= not_after
                days_until_expiry = (not_after - now).days

                ssl_response = {
                    "status": "Valid" if is_valid else "Invalid",
                    "issuer": issuer_name,
                    "valid_from": not_before.strftime('%Y-%m-%d'),
                    "valid_until": not_after.strftime('%Y-%m-%d'),
                    "days_until_expiry": days_until_expiry
                }
                
                # Only add subject_alt_names if it exists and is not empty
                subject_alt_names = cert.get('subjectAltName', [])
                if subject_alt_names:
                    ssl_response["subject_alt_names"] = subject_alt_names
                
                return ssl_response
    except Exception as e:
        logger.warning(f"SSL error for {domain}: {e}")
        return {
            "status": "Error",
            "error": str(e)
        }

def clean_response_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Remove null values and empty lists from response data."""
    cleaned = {}
    for key, value in data.items():
        if value is not None and value != [] and value != "":
            cleaned[key] = value
    return cleaned

def extract_registrar_name(whois_text: str, domain: str = "") -> Optional[str]:
    """Extract registrar name from whois output."""
    if not whois_text:
        return None
    
    # Special handling for .tn domains
    if domain.endswith('.tn'):
        # Look for registrar information in .tn whois format
        tn_patterns = [
            r"Registrar\s*\.{7,}\s*:\s*([^\n\r]+)",
            r"Registrar Name\s*\.{7,}\s*:\s*([^\n\r]+)",
            r"Sponsoring Registrar\s*\.{7,}\s*:\s*([^\n\r]+)",
            r"Registrar\s*:\s*([^\n\r]+)",
            r"Registrar Name\s*:\s*([^\n\r]+)"
        ]
        
        for pattern in tn_patterns:
            match = re.search(pattern, whois_text, re.IGNORECASE)
            if match:
                registrar = match.group(1).strip()
                if registrar and registrar.lower() not in ['', 'none', 'n/a']:
                    return registrar
        
        # If no specific registrar found, return the default .tn registrar
        return "ATI (Agence Tunisienne d'Internet)"
    
    # Generic patterns for other domains
    patterns = [
        r"Registrar:\s*([^\n\r]+)",
        r"Registrar Name:\s*([^\n\r]+)",
        r"Sponsoring Registrar:\s*([^\n\r]+)",
        r"Registrar Organization:\s*([^\n\r]+)",
        r"Registrar\s*:\s*([^\n\r]+)"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, whois_text, re.IGNORECASE)
        if match:
            registrar = match.group(1).strip()
            if registrar and registrar.lower() not in ['', 'none', 'n/a']:
                return registrar
    
    return None

@app.route('/api/check-domain', methods=['POST'])
def check_domain():
    """Main endpoint to check domain information."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        raw_domain = data.get("domain", "").strip()
        if not raw_domain:
            return jsonify({"error": "Domain is required"}), 400

        domain = clean_domain(raw_domain)
        logger.info(f"Checking domain: {domain}")

        # Get basic domain information
        ip = get_ip(domain)
        reverse_dns = get_reverse_dns(ip) if ip else None

        # Get whois information
        whois_text = run_whois(domain)
        whois_data = None
        registrar_name = None

        if whois_text:
            registrar_name = extract_registrar_name(whois_text, domain)
            if domain.endswith('.tn'):
                whois_data = parse_whois_tn(whois_text)
            else:
                whois_data = parse_generic_whois(whois_text)

        # Get DNS records
        all_txt = get_dns_records(domain, "TXT")
        spf = [r for r in all_txt if "v=spf1" in r.lower()]
        dkim = get_specific_record(domain, "TXT", "default._domainkey")
        dmarc = get_specific_record(domain, "TXT", "_dmarc")
        dmarc_filtered = [r for r in dmarc if "v=dmarc1" in r.lower()]

        # Get SSL information only if domain resolves
        ssl_info = get_ssl_info(domain) if ip else None

        response = {
            "domain": domain,
            "status": "Registered" if ip else "Available",
            "ip_address": ip,
            "domain_status": whois_data.get("domain_status", []) if whois_data else [],
            "A": get_dns_records(domain, "A"),
            "MX": get_dns_records(domain, "MX"),
            "SPF": spf,
            "DKIM": dkim,
            "DMARC": dmarc_filtered,
            "reverse_dns": reverse_dns,
            "registration_date": whois_data.get("creation_date") if whois_data else None,
            "registrar_name": registrar_name,
            "nameservers": get_dns_records(domain, "NS"),
            "ssl": ssl_info
        }
        
        # Add additional .tn domain information if available (only if not null)
        if domain.endswith('.tn') and whois_data:
            if whois_data.get("registrant"):
                response["registrant"] = whois_data.get("registrant")
            if whois_data.get("admin_contact"):
                response["admin_contact"] = whois_data.get("admin_contact")
        
        # Clean response by removing null values and empty lists
        cleaned_response = clean_response_data(response)
        return jsonify(cleaned_response)
        
    except Exception as e:
        logger.error(f"Error processing domain check: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy", 
        "version": "1.0.0"
    })

@app.route('/api/check-multiple-domains', methods=['POST'])
def check_multiple_domains():
    """Check multiple domains at once."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        domains = data.get("domains", [])
        if not domains or not isinstance(domains, list):
            return jsonify({"error": "domains must be a non-empty list"}), 400
        
        if len(domains) > 10:  # Limit to prevent abuse
            return jsonify({"error": "Maximum 10 domains allowed per request"}), 400

        results = []
        for domain in domains:
            if isinstance(domain, str) and domain.strip():
                # Create a mock request context for the single domain check
                with app.test_request_context(
                    '/api/check-domain',
                    method='POST',
                    json={"domain": domain.strip()}
                ):
                    result = check_domain()
                    if isinstance(result, tuple):
                        # Error response (tuple of response and status code)
                        response_obj, status_code = result
                        results.append({
                            "domain": domain.strip(),
                            "error": response_obj.get_json().get("error", "Unknown error")
                        })
                    else:
                        # Success response (Response object)
                        results.append(result.get_json())

        return jsonify({
            "results": results,
            "total_checked": len(results)
        })
        
    except Exception as e:
        logger.error(f"Error processing multiple domains: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
