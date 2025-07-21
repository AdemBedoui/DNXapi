#!/usr/bin/env python3
"""
Debug script to examine .tn WHOIS output format
"""

import subprocess
import re

def get_whois_raw(domain):
    """Get raw WHOIS output for a domain."""
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
            print(f"Whois command failed: {result.stderr}")
            return None
    except Exception as e:
        print(f"Error running whois: {e}")
        return None

def analyze_tn_whois(whois_text):
    """Analyze .tn WHOIS output to find registrant patterns."""
    if not whois_text:
        return
    
    print("=" * 80)
    print("ANALYZING .TN WHOIS OUTPUT")
    print("=" * 80)
    
    # Find the .tn section
    match = re.search(r"# whois\.ati\.tn(.*)", whois_text, re.DOTALL | re.IGNORECASE)
    if not match:
        print("No .tn WHOIS section found")
        return
    
    section = match.group(1)
    print("Found .tn WHOIS section:")
    print("-" * 40)
    print(section)
    print("-" * 40)
    
    # Look for registrant-related patterns
    print("\nSEARCHING FOR REGISTRANT PATTERNS:")
    print("-" * 40)
    
    # Common patterns to look for
    patterns = [
        r"First name\s*\.{7,}\s*:\s*(.+)",
        r"Last name\s*\.{7,}\s*:\s*(.+)",
        r"Registrant\s*\.{7,}\s*:\s*(.+)",
        r"Admin contact\s*\.{7,}\s*:\s*(.+)",
        r"Registrar\s*\.{7,}\s*:\s*(.+)",
        r"Creation date\s*\.{7,}\s*:\s*(.+)",
        r"Domain status\s*\.{7,}\s*:\s*(.+)"
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, section, re.IGNORECASE)
        if matches:
            print(f"Pattern '{pattern}':")
            for match in matches:
                print(f"  -> {match.strip()}")
        else:
            print(f"Pattern '{pattern}': No matches")
    
    # Also look for any line containing "name" or "registrant"
    print("\nLINES CONTAINING 'NAME' OR 'REGISTRANT':")
    print("-" * 40)
    lines = section.split('\n')
    for line in lines:
        if re.search(r'name|registrant', line, re.IGNORECASE):
            print(f"  {line.strip()}")

def main():
    """Test with some .tn domains."""
    test_domains = [
        "google.tn",
        "facebook.tn",
        "youtube.tn"
    ]
    
    for domain in test_domains:
        print(f"\n{'='*20} TESTING {domain} {'='*20}")
        whois_text = get_whois_raw(domain)
        if whois_text:
            analyze_tn_whois(whois_text)
        else:
            print(f"Could not get WHOIS data for {domain}")

if __name__ == "__main__":
    main() 