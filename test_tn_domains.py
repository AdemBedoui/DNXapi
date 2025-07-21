#!/usr/bin/env python3
"""
Test script specifically for .tn domain functionality
"""

import requests
import json

BASE_URL = "http://localhost:5000"

def test_tn_domain(domain):
    """Test a specific .tn domain."""
    print(f"\n🔍 Testing .tn domain: {domain}")
    print("-" * 50)
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/check-domain",
            json={"domain": domain},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Domain check successful")
            print(f"   Domain: {data.get('domain')}")
            print(f"   Status: {data.get('status')}")
            print(f"   IP Address: {data.get('ip_address', 'N/A')}")
            print(f"   Registrar: {data.get('registrar_name', 'N/A')}")
            print(f"   Registration Date: {data.get('registration_date', 'N/A')}")
            print(f"   Domain Status: {data.get('domain_status', [])}")
            
            # .tn specific fields
            print(f"   Registrant: {data.get('registrant', 'Not found')}")
            print(f"   Admin Contact: {data.get('admin_contact', 'Not found')}")
            
            # SSL information
            ssl_info = data.get('ssl', {})
            if ssl_info and ssl_info.get('status') != 'Error':
                print(f"   SSL Status: {ssl_info.get('status')}")
                print(f"   SSL Issuer: {ssl_info.get('issuer')}")
                print(f"   SSL Valid Until: {ssl_info.get('valid_until')}")
            
            return True
        else:
            print(f"❌ Domain check failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Domain check error: {e}")
        return False

def main():
    """Test multiple .tn domains."""
    print("🇹🇳 Testing .tn Domain Functionality")
    print("=" * 60)
    
    # Test domains - you can add more .tn domains here
    test_domains = [
        "google.tn",
        "facebook.tn", 
        "youtube.tn",
        "example.tn"  # This might not exist
    ]
    
    passed = 0
    total = len(test_domains)
    
    for domain in test_domains:
        if test_tn_domain(domain):
            passed += 1
    
    print("\n" + "=" * 60)
    print(f"📊 .tn Domain Test Results: {passed}/{total} domains processed successfully")
    
    if passed > 0:
        print("✅ .tn domain functionality is working!")
    else:
        print("❌ .tn domain functionality needs attention.")

if __name__ == "__main__":
    main() 