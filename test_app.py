#!/usr/bin/env python3
"""
Simple test script for the Domain Information Checker API
"""

import requests
import json
import time

BASE_URL = "http://localhost:5000"

def test_health_check():
    """Test the health check endpoint."""
    print("Testing health check...")
    try:
        response = requests.get(f"{BASE_URL}/api/health")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check passed: {data}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_single_domain():
    """Test checking a single domain."""
    print("\nTesting single domain check...")
    test_domain = "google.com"
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/check-domain",
            json={"domain": test_domain},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Domain check successful for {test_domain}")
            print(f"   Status: {data.get('status')}")
            print(f"   IP: {data.get('ip_address')}")
            print(f"   SSL Status: {data.get('ssl', {}).get('status', 'N/A')}")
            print(f"   Registration Date: {data.get('registration_date', 'N/A')}")
            return True
        else:
            print(f"❌ Domain check failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Domain check error: {e}")
        return False

def test_multiple_domains():
    """Test checking multiple domains."""
    print("\nTesting multiple domains check...")
    test_domains = ["google.com", "github.com", "example.com"]
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/check-multiple-domains",
            json={"domains": test_domains},
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Multiple domains check successful")
            print(f"   Total checked: {data.get('total_checked')}")
            
            for result in data.get('results', []):
                domain = result.get('domain')
                status = result.get('status')
                print(f"   {domain}: {status}")
            return True
        else:
            print(f"❌ Multiple domains check failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Multiple domains check error: {e}")
        return False

def test_error_handling():
    """Test error handling."""
    print("\nTesting error handling...")
    
    # Test missing domain
    try:
        response = requests.post(
            f"{BASE_URL}/api/check-domain",
            json={},
            timeout=10
        )
        
        if response.status_code == 400:
            data = response.json()
            print(f"✅ Missing domain error handled correctly: {data.get('error')}")
        else:
            print(f"❌ Unexpected response for missing domain: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error handling test failed: {e}")
        return False
    
    # Test invalid domain
    try:
        response = requests.post(
            f"{BASE_URL}/api/check-domain",
            json={"domain": ""},
            timeout=10
        )
        
        if response.status_code == 400:
            data = response.json()
            print(f"✅ Empty domain error handled correctly: {data.get('error')}")
            return True
        else:
            print(f"❌ Unexpected response for empty domain: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error handling test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🚀 Starting Domain Information Checker API Tests")
    print("=" * 50)
    
    tests = [
        test_health_check,
        test_single_domain,
        test_multiple_domains,
        test_error_handling
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")

if __name__ == "__main__":
    main() 