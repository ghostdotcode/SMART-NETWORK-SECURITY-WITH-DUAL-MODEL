"""
Test script for AI Firewall
Sends various types of requests to test blocking capabilities
"""

import requests
import time

# Configure proxy
PROXIES = {
    'http': 'http://localhost:8080',
    'https': 'http://localhost:8080'
}

# Test target (using httpbin.org for safe testing)
BASE_URL = 'http://httpbin.org'

def test_request(name, url, headers=None, expected_status=None):
    """
    Send a test request and print results
    """
    print(f"\n{'='*60}")
    print(f"Test: {name}")
    print(f"URL: {url}")
    if headers:
        print(f"Headers: {headers}")
    print(f"{'='*60}")
    
    try:
        response = requests.get(
            url,
            proxies=PROXIES,
            headers=headers or {},
            timeout=10
        )
        
        status = response.status_code
        
        if expected_status:
            result = "✓ PASS" if status == expected_status else "✗ FAIL"
        else:
            result = "ℹ Result"
        
        print(f"Status Code: {status}")
        print(f"Result: {result}")
        
        if status == 403:
            print("🛡️  Request was BLOCKED by AI Firewall")
        elif status == 429:
            print("⚠️  Request was CHALLENGED by AI Firewall")
        elif status == 200:
            print("✓ Request was ALLOWED")
        
    except requests.exceptions.ProxyError as e:
        print(f"✗ Proxy Error: Is the AI Firewall running?")
        print(f"   Make sure you started: python ai_firewall_proxy.py")
    except Exception as e:
        print(f"✗ Error: {e}")

def main():
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║          AI FIREWALL TEST SUITE                        ║
    ║                                                        ║
    ║  This script tests your AI Firewall's ability to      ║
    ║  detect and block malicious traffic patterns.         ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    print("\n⚙️  Configuration:")
    print(f"   Proxy: localhost:8080")
    print(f"   Target: {BASE_URL}")
    print(f"\n🚀 Starting tests...\n")
    
    time.sleep(2)
    
    # ===== TEST 1: Legitimate Request =====
    test_request(
        name="Legitimate GET request",
        url=f"{BASE_URL}/get",
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0'},
        expected_status=200
    )
    time.sleep(1)
    
    # ===== TEST 2: Suspicious Endpoint (.env file) =====
    test_request(
        name="Malicious pattern - .env file access",
        url=f"{BASE_URL}/.env",
        headers={'User-Agent': 'curl/7.68.0'},
        expected_status=403
    )
    time.sleep(1)
    
    # ===== TEST 3: Admin Path Probing =====
    test_request(
        name="Malicious pattern - Admin path",
        url=f"{BASE_URL}/admin/config.php",
        headers={'User-Agent': 'python-requests/2.28.1'},
        expected_status=403
    )
    time.sleep(1)
    
    # ===== TEST 4: WordPress Scanning =====
    test_request(
        name="Malicious pattern - WordPress scan",
        url=f"{BASE_URL}/wp-login.php",
        headers={'User-Agent': 'Masscan/1.0'},
        expected_status=403
    )
    time.sleep(1)
    
    # ===== TEST 5: Git Config Access =====
    test_request(
        name="Malicious pattern - Git config access",
        url=f"{BASE_URL}/.git/config",
        headers={'User-Agent': 'curl/7.68.0'},
        expected_status=403
    )
    time.sleep(1)
    
    # ===== TEST 6: Automated Tool Detection =====
    test_request(
        name="Malicious pattern - Automated scanning tool",
        url=f"{BASE_URL}/api/users",
        headers={'User-Agent': 'Nmap Scripting Engine'},
        expected_status=403
    )
    time.sleep(1)
    
    # ===== TEST 7: Backup File Access =====
    test_request(
        name="Malicious pattern - Backup file",
        url=f"{BASE_URL}/backup.zip",
        headers={'User-Agent': 'wget/1.20.3'},
        expected_status=403
    )
    time.sleep(1)
    
    # ===== TEST 8: Normal API Request =====
    test_request(
        name="Legitimate API request",
        url=f"{BASE_URL}/json",
        headers={'User-Agent': 'Mozilla/5.0 (compatible)'},
        expected_status=200
    )
    time.sleep(1)
    
    # ===== TEST 9: Rate Limiting Test =====
    print(f"\n{'='*60}")
    print(f"Test: Rate Limiting (sending 10 requests rapidly)")
    print(f"{'='*60}")
    
    blocked_count = 0
    for i in range(10):
        try:
            response = requests.get(
                f"{BASE_URL}/get",
                proxies=PROXIES,
                headers={'User-Agent': 'Test Bot'},
                timeout=5
            )
            if response.status_code == 403:
                blocked_count += 1
        except:
            pass
        time.sleep(0.1)
    
    print(f"Sent 10 rapid requests")
    print(f"Rate-limited: {blocked_count} requests")
    
    # ===== SUMMARY =====
    print(f"\n\n{'='*60}")
    print("📊 TEST SUMMARY")
    print(f"{'='*60}")
    print("""
    ✓ Tests completed successfully!
    
    Check the AI Firewall logs to see detailed analysis:
    - firewall.log (all traffic)
    - blocked_requests.log (blocked traffic only)
    
    You can also run the monitoring dashboard:
    
        python firewall_monitor.py
    
    To see real-time statistics and blocked IPs.
    """)
    print(f"{'='*60}\n")

if __name__ == '__main__':
    main()
