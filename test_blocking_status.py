import requests
import sqlite3

print("=" * 80)
print("FIREWALL STATUS CHECK")
print("=" * 80)

# Check database
with sqlite3.connect("firewall_rules.db") as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, reason FROM blocked_registry")
    blocked_ips = cursor.fetchall()
    
print(f"\nBlocked IPs in Database: {len(blocked_ips)}")
for ip, reason in blocked_ips:
    print(f"   [BLOCKED] {ip} - {reason}")

# Check if firewall is running
print("\nTesting Firewall Service (Port 5000)...")
try:
    response = requests.get("http://localhost:5000/", timeout=2)
    print(f"   [OK] Firewall is RUNNING on port 5000")
    print(f"   Response: {response.status_code}")
except Exception as e:
    print(f"   [ERROR] Firewall is NOT running: {e}")

# Check if AI service is running
print("\nTesting AI Service (Port 5050)...")
try:
    response = requests.get("http://localhost:5050/threats", timeout=2)
    print(f"   [OK] AI Service is RUNNING on port 5050")
    print(f"   Threats detected: {len(response.json().get('threats', []))}")
except Exception as e:
    print(f"   [ERROR] AI Service is NOT running: {e}")

print("\n" + "=" * 80)
print("RECOMMENDATION:")
print("Both services must be running for the firewall to work:")
print("  1. app.py on port 5050 (AI Threat Detection)")
print("  2. codetoBLOCK.py on port 5000 (Firewall Enforcement)")
print("=" * 80)
