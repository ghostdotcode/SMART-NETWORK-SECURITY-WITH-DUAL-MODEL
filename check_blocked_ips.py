import sqlite3

DB_FILE = "firewall_rules.db"

with sqlite3.connect(DB_FILE) as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_registry ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    
    print("=" * 100)
    print("BLOCKED IPs REGISTRY - codetoBLOCK.py")
    print("=" * 100)
    
    if rows:
        for row in rows:
            print(f"ID: {row[0]}")
            print(f"IP Address: {row[1]}")
            print(f"Reason: {row[2]}")
            print(f"ML Confidence: {row[3]}")
            print(f"Timestamp: {row[4]}")
            print("-" * 100)
        
        print(f"\nTotal IPs Blocked: {len(rows)}")
    else:
        print("No IPs have been blocked yet.")
    
    print("=" * 100)
