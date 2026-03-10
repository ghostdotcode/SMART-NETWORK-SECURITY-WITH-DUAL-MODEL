"""
FIREWALL STARTUP SCRIPT
=======================
This script ensures both services are running for complete protection.

Services:
1. app.py (Port 5050) - AI Threat Detection
2. codetoBLOCK.py (Port 5000) - Firewall Enforcement

Usage:
    python start_firewall_system.py
"""

import subprocess
import time
import sys
import os

def start_service(script_name, port, description):
    """Start a service in a new terminal window"""
    print(f"\n[STARTING] {description} on port {port}...")
    
    if sys.platform == "win32":
        # Windows: Start in new command prompt window
        cmd = f'start cmd /k "python {script_name}"'
        subprocess.Popen(cmd, shell=True, cwd=os.getcwd())
    else:
        # Linux/Mac: Start in background
        subprocess.Popen(["python", script_name], cwd=os.getcwd())
    
    print(f"[OK] {description} started")
    time.sleep(2)

def main():
    print("=" * 80)
    print("AI FIREWALL SYSTEM - STARTUP")
    print("=" * 80)
    
    # Start AI Detection Service
    start_service("app.py", 5050, "AI Threat Detection Service")
    
    # Start Firewall Enforcement
    start_service("codetoBLOCK.py", 5000, "Firewall Enforcement Service")
    
    print("\n" + "=" * 80)
    print("SYSTEM READY")
    print("=" * 80)
    print("\nBoth services are now running:")
    print("  - AI Detection:  http://localhost:5050")
    print("  - Firewall:      http://localhost:5000")
    print("\nBlocked IPs will be automatically rejected.")
    print("Press Ctrl+C in each terminal window to stop services.")
    print("=" * 80)

if __name__ == "__main__":
    main()
