import os
import sqlite3
import logging
import json
import requests
import threading
import time
from flask import Flask, request, abort, jsonify, render_template_string, redirect, url_for

# ==========================================
# CONFIGURATION & SETUP
# ==========================================
app = Flask(__name__)

# Configure professional logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Firewall_Manager")

DB_FILE = "firewall_rules.db"
THREAT_SOURCE_URL = "http://localhost:5050/threats"
POLL_INTERVAL = 5  # Seconds

# ==========================================
# DATABASE LAYER
# ==========================================
def init_db():
    """Initialize the SQLite database with status support."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # Create table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                ml_confidence FLOAT,
                status TEXT DEFAULT 'BLOCKED',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Migration: Check if 'status' column exists, if not add it
        cursor.execute("PRAGMA table_info(blocked_registry)")
        columns = [info[1] for info in cursor.fetchall()]
        if 'status' not in columns:
            logger.info("Migrating database: Adding 'status' column...")
            cursor.execute("ALTER TABLE blocked_registry ADD COLUMN status TEXT DEFAULT 'BLOCKED'")
        
        conn.commit()
    logger.info("Database initialized and schema verified.")

def persist_block(ip, reason, confidence=1.0):
    """Write a new block rule to the database."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            # Insert or Ignore to avoid duplicates, but if it exists, ensure it's BLOCKED
            cursor.execute('''
                INSERT INTO blocked_registry (ip_address, reason, ml_confidence, status)
                VALUES (?, ?, ?, 'BLOCKED')
                ON CONFLICT(ip_address) DO UPDATE SET
                    reason=excluded.reason,
                    timestamp=CURRENT_TIMESTAMP,
                    status='BLOCKED'
            ''', (ip, reason, confidence))
            conn.commit()
        logger.warning(f"⛔ IP {ip} has been BLOCKED and persisted to DB.")
    except Exception as e:
        logger.error(f"Database error while blocking IP: {e}")

def get_all_blocks():
    """Retrieve all records for the dashboard."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocked_registry ORDER BY timestamp DESC")
        return [dict(row) for row in cursor.fetchall()]

def toggle_ip_status(ip):
    """Toggle the status of an IP between BLOCKED and ALLOWED."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM blocked_registry WHERE ip_address = ?", (ip,))
        row = cursor.fetchone()
        if row:
            new_status = 'ALLOWED' if row[0] == 'BLOCKED' else 'BLOCKED'
            cursor.execute("UPDATE blocked_registry SET status = ? WHERE ip_address = ?", (new_status, ip))
            conn.commit()
            logger.info(f"Updated status for {ip} to {new_status}")
            return new_status
    return None

# ==========================================
# THREAT POLLING SERVICE
# ==========================================
def poll_threats_service():
    """Background service to fetch threats from app.py and update DB."""
    logger.info("Threat Polling Service Started...")
    while True:
        try:
            response = requests.get(THREAT_SOURCE_URL, timeout=2)
            if response.status_code == 200:
                data = response.json()
                threats = data.get("threats", [])
                
                for threat in threats:
                    # Check if action is BLOCK
                    if threat.get("ml_action") == "BLOCK":
                        target_ip = threat.get("target_ip")
                        # In app.py, target_ip is actually the attacker's IP (source)
                        
                        if target_ip:
                            # Add to database
                            persist_block(
                                ip=target_ip,
                                reason=f"{threat.get('attack_type')} ({threat.get('threat_level')})",
                                confidence=0.95 # Default high confidence for ML blocks
                            )
            else:
                logger.warning(f"Polling failed: HTTP {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            # Expected if app.py is not running yet
            pass
        except Exception as e:
            logger.error(f"Error in polling service: {e}")
            
        time.sleep(POLL_INTERVAL)

# ==========================================
# DASHBOARD ROUTES
# ==========================================
@app.route('/dashboard')
def dashboard():
    """Render the Firewall Management Dashboard."""
    blocks = get_all_blocks()
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>AI Firewall Manager</title>
        <meta http-equiv="refresh" content="10">
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a0a; color: #e0e0e0; margin: 0; padding: 20px; }
            .container { max-width: 1400px; margin: 0 auto; }
            h1 { color: #00ff9d; border-bottom: 3px solid #00ff9d; padding-bottom: 15px; font-size: 2.2rem; margin-bottom: 10px; }
            .card { background: linear-gradient(145deg, #1a1a1a, #0f0f0f); border-radius: 12px; padding: 30px; box-shadow: 0 8px 16px rgba(0,0,0,0.5); border: 1px solid #222; }
            table { width: 100%; border-collapse: collapse; margin-top: 25px; }
            th, td { padding: 16px; text-align: left; border-bottom: 1px solid #2a2a2a; }
            th { color: #00ff9d; font-weight: 700; text-transform: uppercase; font-size: 0.85rem; letter-spacing: 1px; background: #151515; }
            tr:hover { background: #1f1f1f; }
            tbody tr { transition: background 0.2s; }
            
            .status-badge { padding: 6px 12px; border-radius: 6px; font-size: 0.8rem; font-weight: bold; display: inline-block; }
            .status-blocked { background: #ff4444; color: #fff; box-shadow: 0 0 10px rgba(255,68,68,0.3); }
            .status-allowed { background: #00cc66; color: #fff; box-shadow: 0 0 10px rgba(0,204,102,0.3); }
            
            .meta { font-size: 0.95rem; color: #888; margin-bottom: 5px; }
            
            /* Toggle Switch Styling */
            .toggle-container { display: flex; align-items: center; justify-content: center; gap: 10px; }
            .switch { position: relative; display: inline-block; width: 60px; height: 30px; }
            .switch input { opacity: 0; width: 0; height: 0; }
            .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #555; transition: .3s; border-radius: 30px; }
            .slider:before { position: absolute; content: ""; height: 22px; width: 22px; left: 4px; bottom: 4px; background-color: white; transition: .3s; border-radius: 50%; }
            input:checked + .slider { background-color: #00ff9d; box-shadow: 0 0 10px rgba(0,255,157,0.5); }
            input:checked + .slider:before { transform: translateX(30px); }
            .toggle-label { font-size: 0.85rem; color: #aaa; min-width: 80px; font-weight: 600; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <h1>🛡️ AI Firewall Manager</h1>
                <p class="meta">Connected to: ''' + THREAT_SOURCE_URL + '''</p>
                <p class="meta">Database: ''' + DB_FILE + '''</p>
                
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Status</th>
                            <th>Reason</th>
                            <th>Confidence</th>
                            <th>Last Updated</th>
                            <th style="text-align: center;">Block Control</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for block in blocks %}
                        <tr>
                            <td style="font-family: 'Courier New', monospace; font-size: 1.15rem; color: #00d4ff;">{{ block.ip_address }}</td>
                            <td>
                                <span class="status-badge {{ 'status-blocked' if block.status == 'BLOCKED' else 'status-allowed' }}">
                                    {{ block.status }}
                                </span>
                            </td>
                            <td style="color: #ccc;">{{ block.reason }}</td>
                            <td style="color: #ffaa00; font-weight: 600;">{{ (block.ml_confidence * 100)|round|int }}%</td>
                            <td style="color: #999; font-size: 0.9rem;">{{ block.timestamp }}</td>
                            <td style="text-align: center;">
                                <div class="toggle-container">
                                    <span class="toggle-label">{{ 'BLOCKED' if block.status == 'BLOCKED' else 'ALLOWED' }}</span>
                                    <label class="switch">
                                        <input type="checkbox" {{ 'checked' if block.status == 'BLOCKED' else '' }} 
                                               onclick="window.location.href='/toggle/{{ block.ip_address }}'">
                                        <span class="slider"></span>
                                    </label>
                                </div>
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 60px; color: #555; font-size: 1.1rem;">
                                🔍 No threats detected yet. System is actively monitoring...
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html, blocks=blocks)

@app.route('/toggle/<ip>')
def toggle_route(ip):
    """Handle the toggle button click."""
    toggle_ip_status(ip)
    return redirect(url_for('dashboard'))

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == '__main__':
    # 1. Initialize Database
    init_db()
    
    # 2. Start Threat Polling in Background
    poller = threading.Thread(target=poll_threats_service, daemon=True)
    poller.start()
    
    print("--------------------------------------------------")
    print("FIREWALL MANAGER ACTIVE")
    print("Dashboard: http://localhost:5000/dashboard")
    print("--------------------------------------------------")
    
    # Run Flask (Manager Interface)
    app.run(host='0.0.0.0', port=5000, debug=True)

    