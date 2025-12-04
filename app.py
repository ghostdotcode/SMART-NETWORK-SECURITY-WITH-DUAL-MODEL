from flask import Flask, request, jsonify
import warnings
import traceback
from datetime import datetime
from collections import defaultdict
import threading

# Scapy imports for packet capture
from scapy.all import sniff, IP, TCP, UDP, ICMP

# --- 1. Import ML inference function ---
try:
    from inference import predict_threat
except ImportError:
    print("FATAL ERROR: Could not import 'predict_threat' from 'inference.py'.")
    print("Please ensure 'inference.py' is in the same directory as 'app.py'.")
    exit()

warnings.filterwarnings('ignore')

# --- 2. Initialize Flask Application ---
app = Flask(__name__)
print("Flask application initialized.")

# --- 3. Attack Detection Thresholds ---
SYN_FLOOD_THRESHOLD = 50  # SYN packets per second from same IP
PORT_SCAN_THRESHOLD = 10   # Different ports accessed per second
ICMP_FLOOD_THRESHOLD = 30  # ICMP packets per second
UDP_FLOOD_THRESHOLD = 50   # UDP packets per second

# --- 4. IP Statistics Tracking ---
ip_stats = defaultdict(lambda: {
    'syn_count': 0,
    'udp_count': 0,
    'icmp_count': 0,
    'ports_accessed': set(),
    'total_packets': 0,
    'first_seen': datetime.now(),
    'last_seen': datetime.now(),
    'target_ip': None  # Store target IP
})

# --- 5. Threat Tracking System (No Redundancy) ---
reported_ips = set()  # Track source IPs already reported to avoid duplicates
threats = []  # Store all threat detections in JSON format

# --- 6. Statistics ---
stats = {
    'total_packets': 0,
    'syn_floods': 0,
    'port_scans': 0,
    'icmp_floods': 0,
    'udp_floods': 0,
    'ml_predictions': 0,
    'start_time': datetime.now()
}


# --- 7. Helper Functions ---

def calculate_malicious_score(ip_data, attack_type):
    """Calculate malicious score (0-100) based on attack patterns"""
    time_window = (ip_data['last_seen'] - ip_data['first_seen']).total_seconds()
    if time_window < 1:
        time_window = 1
    
    if attack_type == 'SYN FLOOD':
        syn_rate = ip_data['syn_count'] / time_window
        score = min(100, (syn_rate / SYN_FLOOD_THRESHOLD) * 100)
    elif attack_type == 'PORT SCAN':
        ports_rate = len(ip_data['ports_accessed']) / time_window
        score = min(100, (ports_rate / PORT_SCAN_THRESHOLD) * 100)
    elif attack_type == 'ICMP FLOOD':
        icmp_rate = ip_data['icmp_count'] / time_window
        score = min(100, (icmp_rate / ICMP_FLOOD_THRESHOLD) * 100)
    elif attack_type == 'UDP FLOOD':
        udp_rate = ip_data['udp_count'] / time_window
        score = min(100, (udp_rate / UDP_FLOOD_THRESHOLD) * 100)
    else:
        score = 0
    
    return round(score, 1)


def get_threat_level_from_score(score):
    """Get threat level based on malicious score"""
    if score >= 71:
        return "malicious"
    elif score >= 31:
        return "suspicious"
    else:
        return "clean"


def map_ml_action(predicted_action):
    """Map CHALLENGE/JSCHALLENGE to BLOCK as requested"""
    if predicted_action in ['CHALLENGE', 'JSCHALLENGE', 'BLOCK', 'MANAGED_CHALLENGE']:
        return "BLOCK"
    return predicted_action


def add_threat(src_ip, target_ip, attack_type, ml_action, threat_level):
    """Add threat to tracking system if source IP not already reported"""
    global reported_ips, threats
    
    # Only add if this source IP hasn't been reported yet
    if src_ip not in reported_ips:
        reported_ips.add(src_ip)
        
        threat_entry = {
            "attack_type": attack_type,
            "target_ip": target_ip,
            "ml_action": ml_action,
            "threat_level": threat_level,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        threats.append(threat_entry)
        print(f"[THREAT DETECTED] {src_ip} → {target_ip} | {attack_type} | {threat_level}")
        return True
    else:
        return False


# --- 8. Packet Analysis Function ---

def analyze_packet(packet):
    """Analyze each packet for attack patterns"""
    global stats
    
    stats['total_packets'] += 1
    
    if not packet.haslayer(IP):
        return
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # Update IP stats
    ip_data = ip_stats[src_ip]
    ip_data['total_packets'] += 1
    ip_data['last_seen'] = datetime.now()
    ip_data['target_ip'] = dst_ip  # Store target IP
    
    # Calculate time window
    time_window = (ip_data['last_seen'] - ip_data['first_seen']).total_seconds()
    if time_window < 1:
        time_window = 1
    
    attack_detected = False
    attack_type = None
    
    # Detect SYN Flood
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        ip_data['ports_accessed'].add(tcp_layer.dport)
        
        # SYN flag detection
        if tcp_layer.flags == 'S':  # SYN flag
            ip_data['syn_count'] += 1
            syn_rate = ip_data['syn_count'] / time_window
            
            if syn_rate > SYN_FLOOD_THRESHOLD:
                attack_detected = True
                attack_type = 'SYN FLOOD'
                stats['syn_floods'] += 1
        
        # Port scan detection
        ports_rate = len(ip_data['ports_accessed']) / time_window
        if ports_rate > PORT_SCAN_THRESHOLD:
            if not attack_detected:  # Don't override SYN flood
                attack_detected = True
                attack_type = 'PORT SCAN'
                stats['port_scans'] += 1
    
    # Detect ICMP Flood
    elif packet.haslayer(ICMP):
        ip_data['icmp_count'] += 1
        icmp_rate = ip_data['icmp_count'] / time_window
        
        if icmp_rate > ICMP_FLOOD_THRESHOLD:
            attack_detected = True
            attack_type = 'ICMP FLOOD'
            stats['icmp_floods'] += 1
    
    # Detect UDP Flood
    elif packet.haslayer(UDP):
        ip_data['udp_count'] += 1
        udp_rate = ip_data['udp_count'] / time_window
        
        if udp_rate > UDP_FLOOD_THRESHOLD:
            attack_detected = True
            attack_type = 'UDP FLOOD'
            stats['udp_floods'] += 1
    
    # Process attack if detected
    if attack_detected:
        score = calculate_malicious_score(ip_data, attack_type)
        threat_level = get_threat_level_from_score(score)
        
        # Query ML model for prediction
        ml_action = "BLOCK"  # Default
        try:
            ml_request_data = {
                "IP": src_ip,
                "Endpoint": f"/attack/{attack_type.lower().replace(' ', '_')}",
                "User-Agent": "Network-Attack-Tool",
                "Country": "US",
                "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            ml_result = predict_threat(ml_request_data)
            stats['ml_predictions'] += 1
            
            predicted_action = ml_result.get('predicted_action', 'BLOCK')
            ml_action = map_ml_action(predicted_action)
            
        except Exception as e:
            print(f"[ML ERROR] {e}")
            pass  # Use default BLOCK action
        
        # Add to threat tracking (only if unique source IP)
        # target_ip should be the attacker's IP (src_ip), not the victim's IP
        add_threat(src_ip, src_ip, attack_type, ml_action, threat_level)


# --- 9. Packet Capture Thread ---

def start_packet_capture():
    """Start packet capture in background thread"""
    print("[PACKET CAPTURE] Starting network monitoring...")
    print("[PACKET CAPTURE] Listening for attacks...")
    
    try:
        # Sniff all IP packets
        sniff(
            prn=analyze_packet,
            store=0,  # Don't store packets in memory
            filter="ip"  # Capture all IP packets
        )
    except Exception as e:
        print(f"[PACKET CAPTURE ERROR] {e}")
        print("[PACKET CAPTURE] Make sure you're running as Administrator!")


# --- 10. API Endpoints ---

@app.route('/predict', methods=['POST'])
def handle_prediction():
    """
    Manual prediction endpoint (for compatibility).
    Main threat detection happens via packet sniffing.
    """
    print("\n[API] Received request on /predict endpoint...")
    
    if not request.is_json:
        return jsonify({"error": "Invalid input: request must be in JSON format."}), 400
    
    data = request.get_json()
    
    # Check for required fields
    required_fields = ['IP', 'Endpoint', 'User-Agent', 'Country', 'Date']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        error_msg = f"Missing required fields: {', '.join(missing_fields)}"
        return jsonify({"error": error_msg}), 400
    
    try:
        # Get ML prediction
        result = predict_threat(data)
        return jsonify(result), 200
    
    except Exception as e:
        error_details = traceback.format_exc()
        print(f"[API ERROR] {e}")
        return jsonify({
            "error": "An internal error occurred during prediction.",
            "details": str(e)
        }), 500


@app.route('/threats', methods=['GET'])
def get_threats():
    """
    Returns all tracked threats as a JSON array.
    Only includes unique source IPs (no redundancy).
    """
    return jsonify({"threats": threats}), 200


@app.route('/')
def index():
    """
    Returns API information and current threat statistics as JSON.
    """
    return jsonify({
        "status": "AI Firewall Active",
        "message": "Network threat detection system is running",
        "endpoints": {
            "/": "API information and statistics",
            "/predict": "POST - Submit request for ML threat prediction",
            "/threats": "GET - Retrieve all detected threats (unique IPs only)"
        },
        "statistics": {
            "total_packets": stats['total_packets'],
            "total_threats": len(threats),
            "unique_ips": len(reported_ips),
            "syn_floods": stats['syn_floods'],
            "port_scans": stats['port_scans'],
            "icmp_floods": stats['icmp_floods'],
            "udp_floods": stats['udp_floods'],
            "ml_predictions": stats['ml_predictions']
        },
        "threats": threats
    }), 200


# --- 11. Run the Application ---
if __name__ == '__main__':
    # Check if running as admin (Windows)
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("\n" + "="*79)
            print("ERROR: This application requires Administrator privileges!")
            print("Please run PowerShell/Command Prompt as Administrator")
            print("="*79 + "\n")
            exit()
    except:
        print("WARNING: Could not verify admin privileges\n")
    
    # Start packet capture in background thread
    capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
    capture_thread.start()
    
    # Give packet capture a moment to start
    import time
    time.sleep(1)
    
    print("\n" + "="*79)
    print("AI FIREWALL - Network Threat Detection System")
    print("="*79)
    print(f"Flask API running on: http://0.0.0.0:5050")
    print(f"Packet capture: ACTIVE")
    print(f"Endpoints:")
    print(f"  - GET  /          : API info + statistics")
    print(f"  - GET  /threats   : View detected threats")
    print(f"  - POST /predict   : Manual prediction")
    print("="*79 + "\n")
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5050, debug=False)
