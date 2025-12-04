"""
NETWORK ATTACK DETECTOR WITH ML - Dual-Layer Detection System
Combines Rule-Based Detection + XGBoost ML Model Predictions
Monitors for: SYN floods, UDP floods, ICMP floods, Port scans, DDoS patterns

Requirements:
- Run as Administrator (for packet capture)
- pip install scapy colorama requests
- ML API must be running: python app.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import init, Fore, Back, Style
from datetime import datetime, timedelta
from collections import defaultdict
import os
import requests
import json

# Initialize colorama
init(autoreset=True)

# ===== ATTACK DETECTION THRESHOLDS =====
SYN_FLOOD_THRESHOLD = 50  # SYN packets per second from same IP
PORT_SCAN_THRESHOLD = 10   # Different ports accessed per second
ICMP_FLOOD_THRESHOLD = 30  # ICMP packets per second
UDP_FLOOD_THRESHOLD = 50   # UDP packets per second

# ===== ML MODEL CONFIGURATION =====
ML_MODEL_API = 'http://127.0.0.1:5050/predict'  # Flask API endpoint
USE_ML_PREDICTIONS = True  # Enable/disable ML predictions

# ===== TRACKING DICTIONARIES =====
ip_stats = defaultdict(lambda: {
    'syn_count': 0,
    'udp_count': 0,
    'icmp_count': 0,
    'ports_accessed': set(),
    'total_packets': 0,
    'first_seen': datetime.now(),
    'last_seen': datetime.now(),
    'flags': []
})

# ===== STATISTICS =====
stats = {
    'total_packets': 0,
    'syn_floods': 0,
    'port_scans': 0,
    'icmp_floods': 0,
    'udp_floods': 0,
    'ml_predictions': 0,
    'ml_blocked': 0,
    'ml_api_errors': 0,
    'start_time': datetime.now()
}

# ===== JSON OUTPUT TRACKING =====
reported_ips = set()  # Track IPs already reported to avoid redundancy
detection_results = []  # Store all detections in JSON format

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_client_country(ip):
    """Get country from IP - simplified for local testing"""
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('127.'):
        return 'US'  # Default for local IPs
    
    try:
        # Free IP geolocation API (limited requests)
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get('countryCode', 'US')
    except:
        pass
    
    return 'US'  # Default fallback

def query_ml_model(request_data):
    """Query ML model and return prediction"""
    if not USE_ML_PREDICTIONS:
        return None
    
    try:
        response = requests.post(ML_MODEL_API, json=request_data, timeout=5)
        if response.status_code == 200:
            stats['ml_predictions'] += 1
            return response.json()
        return None
    except Exception as e:
        stats['ml_api_errors'] += 1
        return None

def print_banner():
    """Print beautiful banner"""
    ml_status = f"{Fore.GREEN}ENABLED{Style.RESET_ALL}" if USE_ML_PREDICTIONS else f"{Fore.YELLOW}DISABLED{Style.RESET_ALL}"
    banner = f"""
{Fore.RED}{'='*79}
                                                                             
        {Fore.YELLOW}⚠️  NETWORK ATTACK DETECTOR - Dual-Layer Detection{Fore.RED}          
                                                                             
     {Fore.CYAN}Rule-Based Detection + XGBoost ML Model Predictions{Fore.RED}     
     {Fore.CYAN}Monitors: SYN Floods | Port Scans | ICMP/UDP Floods | DDoS{Fore.RED}            
                                                                             
{'='*79}{Style.RESET_ALL}

{Fore.WHITE}Detection Capabilities:{Style.RESET_ALL}
   🎯 SYN Flood Detection    - Threshold: {SYN_FLOOD_THRESHOLD} pkts/sec
   🎯 Port Scan Detection    - Threshold: {PORT_SCAN_THRESHOLD} ports/sec
   🎯 ICMP Flood Detection   - Threshold: {ICMP_FLOOD_THRESHOLD} pkts/sec
   🎯 UDP Flood Detection    - Threshold: {UDP_FLOOD_THRESHOLD} pkts/sec
   🤖 ML Model Predictions   - Status: {ml_status}

{Fore.WHITE}Malicious Score Legend:{Style.RESET_ALL}
   {Fore.GREEN}[0-30%]{Style.RESET_ALL}   = Low threat (Normal traffic)
   {Fore.YELLOW}[31-70%]{Style.RESET_ALL}  = Medium threat (Suspicious pattern)
   {Fore.RED}[71-100%]{Style.RESET_ALL} = High threat (Attack detected!)

{Fore.CYAN}{'='*79}{Style.RESET_ALL}
{Fore.WHITE}Starting packet capture... (press Ctrl+C to stop){Style.RESET_ALL}
{Fore.CYAN}{'='*79}{Style.RESET_ALL}

"""
    print(banner)

def calculate_malicious_score(ip_data, attack_type):
    """Calculate malicious score (0-100) based on attack patterns"""
    score = 0
    
    # Base score on packet rate
    time_window = (ip_data['last_seen'] - ip_data['first_seen']).total_seconds()
    if time_window < 1:
        time_window = 1
    
    packets_per_sec = ip_data['total_packets'] / time_window
    
    # Score components
    if attack_type == 'SYN_FLOOD':
        syn_rate = ip_data['syn_count'] / time_window
        score = min(100, (syn_rate / SYN_FLOOD_THRESHOLD) * 100)
    
    elif attack_type == 'PORT_SCAN':
        ports_rate = len(ip_data['ports_accessed']) / time_window
        score = min(100, (ports_rate / PORT_SCAN_THRESHOLD) * 100)
    
    elif attack_type == 'ICMP_FLOOD':
        icmp_rate = ip_data['icmp_count'] / time_window
        score = min(100, (icmp_rate / ICMP_FLOOD_THRESHOLD) * 100)
    
    elif attack_type == 'UDP_FLOOD':
        udp_rate = ip_data['udp_count'] / time_window
        score = min(100, (udp_rate / UDP_FLOOD_THRESHOLD) * 100)
    
    return round(score, 1)

def get_threat_level(score):
    """Get threat level and color based on score"""
    if score >= 71:
        return "HIGH THREAT", Fore.RED, "🚨"
    elif score >= 31:
        return "MEDIUM THREAT", Fore.YELLOW, "⚠️"
    else:
        return "LOW THREAT", Fore.GREEN, "✓"

def get_threat_category(score):
    """Get threat category for JSON output (clean/suspicious/malicious)"""
    if score >= 71:
        return "malicious"
    elif score >= 31:
        return "suspicious"
    else:
        return "clean"

def add_to_json_output(src_ip, attack_type, score):
    """Add detection to JSON output array if IP not already reported"""
    global reported_ips, detection_results
    
    # Only add if this IP hasn't been reported yet
    if src_ip not in reported_ips:
        reported_ips.add(src_ip)
        
        detection_entry = {
            "ip": src_ip,
            "threat_level": get_threat_category(score),
            "attack_type": attack_type.replace('_', ' ')
        }
        
        detection_results.append(detection_entry)
        
        # Print JSON array (updated with new entry)
        print(f"\n{Fore.MAGENTA}{'='*79}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}📋 JSON OUTPUT (Unique IPs Only):{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*79}{Style.RESET_ALL}")
        print(json.dumps(detection_results, indent=2))
        print(f"{Fore.MAGENTA}{'='*79}{Style.RESET_ALL}\n")

def print_attack_detection(src_ip, dst_ip, attack_type, score, ip_data, packet_info, ml_result=None):
    """Print beautiful attack detection alert"""
    
    threat_level, color, symbol = get_threat_level(score)
    
    # Create progress bar
    bar_length = int(score / 5)  # 5% = 1 char
    bar = '█' * bar_length
    
    print(f"\n{color}{'='*79}{Style.RESET_ALL}")
    print(f"\n{color}{symbol} ATTACK DETECTED #{stats['total_packets']:05d} • {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}")
    print(f"{color}{'─'*79}{Style.RESET_ALL}")
    
    # Attack info
    print(f"\n{Fore.WHITE}🎯 Attack Classification:{Style.RESET_ALL}")
    print(f"   Type:           {color}{attack_type.replace('_', ' ')}{Style.RESET_ALL}")
    print(f"   Threat Level:   {color}{threat_level}{Style.RESET_ALL}")
    print(f"   Malicious Score: {color}{score}%{Style.RESET_ALL} {color}{bar}{Style.RESET_ALL}")
    
    # Source/Destination
    print(f"\n{Fore.WHITE}🌐 Network Information:{Style.RESET_ALL}")
    print(f"   Source IP:      {Fore.CYAN}{src_ip}{Style.RESET_ALL}")
    print(f"   Target IP:      {Fore.CYAN}{dst_ip}{Style.RESET_ALL}")
    if packet_info.get('src_port'):
        print(f"   Source Port:    {Fore.CYAN}{packet_info['src_port']}{Style.RESET_ALL}")
    if packet_info.get('dst_port'):
        print(f"   Target Port:    {Fore.CYAN}{packet_info['dst_port']}{Style.RESET_ALL}")
    
    # Attack statistics
    time_window = (ip_data['last_seen'] - ip_data['first_seen']).total_seconds()
    if time_window < 1:
        time_window = 1
    
    print(f"\n{Fore.WHITE}📊 Attack Statistics:{Style.RESET_ALL}")
    print(f"   Total Packets:  {Fore.CYAN}{ip_data['total_packets']}{Style.RESET_ALL}")
    print(f"   SYN Packets:    {Fore.CYAN}{ip_data['syn_count']}{Style.RESET_ALL}")
    print(f"   UDP Packets:    {Fore.CYAN}{ip_data['udp_count']}{Style.RESET_ALL}")
    print(f"   ICMP Packets:   {Fore.CYAN}{ip_data['icmp_count']}{Style.RESET_ALL}")
    print(f"   Ports Scanned:  {Fore.CYAN}{len(ip_data['ports_accessed'])}{Style.RESET_ALL}")
    print(f"   Packets/Sec:    {Fore.CYAN}{ip_data['total_packets']/time_window:.1f}{Style.RESET_ALL}")
    print(f"   Duration:       {Fore.CYAN}{time_window:.1f}s{Style.RESET_ALL}")
    
    # Attack indicators
    print(f"\n{Fore.WHITE}🔍 Attack Indicators:{Style.RESET_ALL}")
    for flag in ip_data['flags'][-5:]:  # Show last 5 flags
        print(f"   {color}• {flag}{Style.RESET_ALL}")
    
    # ML Model Prediction (if available)
    if ml_result:
        print(f"\n{Fore.WHITE}🤖 ML Model Prediction:{Style.RESET_ALL}")
        ml_action = ml_result.get('predicted_action', 'N/A')
        ml_confidence = ml_result.get('confidence_scores', {})
        
        # Color code the ML action
        if ml_action in ['BLOCK', 'JSCHALLENGE']:
            ml_color = Fore.RED
        elif ml_action == 'CHALLENGE':
            ml_color = Fore.YELLOW
        else:
            ml_color = Fore.GREEN
        
        print(f"   Action:         {ml_color}{ml_action}{Style.RESET_ALL}")
        if ml_confidence:
            print(f"   Confidence:     {Fore.CYAN}{str(ml_confidence)}{Style.RESET_ALL}")
    
    print(f"\n{color}{'='*79}{Style.RESET_ALL}")

def print_statistics():
    """Print overall statistics"""
    uptime = datetime.now() - stats['start_time']
    
    print(f"\n{Fore.CYAN}{'='*79}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}📈 SESSION STATISTICS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*79}{Style.RESET_ALL}")
    print(f"   {Fore.WHITE}Total Packets:     {Fore.CYAN}{stats['total_packets']:,}{Style.RESET_ALL}")
    print(f"   {Fore.RED}SYN Floods:        {stats['syn_floods']:,}{Style.RESET_ALL}")
    print(f"   {Fore.RED}Port Scans:        {stats['port_scans']:,}{Style.RESET_ALL}")
    print(f"   {Fore.RED}ICMP Floods:       {stats['icmp_floods']:,}{Style.RESET_ALL}")
    print(f"   {Fore.RED}UDP Floods:        {stats['udp_floods']:,}{Style.RESET_ALL}")
    print(f"   {Fore.WHITE}Active Attackers:  {Fore.CYAN}{len(ip_stats)}{Style.RESET_ALL}")
    
    if USE_ML_PREDICTIONS:
        print(f"   {Fore.MAGENTA}ML Predictions:    {stats['ml_predictions']:,}{Style.RESET_ALL}")
        print(f"   {Fore.MAGENTA}ML Blocked:        {stats['ml_blocked']:,}{Style.RESET_ALL}")
        print(f"   {Fore.YELLOW}ML API Errors:     {stats['ml_api_errors']:,}{Style.RESET_ALL}")
    
    print(f"   {Fore.WHITE}Session Uptime:    {Fore.CYAN}{str(uptime).split('.')[0]}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*79}{Style.RESET_ALL}")

def analyze_packet(packet):
    """Analyze each packet for attack patterns"""
    stats['total_packets'] += 1
    
    if not packet.haslayer(IP):
        return
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # Update IP stats
    ip_data = ip_stats[src_ip]
    ip_data['total_packets'] += 1
    ip_data['last_seen'] = datetime.now()
    
    # Calculate time window ONCE at the start (fixes undefined variable bug)
    time_window = (ip_data['last_seen'] - ip_data['first_seen']).total_seconds()
    if time_window < 1:
        time_window = 1
    
    packet_info = {}
    attack_detected = False
    attack_type = None
    
    # Detect SYN Flood
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        packet_info['src_port'] = tcp_layer.sport
        packet_info['dst_port'] = tcp_layer.dport
        
        # Track ports accessed
        ip_data['ports_accessed'].add(tcp_layer.dport)
        
        # SYN flag detection
        if tcp_layer.flags == 'S':  # SYN flag
            ip_data['syn_count'] += 1
            syn_rate = ip_data['syn_count'] / time_window
            
            if syn_rate > SYN_FLOOD_THRESHOLD:
                attack_detected = True
                attack_type = 'SYN_FLOOD'
                stats['syn_floods'] += 1
                ip_data['flags'].append(f"SYN Flood: {syn_rate:.1f} pkts/sec (Threshold: {SYN_FLOOD_THRESHOLD})")
        
        # Port scan detection
        ports_rate = len(ip_data['ports_accessed']) / time_window
        if ports_rate > PORT_SCAN_THRESHOLD:
            if not attack_detected:  # Don't override SYN flood
                attack_detected = True
                attack_type = 'PORT_SCAN'
                stats['port_scans'] += 1
                ip_data['flags'].append(f"Port Scan: {len(ip_data['ports_accessed'])} ports in {time_window:.1f}s")
    
    # Detect ICMP Flood
    elif packet.haslayer(ICMP):
        ip_data['icmp_count'] += 1
        icmp_rate = ip_data['icmp_count'] / time_window
        
        if icmp_rate > ICMP_FLOOD_THRESHOLD:
            attack_detected = True
            attack_type = 'ICMP_FLOOD'
            stats['icmp_floods'] += 1
            ip_data['flags'].append(f"ICMP Flood: {icmp_rate:.1f} pkts/sec (Threshold: {ICMP_FLOOD_THRESHOLD})")
    
    # Detect UDP Flood
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        packet_info['src_port'] = udp_layer.sport
        packet_info['dst_port'] = udp_layer.dport
        
        ip_data['udp_count'] += 1
        udp_rate = ip_data['udp_count'] / time_window
        
        if udp_rate > UDP_FLOOD_THRESHOLD:
            attack_detected = True
            attack_type = 'UDP_FLOOD'
            stats['udp_floods'] += 1
            ip_data['flags'].append(f"UDP Flood: {udp_rate:.1f} pkts/sec (Threshold: {UDP_FLOOD_THRESHOLD})")
    
    
    # Print attack if detected
    if attack_detected:
        score = calculate_malicious_score(ip_data, attack_type)
        
        # Add to JSON output (only if IP not already reported)
        add_to_json_output(src_ip, attack_type, score)
        
        # Query ML model for additional prediction
        ml_result = None
        if USE_ML_PREDICTIONS:
            try:
                # Prepare data for ML model
                country = get_client_country(src_ip)
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                ml_request_data = {
                    "IP": src_ip,
                    "Endpoint": f"/attack/{attack_type.lower()}",  # Simulated endpoint
                    "User-Agent": "Network-Attack-Tool",  # Generic for network attacks
                    "Country": country,
                    "Date": current_time
                }
                
                ml_result = query_ml_model(ml_request_data)
                
                # Track if ML would block this
                if ml_result and ml_result.get('predicted_action') in ['BLOCK', 'JSCHALLENGE']:
                    stats['ml_blocked'] += 1
            except Exception as e:
                pass  # Silent fail, continue with rule-based detection
        
        print_attack_detection(src_ip, dst_ip, attack_type, score, ip_data, packet_info, ml_result)
        
        # Print statistics every 20 attacks
        if (stats['syn_floods'] + stats['port_scans'] + stats['icmp_floods'] + stats['udp_floods']) % 20 == 0:
            print_statistics()

def main():
    """Main entry point"""
    # Check if running as admin
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print(f"{Fore.RED}[X] ERROR: This script requires Administrator privileges!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}    Please run PowerShell/Command Prompt as Administrator{Style.RESET_ALL}\n")
            return
    except:
        print(f"{Fore.YELLOW}[!] WARNING: Could not verify admin privileges{Style.RESET_ALL}\n")
    
    clear_screen()
    print_banner()
    
    # Check if ML Model API is accessible
    if USE_ML_PREDICTIONS:
        try:
            test_response = requests.get('http://127.0.0.1:5050/', timeout=3)
            print(f"{Fore.GREEN}[✓] ML Model API is accessible{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] WARNING: ML Model API is not running!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}    ML predictions will be disabled. Start app.py for ML features.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}    Continuing with rule-based detection only...{Style.RESET_ALL}\n")
    
    
    # Start sniffing
    try:
        print(f"{Fore.GREEN}[MONITORING] Capturing all network packets...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[INFO] Launch hping from Kali - Attacks will be detected below{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}Example hping commands:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}SYN Flood:   {Fore.CYAN}hping3 -S --flood -p 80 <target_ip>{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}ICMP Flood:  {Fore.CYAN}hping3 -1 --flood <target_ip>{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}UDP Flood:   {Fore.CYAN}hping3 -2 --flood -p 80 <target_ip>{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Port Scan:   {Fore.CYAN}hping3 -S --scan 1-1000 <target_ip>{Style.RESET_ALL}\n")
        
        # Sniff all packets
        sniff(
            prn=analyze_packet,
            store=0,  # Don't store packets in memory
            filter="ip"  # Capture all IP packets
        )
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[STOP] Stopping Attack Detector...{Style.RESET_ALL}\n")
        print_statistics()
        
        # Print final JSON output
        print(f"\n{Fore.MAGENTA}{'='*79}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}📋 FINAL JSON OUTPUT (All Unique Detected IPs):{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*79}{Style.RESET_ALL}")
        print(json.dumps(detection_results, indent=2))
        print(f"{Fore.MAGENTA}{'='*79}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[OK] Detection session ended{Style.RESET_ALL}\n")
    except PermissionError:
        print(f"{Fore.RED}[X] Permission denied! Run as Administrator{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.RED}[X] Error: {e}{Style.RESET_ALL}\n")

if __name__ == '__main__':
    main()
