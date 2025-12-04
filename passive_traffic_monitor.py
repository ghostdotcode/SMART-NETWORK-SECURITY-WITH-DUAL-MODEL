"""
AI TRAFFIC ANALYZER - TRUE PASSIVE MONITORING
Uses packet sniffing (Scapy) to monitor network traffic without any proxy configuration
Analyzes HTTP requests with ML model in real-time - NO internet disruption!

Requirements:
- Run as Administrator (for packet capture)
- pip install scapy colorama requests
"""

from scapy.all import sniff, TCP, IP, Raw
from colorama import init, Fore, Back, Style
import requests
import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import os
import re

# Initialize colorama
init(autoreset=True)

# ===== CONFIGURATION =====
ML_MODEL_API = 'http://127.0.0.1:5050/predict'
INTERFACE = None  # None = all interfaces

# ===== STATISTICS =====
stats = {
    'total_scanned': 0,
    'http_requests': 0,
    'safe_count': 0,
    'suspicious_count': 0,
    'malicious_count': 0,
    'start_time': datetime.now()
}

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print beautiful banner"""
    banner = f"""
{Fore.CYAN}===============================================================================
                                                                            
          {Fore.GREEN}AI TRAFFIC ANALYZER - TRUE PASSIVE MONITORING{Fore.CYAN}          
                                                                            
     {Fore.YELLOW}Packet Sniffing with XGBoost ML Model - No Proxy Required{Fore.CYAN}     
     {Fore.YELLOW}Monitors all HTTP traffic automatically - Zero configuration{Fore.CYAN}   
                                                                            
==============================================================================={Style.RESET_ALL}

{Fore.WHITE}Configuration:{Style.RESET_ALL}
   Mode:         {Fore.GREEN}PACKET SNIFFING (Passive){Style.RESET_ALL}
   Interface:    {Fore.GREEN}All Network Interfaces{Style.RESET_ALL}
   ML Model API: {Fore.GREEN}{ML_MODEL_API}{Style.RESET_ALL}

{Fore.WHITE}Features:{Style.RESET_ALL}
   ✓ No proxy configuration needed
   ✓ No internet disruption
   ✓ Monitors all HTTP traffic automatically
   ✓ Real-time ML threat analysis
   ✓ Beautiful visualizations

{Fore.WHITE}Legend:{Style.RESET_ALL}
   {Fore.GREEN}[SAFE]{Style.RESET_ALL}        -> Low threat (MANAGED_CHALLENGE)
   {Fore.YELLOW}[SUSPICIOUS]{Style.RESET_ALL} -> Medium threat (CHALLENGE)
   {Fore.RED}[MALICIOUS]{Style.RESET_ALL}  -> High threat (BLOCK/JSCHALLENGE)

{Fore.CYAN}{'='*79}{Style.RESET_ALL}
{Fore.WHITE}Starting packet capture... (press Ctrl+C to stop){Style.RESET_ALL}
{Fore.CYAN}{'='*79}{Style.RESET_ALL}

"""
    print(banner)

def get_client_country(ip):
    """Get country from IP - with caching"""
    if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
        return 'LOCAL'
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
        if response.status_code == 200:
            return response.json().get('countryCode', 'US')
    except:
        pass
    return 'US'

def query_ml_model(request_data):
    """Query ML model and return prediction"""
    try:
        response = requests.post(ML_MODEL_API, json=request_data, timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        return None

def format_confidence(scores):
    """Format confidence scores with colors"""
    lines = []
    for action, percentage in scores.items():
        # Remove % sign and convert to float
        conf_value = float(percentage.replace('%', ''))
        
        # Color based on action type and confidence
        if action == 'MANAGED_CHALLENGE':
            color = Fore.GREEN
            symbol = '[SAFE]     '
        elif action == 'CHALLENGE':
            color = Fore.YELLOW
            symbol = '[SUSPIC]   '
        else:  # BLOCK or JSCHALLENGE
            color = Fore.RED
            symbol = '[MALICIOUS]'
        
        # Create bar chart
        bar_length = int(conf_value / 5)  # Scale: 5% = 1 char
        bar = '#' * bar_length
        
        lines.append(f"   {color}{symbol} {action:20} {percentage:>6}  {bar}{Style.RESET_ALL}")
    
    return '\n'.join(lines)

def get_threat_level(action, confidence_scores):
    """Determine overall threat level"""
    action_str = str(action).strip()
    
    if action_str in ['BLOCK', 'JSCHALLENGE']:
        return 'MALICIOUS', Fore.RED, '[X]', 'malicious_count'
    elif action_str == 'CHALLENGE':
        return 'SUSPICIOUS', Fore.YELLOW, '[!]', 'suspicious_count'
    else:  # MANAGED_CHALLENGE
        return 'SAFE', Fore.GREEN, '[OK]', 'safe_count'

def print_request_analysis(request_num, src_ip, dst_ip, method, path, host, user_agent, ml_result):
    """Print beautiful request analysis"""
    
    # Extract prediction details
    action = ml_result.get('predicted_action', 'UNKNOWN')
    code = ml_result.get('prediction_code', 0)
    confidence = ml_result.get('confidence_scores', {})
    
    # Determine threat level
    threat_level, color, symbol, stat_key = get_threat_level(action, confidence)
    stats[stat_key] += 1
    
    # Get highest confidence
    max_conf = max(confidence.values(), key=lambda x: float(x.replace('%', ''))) if confidence else '0%'
    
    # Print separator
    print(f"\n{Fore.CYAN}{'-'*79}{Style.RESET_ALL}")
    
    # Print header with threat level
    print(f"\n{Fore.WHITE}[HTTP REQUEST #{request_num:04d}] {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}")
    print(f"{color}{symbol} THREAT LEVEL: {threat_level} (Confidence: {max_conf}){Style.RESET_ALL}")
    
    # Print request details
    print(f"\n{Fore.WHITE}>> Packet Details:{Style.RESET_ALL}")
    print(f"   Method:      {Fore.CYAN}{method}{Style.RESET_ALL}")
    print(f"   Host:        {Fore.CYAN}{host}{Style.RESET_ALL}")
    print(f"   Path:        {Fore.CYAN}{path[:60]}{Style.RESET_ALL}{'...' if len(path) > 60 else ''}")
    print(f"   Source IP:   {Fore.CYAN}{src_ip}{Style.RESET_ALL}")
    print(f"   Dest IP:     {Fore.CYAN}{dst_ip}{Style.RESET_ALL}")
    if user_agent:
        print(f"   User-Agent:  {Fore.CYAN}{user_agent[:50]}{Style.RESET_ALL}{'...' if len(user_agent) > 50 else ''}")
    
    # Print ML prediction
    print(f"\n{Fore.WHITE}>> AI Model Prediction:{Style.RESET_ALL}")
    print(f"   Action:      {color}{action}{Style.RESET_ALL}")
    print(f"   Code:        {Fore.CYAN}{code}{Style.RESET_ALL}")
    
    # Print confidence scores with visualization
    print(f"\n{Fore.WHITE}>> Confidence Distribution:{Style.RESET_ALL}")
    print(format_confidence(confidence))
    
    # Print decision
    print(f"\n{Fore.WHITE}>> Decision:{Style.RESET_ALL}")
    if threat_level == 'MALICIOUS':
        print(f"   {Fore.RED}⚠ MALICIOUS request detected! Would be BLOCKED in active mode.{Style.RESET_ALL}")
    elif threat_level == 'SUSPICIOUS':
        print(f"   {Fore.YELLOW}⚠ SUSPICIOUS request detected! Would show CHALLENGE in active mode.{Style.RESET_ALL}")
    else:
        print(f"   {Fore.GREEN}✓ SAFE - No threat detected{Style.RESET_ALL}")

def print_statistics():
    """Print running statistics"""
    total = stats['http_requests']
    if total == 0:
        return
    
    safe_pct = (stats['safe_count'] / total) * 100
    susp_pct = (stats['suspicious_count'] / total) * 100
    mal_pct = (stats['malicious_count'] / total) * 100
    
    uptime = datetime.now() - stats['start_time']
    
    print(f"\n{Fore.CYAN}{'-'*79}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}[SESSION STATISTICS]{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*79}{Style.RESET_ALL}")
    print(f"   {Fore.WHITE}Total Packets:    {Fore.CYAN}{stats['total_scanned']:,}{Style.RESET_ALL}")
    print(f"   {Fore.WHITE}HTTP Requests:    {Fore.CYAN}{stats['http_requests']:,}{Style.RESET_ALL}")
    print(f"   {Fore.GREEN}[OK] Safe:        {stats['safe_count']:,} ({safe_pct:.1f}%){Style.RESET_ALL}")
    print(f"   {Fore.YELLOW}[!] Suspicious:   {stats['suspicious_count']:,} ({susp_pct:.1f}%){Style.RESET_ALL}")
    print(f"   {Fore.RED}[X] Malicious:    {stats['malicious_count']:,} ({mal_pct:.1f}%){Style.RESET_ALL}")
    print(f"   {Fore.WHITE}Session Uptime:   {Fore.CYAN}{str(uptime).split('.')[0]}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*79}{Style.RESET_ALL}")

def extract_http_info(packet):
    """Extract HTTP request info from packet"""
    try:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Check if it's an HTTP request
            if not any(payload.startswith(method) for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']):
                return None
            
            lines = payload.split('\r\n')
            if not lines:
                return None
            
            # Parse request line
            request_line = lines[0].split(' ')
            if len(request_line) < 3:
                return None
            
            method = request_line[0]
            path = request_line[1]
            
            # Extract headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            host = headers.get('Host', 'unknown')
            user_agent = headers.get('User-Agent', 'Unknown')
            
            return {
                'method': method,
                'path': path,
                'host': host,
                'user_agent': user_agent,
                'full_url': f"http://{host}{path}"
            }
    except:
        pass
    
    return None

def packet_handler(packet):
    """Handle each captured packet"""
    stats['total_scanned'] += 1
    
    # Filter for TCP packets with data
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return
    
    # Extract HTTP info
    http_info = extract_http_info(packet)
    if not http_info:
        return
    
    stats['http_requests'] += 1
    
    # Get IPs
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # Get country for source IP
    country = get_client_country(src_ip)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Prepare ML request
    ml_request_data = {
        "IP": src_ip,
        "Endpoint": http_info['path'],
        "User-Agent": http_info['user_agent'],
        "Country": country,
        "Date": current_time
    }
    
    # Query ML model
    ml_result = query_ml_model(ml_request_data)
    
    if ml_result:
        # Print analysis
        print_request_analysis(
            request_num=stats['http_requests'],
            src_ip=src_ip,
            dst_ip=dst_ip,
            method=http_info['method'],
            path=http_info['path'],
            host=http_info['host'],
            user_agent=http_info['user_agent'],
            ml_result=ml_result
        )
        
        # Print statistics every 10 requests
        if stats['http_requests'] % 10 == 0:
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
    
    # Check ML API
    try:
        requests.get('http://127.0.0.1:5050/', timeout=5)
        print(f"{Fore.GREEN}[OK] ML Model API is online{Style.RESET_ALL}\n")
    except:
        print(f"{Fore.RED}[X] Cannot reach ML Model API!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Please start it first: python app.py{Style.RESET_ALL}\n")
        return
    
    # Start sniffing
    try:
        print(f"{Fore.GREEN}[SNIFFING] Capturing packets on all interfaces...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[INFO] Browse any website - HTTP traffic will be analyzed below{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}Note: Only HTTP traffic is analyzed (not HTTPS){Style.RESET_ALL}\n")
        
        # Sniff packets
        sniff(
            filter="tcp port 80",  # Capture HTTP traffic
            prn=packet_handler,
            store=0,  # Don't store packets in memory
            iface=INTERFACE
        )
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[STOP] Stopping Traffic Analyzer...{Style.RESET_ALL}\n")
        print_statistics()
        print(f"\n{Fore.GREEN}[OK] Analysis session ended{Style.RESET_ALL}\n")
    except PermissionError:
        print(f"{Fore.RED}[X] Permission denied! Run as Administrator{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.RED}[X] Error: {e}{Style.RESET_ALL}\n")

if __name__ == '__main__':
    main()
