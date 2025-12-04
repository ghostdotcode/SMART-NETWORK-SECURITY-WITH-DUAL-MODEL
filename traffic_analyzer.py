"""
AI TRAFFIC ANALYZER - Passive Monitoring Mode
Scans all network traffic and displays AI predictions in real-time
WITHOUT blocking anything - pure analysis and visualization
"""

import http.server
import socketserver
import urllib.request
import requests
import json
import logging
from datetime import datetime
from urllib.parse import urlparse
import time
from colorama import init, Fore, Back, Style
import os

# Initialize colorama for Windows color support
init(autoreset=True)

# ===== CONFIGURATION =====
PROXY_HOST = '0.0.0.0'
PROXY_PORT = 8080
ML_MODEL_API = 'http://127.0.0.1:5050/predict'

# ===== STATISTICS =====
stats = {
    'total_scanned': 0,
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
                                                                           
          {Fore.GREEN}AI TRAFFIC ANALYZER - PASSIVE MONITORING MODE{Fore.CYAN}          
                                                                           
     {Fore.YELLOW}Scanning all network traffic with XGBoost ML Model{Fore.CYAN}              
     {Fore.YELLOW}Real-time threat detection - Zero blocking - Pure analysis{Fore.CYAN}      
                                                                           
==============================================================================={Style.RESET_ALL}

{Fore.WHITE}Configuration:{Style.RESET_ALL}
   Proxy Address: {Fore.GREEN}{PROXY_HOST}:{PROXY_PORT}{Style.RESET_ALL}
   ML Model API:  {Fore.GREEN}{ML_MODEL_API}{Style.RESET_ALL}
   Mode:          {Fore.YELLOW}PASSIVE SCAN (No Blocking){Style.RESET_ALL}

{Fore.WHITE}Usage:{Style.RESET_ALL}
   Configure your browser to use: {Fore.CYAN}localhost:{PROXY_PORT}{Style.RESET_ALL}
   Browse normally - every request will be analyzed and displayed below

{Fore.WHITE}Legend:{Style.RESET_ALL}
   {Fore.GREEN}[SAFE]{Style.RESET_ALL}        -> Low threat (MANAGED_CHALLENGE)
   {Fore.YELLOW}[SUSPICIOUS]{Style.RESET_ALL} -> Medium threat (CHALLENGE)
   {Fore.RED}[MALICIOUS]{Style.RESET_ALL}  -> High threat (BLOCK/JSCHALLENGE)

{Fore.CYAN}{'='*79}{Style.RESET_ALL}
{Fore.WHITE}Starting real-time traffic analysis...{Style.RESET_ALL}
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

def print_request_analysis(request_num, client_ip, method, path, user_agent, country, ml_result):
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
    print(f"\n{Fore.WHITE}[REQUEST #{request_num:04d}] {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}")
    print(f"{color}{symbol} THREAT LEVEL: {threat_level} (Confidence: {max_conf}){Style.RESET_ALL}")
    
    # Print request details
    print(f"\n{Fore.WHITE}>> Request Details:{Style.RESET_ALL}")
    print(f"   Method:      {Fore.CYAN}{method}{Style.RESET_ALL}")
    print(f"   URL:         {Fore.CYAN}{path[:70]}{Style.RESET_ALL}{'...' if len(path) > 70 else ''}")
    print(f"   Source IP:   {Fore.CYAN}{client_ip}{Style.RESET_ALL}")
    print(f"   Country:     {Fore.CYAN}{country}{Style.RESET_ALL}")
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
        print(f"   {Fore.RED}[MALICIOUS] Would be BLOCKED in active mode (403 Forbidden){Style.RESET_ALL}")
    elif threat_level == 'SUSPICIOUS':
        print(f"   {Fore.YELLOW}[SUSPICIOUS] Would show CHALLENGE in active mode (429){Style.RESET_ALL}")
    else:
        print(f"   {Fore.GREEN}[SAFE] Traffic ALLOWED - No threat detected{Style.RESET_ALL}")
    
    # Print features extracted
    print(f"\n{Fore.WHITE}>> Features Analyzed:{Style.RESET_ALL}")
    print(f"   {Fore.CYAN}[+] IP characteristics (IPv6, length, private range)")
    print(f"   [+] Endpoint analysis (length, depth, query params, extensions)")
    print(f"   [+] User-Agent fingerprinting (browser, OS, automation)")
    print(f"   [+] Geographic risk scoring")
    print(f"   [+] Temporal patterns (hour, day, weekend)")
    print(f"   [+] Behavioral analysis (35+ features total){Style.RESET_ALL}")

def print_statistics():
    """Print running statistics"""
    total = stats['total_scanned']
    if total == 0:
        return
    
    safe_pct = (stats['safe_count'] / total) * 100
    susp_pct = (stats['suspicious_count'] / total) * 100
    mal_pct = (stats['malicious_count'] / total) * 100
    
    uptime = datetime.now() - stats['start_time']
    
    print(f"\n{Fore.CYAN}{'-'*79}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}[SESSION STATISTICS]{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*79}{Style.RESET_ALL}")
    print(f"   {Fore.WHITE}Total Scanned:    {Fore.CYAN}{total:,}{Style.RESET_ALL}")
    print(f"   {Fore.GREEN}[OK] Safe:        {stats['safe_count']:,} ({safe_pct:.1f}%){Style.RESET_ALL}")
    print(f"   {Fore.YELLOW}[!] Suspicious:   {stats['suspicious_count']:,} ({susp_pct:.1f}%){Style.RESET_ALL}")
    print(f"   {Fore.RED}[X] Malicious:    {stats['malicious_count']:,} ({mal_pct:.1f}%){Style.RESET_ALL}")
    print(f"   {Fore.WHITE}Session Uptime:   {Fore.CYAN}{str(uptime).split('.')[0]}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*79}{Style.RESET_ALL}")

class TrafficAnalyzerHandler(http.server.BaseHTTPRequestHandler):
    """HTTP proxy handler that analyzes but doesn't block"""
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass
    
    def do_GET(self):
        self.handle_request('GET')
    
    def do_POST(self):
        self.handle_request('POST')
    
    def do_HEAD(self):
        self.handle_request('HEAD')
    
    def do_PUT(self):
        self.handle_request('PUT')
    
    def do_DELETE(self):
        self.handle_request('DELETE')
    
    def do_CONNECT(self):
        """Handle CONNECT method for HTTPS tunneling"""
        # For HTTPS, we need to establish a tunnel
        # But for simplicity, just forward without deep inspection
        try:
            # Extract host and port
            host_port = self.path.split(':')
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
            
            # Log the HTTPS request (can't inspect encrypted content)
            stats['total_scanned'] += 1
            client_ip = self.client_address[0]
            
            print(f"\n{Fore.CYAN}{'-'*79}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}[REQUEST #{stats['total_scanned']:04d}] {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[HTTPS TUNNEL] Cannot analyze encrypted traffic{Style.RESET_ALL}")
            print(f"   Destination: {Fore.CYAN}{host}:{port}{Style.RESET_ALL}")
            print(f"   Source IP:   {Fore.CYAN}{client_ip}{Style.RESET_ALL}")
            print(f"   {Fore.YELLOW}Note: HTTPS traffic is encrypted, skipping ML analysis{Style.RESET_ALL}")
            
            # Create connection to destination
            import socket
            dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dest_socket.connect((host, port))
            
            # Send success response to client
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            # Now just tunnel the data bidirectionally
            self.connection.setblocking(0)
            dest_socket.setblocking(0)
            
            import select
            sockets = [self.connection, dest_socket]
            timeout = 60
            
            while True:
                readable, _, _ = select.select(sockets, [], [], timeout)
                if not readable:
                    break
                    
                for sock in readable:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            return
                            
                        if sock is self.connection:
                            dest_socket.sendall(data)
                        else:
                            self.connection.sendall(data)
                    except:
                        return
                        
        except Exception as e:
            print(f"{Fore.RED}[ERROR] HTTPS tunnel failed: {e}{Style.RESET_ALL}")
            try:
                self.send_error(502, f"Tunnel error: {str(e)}")
            except:
                pass
    
    def handle_request(self, method):
        """Main handler - analyze and forward (no blocking)"""
        stats['total_scanned'] += 1
        
        # Extract request info
        client_ip = self.client_address[0]
        path = self.path
        user_agent = self.headers.get('User-Agent', 'Unknown')
        
        # Get country (with timeout protection)
        country = get_client_country(client_ip)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Prepare ML request
        ml_request_data = {
            "IP": client_ip,
            "Endpoint": path,
            "User-Agent": user_agent,
            "Country": country,
            "Date": current_time
        }
        
        # Query ML model
        ml_result = query_ml_model(ml_request_data)
        
        if ml_result:
            # Print analysis
            print_request_analysis(
                request_num=stats['total_scanned'],
                client_ip=client_ip,
                method=method,
                path=path,
                user_agent=user_agent,
                country=country,
                ml_result=ml_result
            )
            
            # Print statistics every 10 requests
            if stats['total_scanned'] % 10 == 0:
                print_statistics()
        
        # ALWAYS FORWARD - NO BLOCKING IN THIS MODE
        self.forward_request(method)
    
    def forward_request(self, method):
        """Forward request to destination (always allow)"""
        try:
            # Parse URL
            parsed_url = urlparse(self.path)
            
            if parsed_url.scheme:
                target_url = self.path
            else:
                target_host = self.headers.get('Host', 'localhost:5050')
                target_url = f"http://{target_host}{self.path}"
            
            # Prepare headers
            headers = dict(self.headers)
            headers.pop('Proxy-Connection', None)
            
            # Get body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None
            
            # Forward
            response = requests.request(
                method=method,
                url=target_url,
                headers=headers,
                data=body,
                allow_redirects=False,
                timeout=30
            )
            
            # Send response
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                if header.lower() not in ['transfer-encoding', 'connection']:
                    self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.content)
            
        except Exception as e:
            self.send_error(502, f"Error: {str(e)}")

def main():
    """Main entry point"""
    clear_screen()
    print_banner()
    
    # Check ML API
    try:
        requests.get('http://127.0.0.1:5050/', timeout=5)
        print(f"{Fore.GREEN}[OK] ML Model API is online{Style.RESET_ALL}\n")
    except:
        print(f"{Fore.RED}[X] Cannot reach ML Model API!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Please start it first: python app.py{Style.RESET_ALL}\n")
        return
    
    # Start server
    try:
        with socketserver.ThreadingTCPServer((PROXY_HOST, PROXY_PORT), TrafficAnalyzerHandler) as httpd:
            print(f"{Fore.GREEN}[READY] Traffic Analyzer is ACTIVE on {PROXY_HOST}:{PROXY_PORT}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[INFO] Waiting for traffic... (browse any website){Style.RESET_ALL}\n")
            
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print(f"\n\n{Fore.YELLOW}[STOP] Stopping Traffic Analyzer...{Style.RESET_ALL}\n")
                print_statistics()
                print(f"\n{Fore.GREEN}[OK] Analysis session ended{Style.RESET_ALL}\n")
    
    except OSError as e:
        if 'Address already in use' in str(e):
            print(f"{Fore.RED}[X] Port {PROXY_PORT} is already in use!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}  Stop ai_firewall_proxy.py first, or change PROXY_PORT{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}[X] Error: {e}{Style.RESET_ALL}\n")

if __name__ == '__main__':
    main()
