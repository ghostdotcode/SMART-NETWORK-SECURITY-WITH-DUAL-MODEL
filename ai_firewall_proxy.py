"""
AI FIREWALL PROXY - Smart HTTP/HTTPS Interceptor
Integrates with XGBoost ML model to block malicious traffic in real-time
"""

import http.server
import socketserver
import urllib.request
import urllib.parse
import urllib.error
import requests
import json
import logging
from datetime import datetime
from urllib.parse import urlparse
import socket
import ssl
import threading
from collections import defaultdict
import time

# ===== CONFIGURATION =====
PROXY_HOST = '0.0.0.0'  # Listen on all interfaces
PROXY_PORT = 8080        # Proxy port
ML_MODEL_API = 'http://127.0.0.1:5050/predict'  # Your Flask API
LOG_FILE = 'firewall.log'
BLOCKED_LOG_FILE = 'blocked_requests.log'

# Action mappings from your model
BLOCKED_ACTIONS = ['BLOCK', 'JSCHALLENGE']  # Actions that should block traffic
CHALLENGED_ACTIONS = ['CHALLENGE']           # Actions that get captcha/challenge
ALLOWED_ACTIONS = ['MANAGED_CHALLENGE']      # Actions that pass through with monitoring

# Whitelist - these IPs always pass
WHITELIST_IPS = ['127.0.0.1', '::1', 'localhost']

# Rate limiting
RATE_LIMIT = 100  # Max requests per IP per minute
rate_tracker = defaultdict(list)

# ===== LOGGING SETUP =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('AIFirewall')

# Separate logger for blocked requests
blocked_logger = logging.getLogger('BlockedRequests')
blocked_handler = logging.FileHandler(BLOCKED_LOG_FILE)
blocked_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
blocked_logger.addHandler(blocked_handler)
blocked_logger.setLevel(logging.INFO)

# ===== STATISTICS TRACKER =====
stats = {
    'total_requests': 0,
    'blocked_requests': 0,
    'allowed_requests': 0,
    'challenged_requests': 0,
    'ml_api_errors': 0
}

def get_client_country(ip):
    """
    Get country code from IP address.
    In production, use MaxMind GeoIP2 or similar service.
    For now, using a simple API (with fallback).
    """
    if ip in WHITELIST_IPS or ip.startswith('192.168.') or ip.startswith('10.'):
        return 'US'  # Default for local IPs
    
    try:
        # Free IP geolocation API (limited requests)
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get('countryCode', 'US')
    except Exception as e:
        logger.warning(f"GeoIP lookup failed for {ip}: {e}")
    
    return 'US'  # Default fallback

def check_rate_limit(ip):
    """
    Check if IP has exceeded rate limit.
    Returns True if rate limit exceeded.
    """
    current_time = time.time()
    
    # Clean old entries (older than 60 seconds)
    rate_tracker[ip] = [t for t in rate_tracker[ip] if current_time - t < 60]
    
    # Check if exceeded limit
    if len(rate_tracker[ip]) >= RATE_LIMIT:
        return True
    
    # Add current request
    rate_tracker[ip].append(current_time)
    return False

def query_ml_model(request_data):
    """
    Query the XGBoost ML model API for threat prediction.
    Returns: (action, confidence_scores, prediction_code)
    """
    try:
        logger.debug(f"Querying ML model with: {request_data}")
        
        response = requests.post(
            ML_MODEL_API,
            json=request_data,
            timeout=5
        )
        
        if response.status_code == 200:
            result = response.json()
            action = result.get('predicted_action', 'MANAGED_CHALLENGE')
            confidence = result.get('confidence_scores', {})
            code = result.get('prediction_code', 0)
            
            logger.info(f"ML Prediction: {action} (code: {code})")
            return action, confidence, code
        else:
            logger.error(f"ML API returned status {response.status_code}")
            stats['ml_api_errors'] += 1
            return 'MANAGED_CHALLENGE', {}, 0  # Default to allow on API error
            
    except Exception as e:
        logger.error(f"Error querying ML model: {e}")
        stats['ml_api_errors'] += 1
        return 'MANAGED_CHALLENGE', {}, 0  # Default to allow on error

class AIFirewallProxyHandler(http.server.BaseHTTPRequestHandler):
    """
    Custom HTTP proxy handler that intercepts requests,
    analyzes them with ML model, and blocks malicious traffic.
    """
    
    def log_message(self, format, *args):
        """Override to use our custom logger"""
        logger.info(f"{self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests"""
        self.handle_request('GET')
    
    def do_POST(self):
        """Handle POST requests"""
        self.handle_request('POST')
    
    def do_HEAD(self):
        """Handle HEAD requests"""
        self.handle_request('HEAD')
    
    def do_PUT(self):
        """Handle PUT requests"""
        self.handle_request('PUT')
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        self.handle_request('DELETE')
    
    def handle_request(self, method):
        """
        Main request handler - intercepts, analyzes, and forwards/blocks
        """
        stats['total_requests'] += 1
        
        # Extract request information
        client_ip = self.client_address[0]
        path = self.path
        user_agent = self.headers.get('User-Agent', 'Unknown')
        
        logger.info(f"\n{'='*60}")
        logger.info(f"New {method} request from {client_ip}")
        logger.info(f"Path: {path}")
        logger.info(f"User-Agent: {user_agent}")
        
        # Check whitelist
        if client_ip in WHITELIST_IPS:
            logger.info(f"✓ IP {client_ip} is whitelisted - ALLOWING")
            return self.forward_request(method)
        
        # Check rate limit
        if check_rate_limit(client_ip):
            logger.warning(f"✗ Rate limit exceeded for {client_ip} - BLOCKING")
            stats['blocked_requests'] += 1
            return self.send_blocked_response("Rate limit exceeded")
        
        # Prepare data for ML model
        country = get_client_country(client_ip)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        ml_request_data = {
            "IP": client_ip,
            "Endpoint": path,
            "User-Agent": user_agent,
            "Country": country,
            "Date": current_time
        }
        
        # Query ML model
        action, confidence, code = query_ml_model(ml_request_data)
        
        # Make decision based on ML prediction
        if action in BLOCKED_ACTIONS:
            logger.warning(f"✗ BLOCKING request - Action: {action}")
            logger.warning(f"  Confidence: {confidence}")
            
            # Log blocked request details
            blocked_logger.info(json.dumps({
                'ip': client_ip,
                'path': path,
                'user_agent': user_agent,
                'country': country,
                'action': action,
                'confidence': confidence,
                'timestamp': current_time
            }))
            
            stats['blocked_requests'] += 1
            return self.send_blocked_response(f"Access Denied - Threat Level: {action}")
        
        elif action in CHALLENGED_ACTIONS:
            logger.info(f"⚠ CHALLENGING request - Action: {action}")
            stats['challenged_requests'] += 1
            return self.send_challenge_response()
        
        else:
            logger.info(f"✓ ALLOWING request - Action: {action}")
            logger.info(f"  Confidence: {confidence}")
            stats['allowed_requests'] += 1
            return self.forward_request(method)
    
    def forward_request(self, method):
        """
        Forward the request to the actual destination server.
        """
        try:
            # Parse the target URL
            parsed_url = urlparse(self.path)
            
            # Check if it's a full URL or just a path
            if parsed_url.scheme:
                target_url = self.path
            else:
                # For relative paths, we need a default target
                # In production, configure this based on your backend
                target_host = self.headers.get('Host', 'localhost:5050')
                target_url = f"http://{target_host}{self.path}"
            
            logger.debug(f"Forwarding to: {target_url}")
            
            # Prepare headers (remove proxy-specific headers)
            headers = dict(self.headers)
            headers.pop('Proxy-Connection', None)
            
            # Get request body for POST/PUT
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None
            
            # Forward the request
            response = requests.request(
                method=method,
                url=target_url,
                headers=headers,
                data=body,
                allow_redirects=False,
                timeout=30
            )
            
            # Send response back to client
            self.send_response(response.status_code)
            
            # Forward response headers
            for header, value in response.headers.items():
                if header.lower() not in ['transfer-encoding', 'connection']:
                    self.send_header(header, value)
            self.end_headers()
            
            # Forward response body
            self.wfile.write(response.content)
            
            logger.info(f"✓ Request forwarded successfully - Status: {response.status_code}")
            
        except Exception as e:
            logger.error(f"Error forwarding request: {e}")
            self.send_error(502, f"Bad Gateway: {str(e)}")
    
    def send_blocked_response(self, reason="Access Denied"):
        """
        Send a 403 Forbidden response for blocked requests.
        """
        self.send_response(403)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html_response = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Denied - AI Firewall</title>
            <style>
                body {{
                    background: linear-gradient(135deg, #0a0a1a 0%, #1a0a0a 100%);
                    color: #ff3333;
                    font-family: 'Courier New', monospace;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }}
                .container {{
                    text-align: center;
                    padding: 40px;
                    border: 2px solid #ff3333;
                    border-radius: 10px;
                    background: rgba(0,0,0,0.8);
                    box-shadow: 0 0 30px #ff3333;
                }}
                h1 {{ font-size: 48px; margin: 0; text-shadow: 0 0 20px #ff3333; }}
                p {{ font-size: 20px; margin: 20px 0; }}
                .code {{ color: #00ff00; font-family: monospace; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ ACCESS DENIED</h1>
                <p>Your request has been <strong>blocked</strong> by our AI Firewall</p>
                <p class="code">Reason: {reason}</p>
                <p class="code">IP: {self.client_address[0]}</p>
                <p style="font-size:14px; color:#888;">If you believe this is an error, contact the administrator.</p>
            </div>
        </body>
        </html>
        """
        
        self.wfile.write(html_response.encode('utf-8'))
    
    def send_challenge_response(self):
        """
        Send a 429 challenge response (could be CAPTCHA in production).
        """
        self.send_response(429)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Retry-After', '60')
        self.end_headers()
        
        html_response = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Verification Required - AI Firewall</title>
            <style>
                body {
                    background: linear-gradient(135deg, #0a0a1a 0%, #1a1a0a 100%);
                    color: #ffaa00;
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .container {
                    text-align: center;
                    padding: 40px;
                    border: 2px solid #ffaa00;
                    border-radius: 10px;
                    background: rgba(0,0,0,0.8);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>⚠️ VERIFICATION REQUIRED</h1>
                <p>Please verify you are human to continue</p>
                <p><small>In production, this would show a CAPTCHA</small></p>
            </div>
        </body>
        </html>
        """
        
        self.wfile.write(html_response.encode('utf-8'))

def print_banner():
    """Print startup banner"""
    banner = f"""
    {'='*70}
    
         █████╗ ██╗    ███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗     
        ██╔══██╗██║    ██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║     
        ███████║██║    █████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║     
        ██╔══██║██║    ██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║     
        ██║  ██║██║    ██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗
        ╚═╝  ╚═╝╚═╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
                                                                                      
                            AI-Powered Traffic Interceptor
                            Powered by XGBoost ML Model
    
    {'='*70}
    
    🔧 Configuration:
       Proxy Address: {PROXY_HOST}:{PROXY_PORT}
       ML Model API:  {ML_MODEL_API}
       Log File:      {LOG_FILE}
    
    🛡️  Protection Status: ACTIVE
    
    💡 Usage:
       Configure your browser/application to use this proxy:
       HTTP Proxy: localhost:{PROXY_PORT}
    
    📊 Press Ctrl+C to view statistics and stop
    
    {'='*70}
    """
    print(banner)

def print_statistics():
    """Print current statistics"""
    print(f"\n{'='*70}")
    print("📊 AI FIREWALL STATISTICS")
    print(f"{'='*70}")
    print(f"Total Requests:      {stats['total_requests']:,}")
    print(f"✓ Allowed:           {stats['allowed_requests']:,}")
    print(f"✗ Blocked:           {stats['blocked_requests']:,}")
    print(f"⚠ Challenged:        {stats['challenged_requests']:,}")
    print(f"⚡ ML API Errors:     {stats['ml_api_errors']:,}")
    
    if stats['total_requests'] > 0:
        block_rate = (stats['blocked_requests'] / stats['total_requests']) * 100
        print(f"\n🎯 Block Rate:        {block_rate:.2f}%")
    
    print(f"{'='*70}\n")

def main():
    """Main entry point"""
    print_banner()
    
    # Check if ML model API is accessible
    try:
        test_response = requests.get('http://127.0.0.1:5050/', timeout=5)
        logger.info("✓ ML Model API is accessible")
    except Exception as e:
        logger.error("✗ Cannot reach ML Model API! Make sure app.py is running.")
        logger.error(f"  Error: {e}")
        print("\n⚠️  WARNING: ML Model API is not running!")
        print("   Please start it first: python app.py")
        print("   Then restart this proxy.\n")
        return
    
    # Create proxy server
    try:
        with socketserver.ThreadingTCPServer((PROXY_HOST, PROXY_PORT), AIFirewallProxyHandler) as httpd:
            logger.info(f"🚀 AI Firewall Proxy is running on {PROXY_HOST}:{PROXY_PORT}")
            logger.info("🛡️  All traffic will be analyzed by XGBoost ML model")
            logger.info("Press Ctrl+C to stop\n")
            
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                logger.info("\n\n🛑 Shutting down AI Firewall...")
                print_statistics()
                logger.info("✓ Proxy stopped successfully")
    
    except OSError as e:
        if 'Address already in use' in str(e):
            logger.error(f"✗ Port {PROXY_PORT} is already in use!")
            logger.error("  Either stop the other process or change PROXY_PORT in this script")
        else:
            logger.error(f"✗ Error starting proxy: {e}")

if __name__ == '__main__':
    main()
