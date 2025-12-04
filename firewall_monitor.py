"""
AI FIREWALL MONITORING DASHBOARD
Real-time monitoring and statistics for the AI Firewall
"""

import json
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
import os

class FirewallMonitor:
    """
    Real-time monitoring and statistics tracking for AI Firewall
    """
    
    def __init__(self, log_file='firewall.log', blocked_log='blocked_requests.log'):
        self.log_file = log_file
        self.blocked_log = blocked_log
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'blocked': 0,
            'allowed': 0,
            'challenged': 0,
            'start_time': datetime.now(),
            'uptime': 0
        }
        
        # IP tracking
        self.ip_stats = defaultdict(lambda: {
            'total': 0,
            'blocked': 0,
            'allowed': 0
        })
        
        # Time-series data (last 100 requests)
        self.recent_requests = deque(maxlen=100)
        
        # Blocked IPs and reasons
        self.blocked_ips = defaultdict(list)
        
        # Attack patterns
        self.attack_patterns = defaultdict(int)
    
    def parse_logs(self):
        """
        Parse firewall logs and extract statistics
        """
        if not os.path.exists(self.log_file):
            return
        
        with open(self.log_file, 'r') as f:
            for line in f:
                if 'ALLOWING request' in line:
                    self.stats['allowed'] += 1
                elif 'BLOCKING request' in line:
                    self.stats['blocked'] += 1
                elif 'CHALLENGING request' in line:
                    self.stats['challenged'] += 1
        
        self.stats['total_requests'] = (
            self.stats['allowed'] + 
            self.stats['blocked'] + 
            self.stats['challenged']
        )
    
    def parse_blocked_log(self):
        """
        Parse blocked requests log for detailed analysis
        """
        if not os.path.exists(self.blocked_log):
            return
        
        with open(self.blocked_log, 'r') as f:
            for line in f:
                try:
                    # Each line is a JSON object
                    parts = line.split(' - ', 1)
                    if len(parts) == 2:
                        data = json.loads(parts[1])
                        
                        ip = data.get('ip', 'unknown')
                        endpoint = data.get('path', '')
                        action = data.get('action', '')
                        
                        self.blocked_ips[ip].append({
                            'endpoint': endpoint,
                            'action': action,
                            'timestamp': data.get('timestamp')
                        })
                        
                        # Track attack patterns
                        if 'admin' in endpoint.lower():
                            self.attack_patterns['admin_probing'] += 1
                        if '.env' in endpoint:
                            self.attack_patterns['env_file_access'] += 1
                        if 'wp-' in endpoint:
                            self.attack_patterns['wordpress_scan'] += 1
                        if 'sql' in endpoint.lower():
                            self.attack_patterns['sql_injection'] += 1
                
                except json.JSONDecodeError:
                    continue
    
    def get_top_blocked_ips(self, n=10):
        """
        Get top N most blocked IPs
        """
        sorted_ips = sorted(
            self.blocked_ips.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )
        return sorted_ips[:n]
    
    def get_blocking_rate(self):
        """
        Calculate blocking rate percentage
        """
        if self.stats['total_requests'] == 0:
            return 0.0
        return (self.stats['blocked'] / self.stats['total_requests']) * 100
    
    def print_dashboard(self):
        """
        Print a beautiful dashboard to console
        """
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Update stats
        self.parse_logs()
        self.parse_blocked_log()
        
        uptime = datetime.now() - self.stats['start_time']
        
        print("=" * 80)
        print(" " * 20 + "🛡️  AI FIREWALL MONITORING DASHBOARD 🛡️")
        print("=" * 80)
        print()
        
        # Status
        print(f"📊 STATUS")
        print(f"   Uptime:          {str(uptime).split('.')[0]}")
        print(f"   Current Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Request Statistics
        print(f"📈 REQUEST STATISTICS")
        print(f"   Total Requests:  {self.stats['total_requests']:,}")
        print(f"   ✓ Allowed:       {self.stats['allowed']:,}  ({self.stats['allowed']/max(self.stats['total_requests'],1)*100:.1f}%)")
        print(f"   ✗ Blocked:       {self.stats['blocked']:,}  ({self.stats['blocked']/max(self.stats['total_requests'],1)*100:.1f}%)")
        print(f"   ⚠ Challenged:    {self.stats['challenged']:,}  ({self.stats['challenged']/max(self.stats['total_requests'],1)*100:.1f}%)")
        print()
        
        # Blocking Rate
        blocking_rate = self.get_blocking_rate()
        if blocking_rate > 30:
            status_emoji = "🚨 HIGH"
        elif blocking_rate > 10:
            status_emoji = "⚠️  MODERATE"
        else:
            status_emoji = "✓ LOW"
        
        print(f"🎯 THREAT LEVEL:    {status_emoji} ({blocking_rate:.2f}% blocked)")
        print()
        
        # Top Blocked IPs
        top_blocked = self.get_top_blocked_ips(5)
        if top_blocked:
            print(f"🔥 TOP BLOCKED IPs")
            for ip, blocks in top_blocked:
                print(f"   {ip:<20} {len(blocks):>4} blocks")
            print()
        
        # Attack Patterns
        if self.attack_patterns:
            print(f"🎭 ATTACK PATTERNS DETECTED")
            for pattern, count in sorted(self.attack_patterns.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"   {pattern:<25} {count:>4} attempts")
            print()
        
        print("=" * 80)
        print("Press Ctrl+C to stop monitoring...")
        print("=" * 80)
    
    def monitor_realtime(self, refresh_interval=5):
        """
        Continuously monitor and update dashboard
        """
        try:
            while True:
                self.print_dashboard()
                time.sleep(refresh_interval)
        except KeyboardInterrupt:
            print("\n\n✓ Monitoring stopped")
            self.print_final_report()
    
    def print_final_report(self):
        """
        Print final summary report
        """
        print("\n" + "=" * 80)
        print(" " * 25 + "📋 FINAL REPORT")
        print("=" * 80)
        print()
        
        total_time = datetime.now() - self.stats['start_time']
        
        print(f"Session Duration:    {str(total_time).split('.')[0]}")
        print(f"Total Requests:      {self.stats['total_requests']:,}")
        print(f"Requests/Hour:       {(self.stats['total_requests'] / max(total_time.total_seconds()/3600, 1)):.1f}")
        print()
        
        print(f"✓ Allowed:           {self.stats['allowed']:,}")
        print(f"✗ Blocked:           {self.stats['blocked']:,}")
        print(f"⚠ Challenged:        {self.stats['challenged']:,}")
        print()
        
        print(f"Blocking Rate:       {self.get_blocking_rate():.2f}%")
        print(f"Unique IPs Blocked:  {len(self.blocked_ips)}")
        print()
        
        # Save report to file
        report_file = f"firewall_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write(f"AI Firewall Report\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"=" * 50 + "\n\n")
            f.write(f"Total Requests: {self.stats['total_requests']}\n")
            f.write(f"Blocked: {self.stats['blocked']}\n")
            f.write(f"Allowed: {self.stats['allowed']}\n")
            f.write(f"Challenged: {self.stats['challenged']}\n\n")
            
            f.write("Top Blocked IPs:\n")
            for ip, blocks in self.get_top_blocked_ips(20):
                f.write(f"  {ip}: {len(blocks)} blocks\n")
        
        print(f"✓ Report saved to: {report_file}")
        print("=" * 80 + "\n")

def main():
    """
    Main entry point for monitoring dashboard
    """
    print("\n🚀 Starting AI Firewall Monitor...\n")
    
    monitor = FirewallMonitor()
    
    print("📊 Monitoring firewall activity...")
    print("   Dashboard will refresh every 5 seconds")
    print("   Press Ctrl+C to stop and view final report\n")
    
    time.sleep(2)
    monitor.monitor_realtime(refresh_interval=5)

if __name__ == '__main__':
    main()
