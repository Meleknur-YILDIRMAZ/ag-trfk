from collections import deque
import time

class TrafficAnalyzer:
    def __init__(self, window_seconds, list_manager):
        self.window_seconds = window_seconds
        self.list_manager = list_manager
        self.ip_stats = {} # { ip: deque([timestamps]) }

    def analyze(self, pkt_data):
        # Whitelist check
        if self.list_manager.is_whitelisted(pkt_data["src_ip"]):
            return None

        # Feature Extraction
        pkt_data["is_http"] = False
        pkt_data["http_host"] = ""
        
        if pkt_data["protocol"] == "TCP" and pkt_data["dst_port"] == 80:
            payload = pkt_data["raw_payload"].decode('utf-8', errors='ignore')
            methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]
            if any(payload.startswith(m) for m in methods):
                pkt_data["is_http"] = True
                # Try extract Host header
                for line in payload.split("\r\n"):
                    if line.startswith("Host:"):
                        pkt_data["http_host"] = line.split(":", 1)[1].strip()

        pkt_data["is_https"] = (pkt_data["protocol"] == "TCP" and pkt_data["dst_port"] == 443)

        # Update IP stats for sliding window
        src_ip = pkt_data["src_ip"]
        now = time.time()
        if src_ip not in self.ip_stats:
            self.ip_stats[src_ip] = deque()
        
        self.ip_stats[src_ip].append(now)
        
        # Cleanup old entries
        while self.ip_stats[src_ip] and now - self.ip_stats[src_ip][0] > self.window_seconds:
            self.ip_stats[src_ip].popleft()

        return pkt_data

    def get_rps_for_ip(self, ip):
        if ip not in self.ip_stats:
            return 0
        return len(self.ip_stats[ip]) / self.window_seconds

    def get_total_rps(self):
        total_reqs = sum(len(d) for d in self.ip_stats.values())
        return total_reqs / self.window_seconds
