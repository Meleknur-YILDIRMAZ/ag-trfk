import requests
import time
import threading

class HTTPDetector:
    def detect(self, pkt_data, alert_system, geoip):
        if pkt_data.get("is_http"):
            geo = geoip.lookup(pkt_data["src_ip"])
            msg = f"Cleartext HTTP detected to {pkt_data['dst_ip']}"
            if pkt_data["http_host"]:
                msg += f" (Host: {pkt_data['http_host']})"
            alert_system.trigger_alert("HTTP_CLEARTEXT", "HIGH", pkt_data["src_ip"], pkt_data["dst_ip"], geo, msg)

class DDoSDetector(threading.Thread):
    def __init__(self, traffic_analyzer, alert_system, geoip, settings, stop_event, list_manager):
        super().__init__()
        self.analyzer = traffic_analyzer
        self.alert_system = alert_system
        self.geoip = geoip
        self.settings = settings
        self.stop_event = stop_event
        self.list_manager = list_manager
        self.daemon = True

    def run(self):
        while not self.stop_event.is_set():
            time.sleep(5)
            # Total RPS check
            total_rps = self.analyzer.get_total_rps()
            if total_rps > self.settings.TOTAL_RPS_THRESHOLD:
                self.alert_system.trigger_alert(
                    "POTENTIAL_DDOS", "HIGH", "MULTIPLE", "LOCAL", 
                    {"country": "LOCAL", "flag": "🔥"}, 
                    f"High total traffic: {total_rps:.1f} RPS"
                )

            # Per IP check
            for ip, history in list(self.analyzer.ip_stats.items()):
                reqs = len(history)
                threshold = self.settings.REQS_PER_IP_THRESHOLD
                
                # If blacklisted, lower threshold (more sensitive)
                if self.list_manager.is_blacklisted(ip):
                    threshold /= 2

                if reqs > threshold:
                    geo = self.geoip.lookup(ip)
                    self.alert_system.trigger_alert(
                        "POTENTIAL_DDOS", "MEDIUM", ip, "LOCAL", geo,
                        f"Rate limit exceeded: {reqs} reqs/{self.settings.WINDOW_SECONDS}s"
                    )

class MaliciousIPDetector:
    def __init__(self, api_url, cache, list_manager):
        self.api_url = api_url
        self.cache = cache
        self.list_manager = list_manager

    def detect(self, pkt_data, alert_system, geoip):
        src_ip = pkt_data["src_ip"]
        dst_ip = pkt_data["dst_ip"]
        
        for ip in [src_ip, dst_ip]:
            # Blacklist manual check
            if self.list_manager.is_blacklisted(ip):
                geo = geoip.lookup(ip)
                alert_system.trigger_alert("BLACKLIST_MATCH", "CRITICAL", ip, "N/A", geo, "IP present in manual blacklist")
                continue

            # API Cache check
            cached = self.cache.get(ip)
            if cached is not None:
                if cached: # is malicious
                    geo = geoip.lookup(ip)
                    alert_system.trigger_alert("MALICIOUS_IP", "CRITICAL", ip, "N/A", geo, "Known malicious IP (Cached)")
                continue

            # API Call (Threaded or rate limited suggested, here direct for simplicity but we should be careful)
            # We only do this if it's a non-local IP
            if not any(ip.startswith(p) for p in ["10.", "192.168.", "127."]):
                threading.Thread(target=self._check_threatfox, args=(ip, alert_system, geoip), daemon=True).start()

    def _check_threatfox(self, ip, alert_system, geoip):
        try:
            payload = {"query": "search_ioc", "search_term": ip}
            response = requests.post(self.api_url, json=payload, timeout=3)
            data = response.json()
            
            is_malicious = (data.get("query_status") == "ok" and data.get("data"))
            self.cache.set(ip, is_malicious)
            
            if is_malicious:
                geo = geoip.lookup(ip)
                alert_system.trigger_alert("MALICIOUS_IP", "CRITICAL", ip, "N/A", geo, f"ThreatFox match: {data['data'][0]['threat_type']}")
        except Exception:
            self.cache.set(ip, False) # Mark as false on error to avoid spamming API
