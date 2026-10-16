import json
import os
import csv
from datetime import datetime
from collections import deque
import uuid

class AlertSystem:
    def __init__(self, session_dir):
        self.session_dir = session_dir
        self.alerts_file = os.path.join(session_dir, "alerts.jsonl")
        self.packets_file = os.path.join(session_dir, "packets.csv")
        self.summary_file = os.path.join(session_dir, "summary.txt")
        self.alert_history = deque(maxlen=100)
        self.stats = {
            "total_packets": 0,
            "http_packets": 0,
            "unique_ips": set(),
            "alerts_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "top_ips": {}
        }
        self.start_time = datetime.now()
        
        # Init CSV
        with open(self.packets_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src", "dst", "proto", "size"])

    def log_packet(self, pkt_data):
        self.stats["total_packets"] += 1
        self.stats["unique_ips"].add(pkt_data["src_ip"])
        self.stats["unique_ips"].add(pkt_data["dst_ip"])
        
        # Track top IPs
        src = pkt_data["src_ip"]
        self.stats["top_ips"][src] = self.stats["top_ips"].get(src, 0) + 1

        with open(self.packets_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                pkt_data["timestamp"],
                pkt_data["src_ip"],
                pkt_data["dst_ip"],
                pkt_data["protocol"],
                pkt_data["packet_size"]
            ])

    def trigger_alert(self, alert_type, severity, src_ip, dst_ip, geo, message, extra=None):
        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "geo": geo,
            "message": message,
            "extra": extra or {}
        }
        
        self.alert_history.appendleft(alert)
        self.stats["alerts_by_severity"][severity] += 1
        
        with open(self.alerts_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(alert) + "\n")
            
        return alert

    def finalize_session(self):
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        with open(self.summary_file, 'w', encoding='utf-8') as f:
            f.write("=== WARD SESSION SUMMARY ===\n")
            f.write(f"Start: {self.start_time}\n")
            f.write(f"End:   {end_time}\n")
            f.write(f"Duration: {duration}\n\n")
            f.write(f"Total Packets: {self.stats['total_packets']}\n")
            f.write(f"Unique IPs:    {len(self.stats['unique_ips'])}\n\n")
            f.write("Alerts by Severity:\n")
            for sev, count in self.stats["alerts_by_severity"].items():
                f.write(f"  - {sev}: {count}\n")
            f.write("\nTop 5 IPs:\n")
            top_5 = sorted(self.stats["top_ips"].items(), key=lambda x: x[1], reverse=True)[:5]
            for ip, count in top_5:
                f.write(f"  - {ip}: {count} packets\n")
