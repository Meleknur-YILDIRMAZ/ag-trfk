import subprocess
import os

class FirewallManager:
    def __init__(self):
        self.blocked_ips = set()

    def block_ip(self, ip):
        if ip in self.blocked_ips:
            return False
        
        try:
            # Linux iptables komutu ile IP'yi tamamen engelle
            # -A INPUT: Gelen trafiğe ekle
            # -s: Kaynak IP
            # -j DROP: Paketi çöpe at
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True)
            self.blocked_ips.add(ip)
            return True
        except Exception:
            return False

    def unblock_ip(self, ip):
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True)
            self.blocked_ips.discard(ip)
            return True
        except Exception:
            return False

    def cleanup(self):
        # Program kapanırken tüm engelleri kaldır
        for ip in list(self.blocked_ips):
            self.unblock_ip(ip)
