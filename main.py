import os
import sys
import time
import threading
import queue
from datetime import datetime
import psutil
from rich.console import Console
from rich.prompt import Prompt
import select

# Project Modules
from config import settings
from list_manager import ListManager
from ip_cache import IPCache
from geoip_lookup import GeoIPLookup
from alert_system import AlertSystem
from packet_capture import PacketCapture
from traffic_analyzer import TrafficAnalyzer
from detection_engine import HTTPDetector, DDoSDetector, MaliciousIPDetector
from dashboard import Dashboard
from firewall_manager import FirewallManager

BANNER = """
[bold red]
 __        __   _      ____    ____  
 \ \      / /  / \    |  _ \  |  _ \ 
  \ \ /\ / /  / _ \   | |_) | | | | |
   \ V  V /  / ___ \  |  _ <  | |_| |
    \_/\_/  /_/   \_\ |_| \_\ |____/ 
[/bold red]
[bold white]                         AĞ TRAFİK ANALİZÖRÜ & SALDIRI TESPİT SİSTEMİ [/bold white]
"""

class WardApp:
    def __init__(self):
        self.console = Console()
        self.stop_event = threading.Event()
        self.packet_queue = queue.Queue()
        
        # Init components
        self.list_manager = ListManager(settings.WHITELIST_PATH, settings.BLACKLIST_PATH)
        self.ip_cache = IPCache(settings.THREATFOX_CACHE_TTL)
        self.geoip = GeoIPLookup(settings.GEOIP_DB_PATH)
        self.input_queue = queue.Queue()
        
        # Session setup
        session_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.session_dir = os.path.join(settings.SESSIONS_DIR, session_name)
        os.makedirs(self.session_dir, exist_ok=True)
        
        self.alert_system = AlertSystem(self.session_dir)
        self.analyzer = TrafficAnalyzer(settings.WINDOW_SECONDS, self.list_manager)
        
        # Detectors
        self.http_detector = HTTPDetector()
        self.malicious_detector = MaliciousIPDetector(settings.THREATFOX_API_URL, self.ip_cache, self.list_manager)
        self.firewall = FirewallManager()

    def check_permissions(self):
        if os.name != 'nt' and os.geteuid() != 0:
            self.console.print("[bold red][!] Hata: Bu program root yetkisi gerektirir (sudo).[/bold red]")
            sys.exit(1)

    def select_interface(self):
        interfaces = psutil.net_if_addrs()
        iface_names = list(interfaces.keys())
        
        self.console.print("\n[bold cyan]Mevcut Ağ Arayüzleri:[/bold cyan]")
        for i, name in enumerate(iface_names):
            self.console.print(f" {i+1}. {name}")
        
        choice = Prompt.ask("\nArayüz seçin", choices=[str(i+1) for i in range(len(iface_names))])
        return iface_names[int(choice)-1]

    def handle_keyboard(self, live):
        # Linux/WSL friendly non-blocking key read
        if select.select([sys.stdin], [], [], 0)[0]:
            ch = sys.stdin.read(1).lower()
            if ch == 'q':
                self.stop_event.set()
                return # Exit handler immediately
            elif ch == 'w':
                self.input_queue.put("whitelist")
            elif ch == 'b':
                self.input_queue.put("blacklist")
            elif ch == 'x':
                self.input_queue.put("firewall")
            elif ch == 'u':
                self.input_queue.put("unblock")
            
            # Clear any extra characters in buffer
            while select.select([sys.stdin], [], [], 0)[0]:
                sys.stdin.read(1)

    def run(self):
        self.console.clear()
        self.console.print(BANNER)
        
        self.check_permissions()
        
        if not os.path.exists(settings.GEOIP_DB_PATH):
            self.console.print(f"[yellow][!] Uyarı: {settings.GEOIP_DB_PATH} bulunamadı. GeoIP devre dışı.[/yellow]")
        
        iface = self.select_interface()
        self.console.print(f"\n[green][*] {iface} dinleniyor... Dashboard başlıyor...[/green]")
        time.sleep(2)
        
        # Start Threads
        capture_thread = PacketCapture(iface, self.packet_queue, self.stop_event)
        capture_thread.start()
        
        ddos_detector = DDoSDetector(self.analyzer, self.alert_system, self.geoip, settings, self.stop_event, self.list_manager)
        ddos_detector.start()
        
        dashboard = Dashboard(iface, self.alert_system)
        
        # Set terminal to raw mode for better key capturing
        import tty, termios
        old_settings = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())

        try:
            from rich.live import Live
            with Live(dashboard.generate_renderable(), refresh_per_second=settings.DASHBOARD_REFRESH_HZ, screen=True) as live:
                while not self.stop_event.is_set():
                    try:
                        # Handle keyboard input
                        self.handle_keyboard(live)
                        
                        # Only handle queue if we are NOT stopping
                        if not self.stop_event.is_set() and not self.input_queue.empty():
                            req_type = self.input_queue.get_nowait()
                            live.stop()
                            # Restore terminal for input
                            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                            
                            self.console.print("\n" * 2)
                            ip = Prompt.ask(f"[bold yellow][?] {req_type.capitalize()} listesine eklenecek IP[/bold yellow]")
                            if ip:
                                if req_type == "firewall":
                                    if self.firewall.block_ip(ip):
                                        self.console.print(f"[bold white on red][!] {ip} GERÇEK ZAMANLI ENGELLENDİ![/bold white on red]")
                                    else:
                                        self.console.print(f"[red][!] {ip} engellenemedi (Belki zaten engellidir).[/red]")
                                elif req_type == "unblock":
                                    if self.firewall.unblock_ip(ip):
                                        self.console.print(f"[bold black on green][+] {ip} ENGELİ KALDIRILDI![/bold black on green]")
                                    else:
                                        self.console.print(f"[red][!] {ip} engel listesinde bulunamadı.[/red]")
                                else:
                                    self.list_manager.add(req_type, ip)
                                    self.console.print(f"[green][+] {ip} {req_type} listesine eklendi![/green]")
                                time.sleep(1)
                            
                            # Back to raw mode
                            tty.setcbreak(sys.stdin.fileno())
                            live.start()

                        pkt_data = self.packet_queue.get(timeout=0.5)
                        analyzed_pkt = self.analyzer.analyze(pkt_data)
                        
                        if analyzed_pkt:
                            self.alert_system.log_packet(analyzed_pkt)
                            dashboard.update_packets(analyzed_pkt)
                            
                            # Detectors
                            self.http_detector.detect(analyzed_pkt, self.alert_system, self.geoip)
                            self.malicious_detector.detect(analyzed_pkt, self.alert_system, self.geoip)
                        
                        live.update(dashboard.generate_renderable())
                    except queue.Empty:
                        live.update(dashboard.generate_renderable())
                        continue
        except KeyboardInterrupt:
            self.stop_event.set()
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            self.firewall.cleanup()
            self.console.print("\n[yellow][*] Oturum kapatılıyor, özet yazılıyor...[/yellow]")
            self.alert_system.finalize_session()
            self.geoip.close()
            self.console.print(f"[green][+] Başarılı! Loglar burada: {self.session_dir}[/green]")
            sys.exit(0)

if __name__ == "__main__":
    app = WardApp()
    app.run()
