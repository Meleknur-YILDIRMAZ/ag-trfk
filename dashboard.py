from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Console
from datetime import datetime

class Dashboard:
    def __init__(self, interface, alert_system):
        self.interface = interface
        self.alert_system = alert_system
        self.console = Console()
        self.layout = self._make_layout()
        self.recent_packets = []

    def _make_layout(self):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        layout["body"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1)
        )
        layout["left"].split_column(
            Layout(name="packets", ratio=2),
            Layout(name="alerts", ratio=3)
        )
        return layout

    def update_packets(self, pkt_data):
        self.recent_packets.append(pkt_data)
        if len(self.recent_packets) > 15:
            self.recent_packets.pop(0)

    def generate_renderable(self):
        # Header
        runtime = str(datetime.now() - self.alert_system.start_time).split(".")[0]
        self.layout["header"].update(Panel(
            Text(f"WARD IDS v1.0   |   INTERFACE: {self.interface}   |   UPTIME: {runtime}", justify="center", style="bold white on blue")
        ))

        # Packet Flow
        packet_table = Table(title="LIVE PACKET FLOW", expand=True)
        packet_table.add_column("Time", style="dim")
        packet_table.add_column("Proto", style="cyan")
        packet_table.add_column("Source", style="white")
        packet_table.add_column("Dest", style="white")
        packet_table.add_column("Size", justify="right")

        for p in reversed(self.recent_packets):
            packet_table.add_row(
                p["timestamp"], p["protocol"], p["src_ip"], p["dst_ip"], str(p["packet_size"])
            )
        self.layout["packets"].update(Panel(packet_table))

        # Alerts
        alert_table = Table(title="RECENT ALERTS", expand=True)
        alert_table.add_column("Severity", width=12)
        alert_table.add_column("Type")
        alert_table.add_column("Source")
        alert_table.add_column("Message")

        for a in list(self.alert_system.alert_history)[:10]:
            sev_style = {
                "CRITICAL": "bold bright_red",
                "HIGH": "bold yellow",
                "MEDIUM": "bold blue",
                "LOW": "green"
            }.get(a["severity"], "white")
            
            flag = a["geo"].get("flag", "")
            alert_table.add_row(
                Text(a["severity"], style=sev_style),
                a["type"],
                f"{a['src_ip']} {flag}",
                a["message"]
            )
        self.layout["alerts"].update(Panel(alert_table))

        # Stats
        stats_text = Text()
        stats_text.append(f"Total Packets: {self.alert_system.stats['total_packets']}\n", style="bold cyan")
        stats_text.append(f"Unique IPs:    {len(self.alert_system.stats['unique_ips'])}\n", style="bold green")
        stats_text.append("\nSeverity Breakdown:\n")
        for sev, count in self.alert_system.stats["alerts_by_severity"].items():
            stats_text.append(f"  {sev:8}: {count}\n", style="yellow" if count > 0 else "dim")
        
        self.layout["right"].update(Panel(stats_text, title="NETWORK STATISTICS"))

        # Footer
        self.layout["footer"].update(Panel(
            Text("[W] Whitelist   [B] Blacklist   [X] Block   [U] Unblock   [Q] Exit", justify="center", style="bold white")
        ))

        return self.layout
