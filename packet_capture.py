from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import threading
import queue
import time
from datetime import datetime

class PacketCapture(threading.Thread):
    def __init__(self, interface, packet_queue, stop_event):
        super().__init__()
        self.interface = interface
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.daemon = True

    def run(self):
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=0,
                stop_filter=lambda x: self.stop_event.is_set()
            )
        except PermissionError:
            print(f"\n[!] Error: Root privileges required for interface {self.interface}")
        except Exception as e:
            print(f"\n[!] Sniffing error: {e}")

    def process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        pkt_data = {
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "protocol": self.get_proto_name(pkt),
            "packet_size": len(pkt),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "raw_payload": bytes(pkt[Raw]) if pkt.haslayer(Raw) else b"",
            "dst_port": pkt.dport if hasattr(pkt, 'dport') else None
        }
        
        self.packet_queue.put(pkt_data)

    def get_proto_name(self, pkt):
        if pkt.haslayer(TCP): return "TCP"
        if pkt.haslayer(UDP): return "UDP"
        if pkt.haslayer(ICMP): return "ICMP"
        return "Other"
