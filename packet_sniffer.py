import threading , time
from collections import Counter

from scapy.all import sniff, IP, TCP, UDP, ICMP


stats = {
    "total": 0, "bytes": 0,
    "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
    "src": Counter(),
    "ports": Counter(),
}
lock = threading.Lock()
start_time = time.time()


def handle(pkt):
    src = pkt[IP].src if pkt.haslayer(IP) else getattr(pkt, "src", "Unknown")

    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        proto, port = "tcp", pkt[TCP].dport
    elif pkt.haslayer(IP) and pkt.haslayer(UDP):
        proto, port = "udp", pkt[UDP].dport
    elif pkt.haslayer(IP) and pkt.haslayer(ICMP):
        proto, port = "icmp", None
    else:
        proto, port = "other", None

    with lock:
        stats["total"] += 1
        stats["bytes"] += len(pkt)
        stats[proto] += 1
        stats["src"][(src, proto)] += 1
        if port is not None:
            stats["ports"][(proto, port)] += 1


def start_sniffing():
    threading.Thread(target=lambda: sniff(prn=handle, store=False),
                    daemon=True).start()

def get_snapshot(top=10):
    with lock:
        return{
            "total": stats["total"], "bytes": stats["bytes"],
            "uptime": int(time.time() - start_time),
            "tcp": stats["tcp"], "udp": stats["udp"],
            "icmp": stats["icmp"], "other": stats["other"],
            "src": stats["src"].most_common(top),
            "ports": stats["ports"].most_common(top),
        }