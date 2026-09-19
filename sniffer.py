from scapy.all import IP, IPv6, UDP, sniff
BPF_FILTER = (
    "ip proto 50 or "
    "ip proto 51 or "
    "ip6 proto 50 or "
    "ip6 proto 51 or "
    "(udp port 500 or udp port 4500)"
)


def packet_dispatcher(pkt):
    if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
        return
    
    is_esp = (
        (pkt.haslayer(IP) and pkt[IP].proto == 50) or
        (pkt.haslayer(IPv6) and pkt[IPv6].nh == 50)
    )

    is_ah = (
        (pkt.haslayer(IP) and pkt[IP].proto == 51) or
        (pkt.haslayer(IPv6) and pkt[IPv6].nh == 51)
    )

    is_udp_ike_or_natt = pkt.haslayer(UDP) and (
        pkt[UDP].sport in (500, 4500) or pkt[UDP].dport in (500, 4500)
    )

    if is_udp_ike_or_natt:
        control_plane(pkt)

    elif is_esp:
        data_plane(pkt)

    elif is_ah:
        AH_plane(pkt)

def control_plane(pkt):
    src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
    dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
    print(f"[CONTROL] IKE packet intercepted: {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}")

def data_plane(pkt):
    src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
    dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
    wire_size = len(pkt)
    print(f"[DATA] ESP packet intercepted: {src} -> {dst} | Size: {wire_size} bytes")

def AH_plane(pkt):

    src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
    dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst

    wire_size = len(pkt)

    print(
        f"[AH] "
        f"{src} -> {dst} | "
        f"Size: {wire_size} bytes"
    )


def sniff_packets():  
    print("[*] Starting real-time IPsec network sniffer...")
    print(f"[*] Kernel BPF Filter applied: \"{BPF_FILTER}\"")
    print("[*] Waiting for VPN traffic (Press Ctrl+C to stop)...")
    packets = sniff(filter = BPF_FILTER, prn=packet_dispatcher, store=0 )


if __name__ == "__main__":
    sniff_packets()
