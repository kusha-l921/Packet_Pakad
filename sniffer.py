import sys
import threading
import argparse
from scapy.all import IP, IPv6, UDP, Raw, sniff
import pyshark

# ─── BPF Filters ─────────────────────────────────────────────────────────────
# Scapy captures Native ESP (proto 50) and NAT-T ESP (UDP 4500)
DATA_PLANE_BPF = "ip proto 50 or ip6 proto 50 or (udp port 4500)"

# PyShark captures IKEv2 control exchanges (UDP 500 & UDP 4500)
CONTROL_PLANE_BPF = "udp port 500 or udp port 4500"


# ─── Data Plane (Scapy) ─────────────────────────────────────────────────────

def esp_packet_handler(pkt):
    """Fast-path Scapy handler for data-plane ESP and NAT-T traffic."""
    try:
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return

        is_natt = pkt.haslayer(UDP) and (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500)

        # RFC 3948: Check if UDP 4500 is IKE (Non-ESP Marker) -> Skip for PyShark
        if is_natt:
            if not pkt.haslayer(Raw):
                return
            raw_payload = pkt[Raw].load
            if len(raw_payload) < 8 or raw_payload[:4] == b"\x00\x00\x00\x00":
                return

        # Endpoints
        if is_natt:
            src = f"{pkt[IP].src}:{pkt[UDP].sport}" if pkt.haslayer(IP) else f"{pkt[IPv6].src}:{pkt[UDP].sport}"
            dst = f"{pkt[IP].dst}:{pkt[UDP].dport}" if pkt.haslayer(IP) else f"{pkt[IPv6].dst}:{pkt[UDP].dport}"
            mode_str = "UDP/4500 (NAT-T)"
            raw_data = pkt[Raw].load
            spi_hex = f"0x{raw_data[:4].hex()}"
            seq_num = int.from_bytes(raw_data[4:8], "big")
        else:
            src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
            dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
            mode_str = "Native IP/50"
            layer_payload = bytes(pkt[IP].payload if pkt.haslayer(IP) else pkt[IPv6].payload)
            if len(layer_payload) < 8:
                return
            spi_hex = f"0x{layer_payload[:4].hex()}"
            seq_num = int.from_bytes(layer_payload[4:8], "big")

        wire_bytes = len(pkt)

        print(
            f"[DATA - SCAPY] ESP {mode_str} | {src} -> {dst} | "
            f"SPI: {spi_hex} | Seq: {seq_num} | Wire: {wire_bytes}B"
        )

    except Exception:
        # Prevent unhandled exceptions from terminating the sniffer
        pass


def run_data_plane(interface=None, stop_event=None):
    """Worker thread running Scapy sniffer for wire-speed ESP capture."""
    print(f"[*] [DATA PLANE] Started Scapy sniffer on filter: \"{DATA_PLANE_BPF}\"")

    def stop_filter(pkt):
        return stop_event.is_set() if stop_event else False

    try:
        sniff(
            filter=DATA_PLANE_BPF,
            prn=esp_packet_handler,
            store=0,
            iface=interface,
            stop_filter=stop_filter
        )
    except Exception as e:
        print(f"[-] [DATA PLANE] Error: {e}")
    finally:
        print("[*] [DATA PLANE] Scapy sniffer stopped.")


# ─── Control Plane (PyShark) ─────────────────────────────────────────────────

def run_control_plane(interface=None, stop_event=None):
    """Worker thread running PyShark LiveCapture for IKE control exchanges."""
    print(f"[*] [CONTROL PLANE] Started PyShark sniffer on filter: \"{CONTROL_PLANE_BPF}\"")

    # display_filter='isakmp' instructs tshark to only return parsed IKE/ISAKMP packets
    capture = pyshark.LiveCapture(
        interface=interface,
        bpf_filter=CONTROL_PLANE_BPF,
        display_filter="isakmp"
    )

    try:
        for pkt in capture.sniff_continuously():
            if stop_event and stop_event.is_set():
                break

            try:
                # Basic IP extraction
                has_ip = hasattr(pkt, "ip")
                src_ip = pkt.ip.src if has_ip else getattr(pkt.ipv6, "src", "unknown")
                dst_ip = pkt.ip.dst if has_ip else getattr(pkt.ipv6, "dst", "unknown")

                # UDP ports
                sport = getattr(pkt.udp, "srcport", "")
                dport = getattr(pkt.udp, "dstport", "")
                src = f"{src_ip}:{sport}" if sport else src_ip
                dst = f"{dst_ip}:{dport}" if dport else dst_ip

                # ISAKMP fields
                ex_type = "Unknown"
                init_spi = None
                resp_spi = None
                msg_id = None

                if hasattr(pkt, "isakmp"):
                    ex_type = getattr(pkt.isakmp, "exchangetype", "Unknown")
                    init_spi = getattr(pkt.isakmp, "ispi", None)
                    resp_spi = getattr(pkt.isakmp, "rspi", None)
                    msg_id = getattr(pkt.isakmp, "messageid", None)

                wire_len = getattr(pkt, "length", len(pkt))

                print(
                    f"[CONTROL - PYSHARK] IKE packet | Exch: {ex_type} | MsgID: {msg_id} | "
                    f"{src} -> {dst} | InitSPI: {init_spi} | RespSPI: {resp_spi} | Size: {wire_len}B"
                )

            except Exception:
                continue

    except Exception as e:
        if not (stop_event and stop_event.is_set()):
            print(f"[-] [CONTROL PLANE] Error: {e}")
    finally:
        capture.close()
        print("[*] [CONTROL PLANE] PyShark sniffer stopped.")


# ─── Orchestrator ────────────────────────────────────────────────────────────

def start_hybrid_sniffer(interface=None):
    """Launches dual-threaded hybrid capture engine: Scapy for ESP, PyShark for IKE."""
    print("=" * 70)
    print(" IPsec Real-Time Hybrid Sniffer")
    print(" - Data Plane: Scapy (Native ESP & NAT-T ESP) -> Wire Speed")
    print(" - Control Plane: PyShark (IKEv2 ISAKMP)     -> Deep Dissection")
    print("=" * 70)

    stop_event = threading.Event()

    # Thread 1: Data Plane (Scapy)
    data_thread = threading.Thread(
        target=run_data_plane,
        kwargs={"interface": interface, "stop_event": stop_event},
        name="DataPlane-Scapy",
        daemon=True
    )

    # Thread 2: Control Plane (PyShark)
    control_thread = threading.Thread(
        target=run_control_plane,
        kwargs={"interface": interface, "stop_event": stop_event},
        name="ControlPlane-PyShark",
        daemon=True
    )

    data_thread.start()
    control_thread.start()

    print("[*] Hybrid sniffer running. Press Ctrl+C to stop...\n")

    try:
        while data_thread.is_alive() and control_thread.is_alive():
            data_thread.join(timeout=0.5)
            control_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\n[*] Shutdown signal received (Ctrl+C). Cleaning up...")
        stop_event.set()
        # Allow threads brief window to exit
        data_thread.join(timeout=2.0)
        control_thread.join(timeout=2.0)
        print("[*] All sniffer engines stopped cleanly.")
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IPsec Hybrid Network Sniffer (Scapy + PyShark)")
    parser.add_argument("-i", "--interface", default=None, help="Network interface name (e.g., 'Wi-Fi', 'eth0')")
    args = parser.parse_args()

    start_hybrid_sniffer(interface=args.interface)