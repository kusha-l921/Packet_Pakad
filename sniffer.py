"""Root sniffer runner - proxies to SIH-160 Rule Engine/sniffer.py."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SIH_DIR = ROOT / "SIH-160 Rule Engine"
if str(SIH_DIR) not in sys.path:
    sys.path.insert(0, str(SIH_DIR))

import sniffer

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="IPsec Hybrid Network Sniffer (Scapy + PyShark)")
    parser.add_argument("-i", "--interface", default=None, help="Network interface name (e.g., 'Wi-Fi', 'eth0')")
    parser.add_argument("-p", "--pipeline", action="store_true", help="Enable integrated analytical engine pipeline")
    parser.add_argument("-o", "--output-dir", default="output", help="Directory for JSON reports")
    args = parser.parse_args()

    sniffer.start_hybrid_sniffer(interface=args.interface, enable_pipeline=args.pipeline, output_dir=args.output_dir)
