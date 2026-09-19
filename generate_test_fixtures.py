"""
generate_test_fixtures.py — One-time script to create .pcap test fixtures using Scapy.

Run once:
    python generate_test_fixtures.py

This generates static .pcap files in test_fixtures/ that the PyShark-based tests
will read via pyshark.FileCapture. After generating, commit the pcaps and never
need Scapy for IKE testing again.
"""

import os
from scapy.all import IP, IPv6, UDP, Raw, wrpcap
from scapy.contrib.ikev2 import (
    IKEv2,
    IKEv2_SA,
    IKEv2_Proposal,
    IKEv2_Transform,
    IKEv2_Notify,
    IKEv2_CERT,
    IKEv2_AUTH,
    IKEv2_TSi,
    IKEv2_TSr,
)
from scapy.layers.isakmp import (
    ISAKMP,
    ISAKMP_payload_SA,
    ISAKMP_payload_Proposal,
    ISAKMP_payload_Transform,
    ISAKMP_payload_KE,
    ISAKMP_payload_ID,
    ISAKMP_payload_Hash,
    ISAKMP_payload_SIG,
    ISAKMP_payload_Nonce,
    ISAKMP_payload_Notify,
    ISAKMP_payload_Delete,
)
import struct

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "test_fixtures")
os.makedirs(FIXTURE_DIR, exist_ok=True)


def save(name, pkt):
    """Serialize through wire format (ensures Scapy recalculates lengths/checksums),
    then write to pcap."""
    # Force wire-format re-parse so all lengths and checksums are correct
    if pkt.haslayer(IP):
        wire_pkt = IP(bytes(pkt))
    elif pkt.haslayer(IPv6):
        wire_pkt = IPv6(bytes(pkt))
    else:
        wire_pkt = pkt.__class__(bytes(pkt))

    path = os.path.join(FIXTURE_DIR, name)
    wrpcap(path, [wire_pkt])
    print(f"  [OK] {path}")


# =========================================================================
# IKEv2 FIXTURES
# =========================================================================

def gen_ikev2_sa_init_notify():
    """IKE_SA_INIT with Notify type 16443 (SIGNATURE_HASH_ALGORITHMS)."""
    sig_hash_data = (
        (18).to_bytes(2, "big") +
        (19).to_bytes(2, "big") +
        (1).to_bytes(2, "big")
    )
    notify = IKEv2_Notify(
        next_payload=0, flags=0, proto=0,
        type=16443, SPI=b"", notify=sig_hash_data
    )
    ike = IKEv2(
        init_SPI=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        resp_SPI=b"\x00\x00\x00\x00\x00\x00\x00\x00",
        next_payload=41, version=0x20, exch_type=34,
        flags=0x08, id=1
    )
    pkt = IP(src="192.168.1.100", dst="10.0.0.1") / UDP(sport=500, dport=500) / ike / notify
    save("ikev2_sa_init_notify.pcap", pkt)


def gen_ikev2_auth_cert():
    """IKE_AUTH with CERT (encoding=4) and AUTH (type=1)."""
    cert = IKEv2_CERT(
        cert_encoding=4,
        cert_data=b"\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xaa\xbb\xcc"
    )
    auth = IKEv2_AUTH(
        auth_type=1,
        load=b"\xde\xad\xbe\xef"
    )
    ike = IKEv2(
        init_SPI=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        resp_SPI=b"\x88\x77\x66\x55\x44\x33\x22\x11",
        version=0x20, exch_type=35, flags=0x08, id=2
    )
    pkt = IP(src="192.168.1.100", dst="10.0.0.1") / UDP(sport=500, dport=500) / ike / cert / auth
    save("ikev2_auth_cert.pcap", pkt)


# =========================================================================
# IKEv1 FIXTURES
# =========================================================================

def gen_ikev1_main_mode_sa():
    """Main Mode: 2 proposals with multiple transforms."""
    t1 = ISAKMP_payload_Transform(
        transform_count=1, transform_id=1,
        transforms=[
            ('Encryption', 'AES-CBC'), ('Hash', 'SHA2-256'),
            ('Authentication', 'PSK'), ('GroupDesc', '2048MODPgr'),
            ('LifeType', 'Seconds'), ('LifeDuration', 28800),
            ('KeyLength', 256),
        ]
    )
    t2 = ISAKMP_payload_Transform(
        transform_count=2, transform_id=1,
        transforms=[
            ('Encryption', '3DES-CBC'), ('Hash', 'SHA'),
            ('Authentication', 'PSK'), ('GroupDesc', '1024MODPgr'),
            ('LifeType', 'Seconds'), ('LifeDuration', 28800),
        ]
    )
    p1 = ISAKMP_payload_Proposal(proposal=1, proto=1, trans_nb=2, trans=t1 / t2)

    t3 = ISAKMP_payload_Transform(
        transform_count=1, transform_id=1,
        transforms=[
            ('Encryption', 'AES-CBC'), ('Hash', 'SHA'),
            ('Authentication', 'RSA Sig'), ('GroupDesc', '2048MODPgr'),
        ]
    )
    p2 = ISAKMP_payload_Proposal(proposal=2, proto=1, trans_nb=1, trans=t3)

    sa = ISAKMP_payload_SA(prop=p1 / p2)
    pkt = (
        IP(src="192.168.1.10", dst="192.168.1.20") /
        UDP(sport=500, dport=500) /
        ISAKMP(init_cookie=b"\x11\x22\x33\x44\x55\x66\x77\x88",
               resp_cookie=b"\x00" * 8, exch_type=2) /
        sa
    )
    save("ikev1_main_mode_sa.pcap", pkt)


def gen_ikev1_main_mode_ke_nonce():
    """Main Mode: KE + Nonce."""
    ke = ISAKMP_payload_KE(ke=b"\xab" * 64)
    nonce = ISAKMP_payload_Nonce(nonce=b"\xcd" * 32)
    pkt = (
        IP(src="192.168.1.10", dst="192.168.1.20") /
        UDP(sport=500, dport=500) /
        ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8, exch_type=2) /
        ke / nonce
    )
    save("ikev1_main_mode_ke_nonce.pcap", pkt)


def gen_ikev1_main_mode_id_hash():
    """Main Mode: ID + Hash (PSK authentication)."""
    id_payload = ISAKMP_payload_ID(IDtype=1, IdentData="192.168.1.10")
    hash_payload = ISAKMP_payload_Hash(hash=b"\xee" * 20)
    pkt = (
        IP(src="192.168.1.10", dst="192.168.1.20") /
        UDP(sport=500, dport=500) /
        ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8, exch_type=2) /
        id_payload / hash_payload
    )
    save("ikev1_main_mode_id_hash.pcap", pkt)


def gen_ikev1_main_mode_sig():
    """Main Mode: Signature authentication."""
    sig_payload = ISAKMP_payload_SIG(sig=b"\x77" * 64)
    pkt = (
        IP(src="192.168.1.10", dst="192.168.1.20") /
        UDP(sport=500, dport=500) /
        ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8, exch_type=2) /
        sig_payload
    )
    save("ikev1_main_mode_sig.pcap", pkt)


def gen_ikev1_aggressive():
    """Aggressive Mode: SA + KE + Nonce + ID."""
    t1 = ISAKMP_payload_Transform(
        transform_count=1, transform_id=1,
        transforms=[('Encryption', 'AES-CBC'), ('Hash', 'SHA')]
    )
    p1 = ISAKMP_payload_Proposal(proposal=1, proto=1, trans_nb=1, trans=t1)
    sa = ISAKMP_payload_SA(prop=p1)
    ke = ISAKMP_payload_KE(ke=b"\x12" * 32)
    nonce = ISAKMP_payload_Nonce(nonce=b"\x34" * 16)
    id_p = ISAKMP_payload_ID(IDtype=1, IdentData="10.1.1.1")

    pkt = (
        IP(src="10.1.1.1", dst="10.2.2.2") /
        UDP(sport=500, dport=500) /
        ISAKMP(init_cookie=b"\xaa" * 8, resp_cookie=b"\x00" * 8, exch_type=4) /
        sa / ke / nonce / id_p
    )
    save("ikev1_aggressive.pcap", pkt)


def gen_ikev1_quick_mode():
    """Quick Mode: SA (ESP) + Nonce + IDci + IDcr."""
    t_esp = ISAKMP_payload_Transform(
        transform_count=1, transform_id=12,
        transforms=[
            (4, 1),   # EncapsulationMode = Tunnel
            (5, 2),   # AuthenticationAlgorithm = HMAC-SHA
            (1, 1),   # LifeType = seconds
            (2, 3600), # LifeDuration = 3600
        ]
    )
    p_esp = ISAKMP_payload_Proposal(
        proposal=1, proto=3, SPIsize=4,
        SPI=b"\x01\x02\x03\x04", trans_nb=1, trans=t_esp
    )
    sa = ISAKMP_payload_SA(doi=1, situation=1, prop=p_esp)
    nonce = ISAKMP_payload_Nonce(nonce=b"\x99" * 16)
    idci = ISAKMP_payload_ID(IDtype=4, IdentData=bytes([192, 168, 10, 0, 255, 255, 255, 0]))
    idcr = ISAKMP_payload_ID(IDtype=4, IdentData=bytes([10, 0, 0, 0, 255, 0, 0, 0]))

    pkt = (
        IP(src="192.168.1.1", dst="192.168.1.2") /
        UDP(sport=500, dport=500) /
        ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8,
               exch_type=32, id=0x12345678) /
        sa / nonce / idci / idcr
    )
    save("ikev1_quick_mode.pcap", pkt)


def gen_ikev1_informational():
    """Informational: Notify (INITIAL-CONTACT) + Delete."""
    notif = ISAKMP_payload_Notify(
        doi=1, proto=1, notify_msg_type=24578,
        SPIsize=8, SPI=b"\x11" * 8,
        notify_data=b"notify_payload_data"
    )
    dele = ISAKMP_payload_Delete(
        doi=1, proto=3, SPIsize=4, SPIcount=2,
        SPIs=[b"\xaa\xbb\xcc\xdd", b"\x11\x22\x33\x44"]
    )
    pkt = (
        IP(src="1.1.1.1", dst="2.2.2.2") /
        UDP(sport=500, dport=500) /
        ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8, exch_type=5) /
        notif / dele
    )
    save("ikev1_informational.pcap", pkt)


def gen_ikev1_cert():
    """Main Mode with Certificate payload (next_payload=6)."""
    cert_body = struct.pack("!B", 4) + b"MIIB..."
    raw_cert = struct.pack("!BBH", 0, 0, 4 + len(cert_body)) + cert_body
    pkt = (
        IP(src="1.1.1.1", dst="2.2.2.2") /
        UDP(sport=500, dport=500) /
        ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8,
               next_payload=6, exch_type=2) /
        raw_cert
    )
    save("ikev1_cert.pcap", pkt)


def gen_ikev1_new_group():
    """New Group Mode: SA with group attributes."""
    t1 = ISAKMP_payload_Transform(
        transform_count=1, transform_id=1,
        transforms=[('GroupDesc', '2048MODPgr'), ('GroupType', 'MODP')]
    )
    p1 = ISAKMP_payload_Proposal(proposal=1, proto=1, trans_nb=1, trans=t1)
    sa = ISAKMP_payload_SA(prop=p1)
    pkt = (
        IP(src="1.1.1.1", dst="2.2.2.2") /
        UDP(sport=500, dport=500) /
        ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8, exch_type=33) /
        sa
    )
    save("ikev1_new_group.pcap", pkt)


def gen_ikev1_ipv6():
    """IPv6 ISAKMP Main Mode (minimal)."""
    pkt = (
        IPv6(src="2001:db8::1", dst="2001:db8::2") /
        UDP(sport=500, dport=500) /
        ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x00" * 8, exch_type=2)
    )
    save("ikev1_ipv6.pcap", pkt)


# =========================================================================
# MAIN
# =========================================================================

if __name__ == "__main__":
    print(f"Generating test fixtures in {FIXTURE_DIR}/\n")

    # IKEv2
    print("--- IKEv2 ---")
    gen_ikev2_sa_init_notify()
    gen_ikev2_auth_cert()

    # IKEv1
    print("\n--- IKEv1 ---")
    gen_ikev1_main_mode_sa()
    gen_ikev1_main_mode_ke_nonce()
    gen_ikev1_main_mode_id_hash()
    gen_ikev1_main_mode_sig()
    gen_ikev1_aggressive()
    gen_ikev1_quick_mode()
    gen_ikev1_informational()
    gen_ikev1_cert()
    gen_ikev1_new_group()
    gen_ikev1_ipv6()

    print(f"\nDone! {len(os.listdir(FIXTURE_DIR))} fixture(s) generated.")
