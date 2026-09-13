import sys
import unittest
from scapy.all import IP, IPv6, UDP
from scapy.layers.isakmp import (
    ISAKMP,
    ISAKMP_payload,
    ISAKMP_payload_SA,
    ISAKMP_payload_Proposal,
    ISAKMP_payload_Transform,
    ISAKMP_payload_KE,
    ISAKMP_payload_Nonce,
    ISAKMP_payload_ID,
    ISAKMP_payload_Hash,
    ISAKMP_payload_SIG,
    ISAKMP_payload_Notify,
    ISAKMP_payload_Delete,
)
import struct

from metadataExtractor import extract_ikeV1_metadata


class TestIKEv1MetadataExtractor(unittest.TestCase):

    def test_non_isakmp_returns_none(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=5678)
        self.assertIsNone(extract_ikeV1_metadata(pkt))

    def test_main_mode_sa_multi_proposal_multi_transform(self):
        """
        Critical test: Verify that proposals[] contains exactly 2 proposal dicts,
        and each proposal contains all its transforms' attributes, avoiding the bug
        where proposal dict was created inside transform loop.
        """
        # Proposal 1: 2 transforms
        t1 = ISAKMP_payload_Transform(
            transform_count=1,
            transform_id=1,
            transforms=[
                ('Encryption', 'AES-CBC'),
                ('Hash', 'SHA2-256'),
                ('Authentication', 'PSK'),
                ('GroupDesc', '2048MODPgr'),
                ('LifeType', 'Seconds'),
                ('LifeDuration', 28800),
                ('KeyLength', 256),
            ]
        )
        t2 = ISAKMP_payload_Transform(
            transform_count=2,
            transform_id=1,
            transforms=[
                ('Encryption', '3DES-CBC'),
                ('Hash', 'SHA'),
                ('Authentication', 'PSK'),
                ('GroupDesc', '1024MODPgr'),
                ('LifeType', 'Seconds'),
                ('LifeDuration', 28800),
            ]
        )
        p1 = ISAKMP_payload_Proposal(proposal=1, proto=1, trans_nb=2, trans=t1 / t2)

        # Proposal 2: 1 transform
        t3 = ISAKMP_payload_Transform(
            transform_count=1,
            transform_id=1,
            transforms=[
                ('Encryption', 'AES-CBC'),
                ('Hash', 'SHA'),
                ('Authentication', 'RSA Sig'),
                ('GroupDesc', '2048MODPgr'),
            ]
        )
        p2 = ISAKMP_payload_Proposal(proposal=2, proto=1, trans_nb=1, trans=t3)

        sa = ISAKMP_payload_SA(prop=p1 / p2)
        pkt = (
            IP(src="192.168.1.10", dst="192.168.1.20") /
            UDP(sport=500, dport=500) /
            ISAKMP(init_cookie=b"\x11\x22\x33\x44\x55\x66\x77\x88", resp_cookie=b"\x00" * 8, exch_type=2) /
            sa
        )
        # Parse through Scapy wire deserialization to simulate real packet
        dissected_pkt = IP(bytes(pkt))
        meta = extract_ikeV1_metadata(dissected_pkt)

        self.assertIsNotNone(meta)
        self.assertIn("common", meta)
        self.assertIn("MAIN_MODE", meta)

        common = meta["common"]
        self.assertEqual(common["plane"], "control")
        self.assertEqual(common["ike_version"], 1)
        self.assertEqual(common["src_ip"], "192.168.1.10")
        self.assertEqual(common["dst_ip"], "192.168.1.20")
        self.assertEqual(common["src_port"], 500)
        self.assertEqual(common["dst_port"], 500)
        self.assertEqual(common["initiator_cookie"], "0x1122334455667788")
        self.assertEqual(common["responder_cookie"], "0x0000000000000000")
        self.assertEqual(common["exchange_type"], "Main Mode")
        self.assertEqual(common["exchange_type_id"], 2)
        self.assertFalse(common["is_response"])

        mm = meta["MAIN_MODE"]
        self.assertEqual(mm["exchange"], "MAIN_MODE")
        self.assertTrue(mm["security_association"]["present"])

        proposals = mm["security_association"]["proposals"]
        # MUST BE 2 PROPOSALS, NOT 3 (not one per transform!)
        self.assertEqual(len(proposals), 2)

        # Proposal 1
        prop1 = proposals[0]
        self.assertEqual(prop1["proposal_num"], 1)
        self.assertEqual(prop1["protocol_id"], 1)
        self.assertEqual(len(prop1["transforms"]["encryption"]), 2)
        self.assertEqual(prop1["transforms"]["encryption"][0]["value"], "AES-CBC")
        self.assertEqual(prop1["transforms"]["encryption"][1]["value"], "3DES-CBC")
        self.assertEqual(len(prop1["transforms"]["hash"]), 2)
        self.assertEqual(prop1["transforms"]["hash"][0]["value"], "SHA2-256")
        self.assertEqual(prop1["transforms"]["hash"][1]["value"], "SHA")
        self.assertEqual(len(prop1["transforms"]["key_length"]), 1)
        self.assertEqual(prop1["transforms"]["key_length"][0]["value"], 256)

        # Proposal 2
        prop2 = proposals[1]
        self.assertEqual(prop2["proposal_num"], 2)
        self.assertEqual(prop2["protocol_id"], 1)
        self.assertEqual(len(prop2["transforms"]["encryption"]), 1)
        self.assertEqual(prop2["transforms"]["encryption"][0]["value"], "AES-CBC")
        self.assertEqual(prop2["transforms"]["auth_method"][0]["value"], "RSA Sig")

    def test_main_mode_ke_nonce(self):
        ke = ISAKMP_payload_KE(ke=b"\xab" * 64)
        nonce = ISAKMP_payload_Nonce(nonce=b"\xcd" * 32)
        pkt = (
            IP(src="192.168.1.10", dst="192.168.1.20") /
            UDP(sport=500, dport=500) /
            ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8, exch_type=2) /
            ke / nonce
        )
        meta = extract_ikeV1_metadata(IP(bytes(pkt)))

        self.assertIsNotNone(meta)
        mm = meta["MAIN_MODE"]
        self.assertTrue(mm["key_exchange"]["present"])
        self.assertEqual(mm["key_exchange"]["value"], f"0x{(b'\xab' * 64).hex()}")
        self.assertTrue(mm["nonce"]["present"])
        self.assertEqual(mm["nonce"]["value"], f"0x{(b'\xcd' * 32).hex()}")

    def test_main_mode_id_and_auth_hash(self):
        id_payload = ISAKMP_payload_ID(IDtype=1, IdentData="192.168.1.10")
        hash_payload = ISAKMP_payload_Hash(hash=b"\xee" * 20)
        pkt = (
            IP(src="192.168.1.10", dst="192.168.1.20") /
            UDP(sport=500, dport=500) /
            ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8, exch_type=2) /
            id_payload / hash_payload
        )
        meta = extract_ikeV1_metadata(IP(bytes(pkt)))

        self.assertIsNotNone(meta)
        mm = meta["MAIN_MODE"]
        self.assertTrue(mm["identification"]["present"])
        self.assertEqual(mm["identification"]["data"], "192.168.1.10")
        self.assertTrue(mm["authentication"]["present"])
        self.assertEqual(mm["authentication"]["method"], "pre-shared key")
        self.assertEqual(mm["authentication"]["data"], f"0x{(b'\xee' * 20).hex()}")

    def test_main_mode_auth_sig(self):
        sig_payload = ISAKMP_payload_SIG(sig=b"\x77" * 64)
        pkt = (
            IP(src="192.168.1.10", dst="192.168.1.20") /
            UDP(sport=500, dport=500) /
            ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8, exch_type=2) /
            sig_payload
        )
        meta = extract_ikeV1_metadata(IP(bytes(pkt)))

        self.assertIsNotNone(meta)
        mm = meta["MAIN_MODE"]
        self.assertTrue(mm["authentication"]["present"])
        self.assertEqual(mm["authentication"]["method"], "signature")
        self.assertEqual(mm["authentication"]["data"], f"0x{(b'\x77' * 64).hex()}")

    def test_aggressive_mode(self):
        t1 = ISAKMP_payload_Transform(
            transform_count=1,
            transform_id=1,
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
        meta = extract_ikeV1_metadata(IP(bytes(pkt)))

        self.assertIsNotNone(meta)
        self.assertEqual(meta["common"]["exchange_type"], "Aggressive Mode")
        self.assertIn("AGGRESSIVE_MODE", meta)
        agg = meta["AGGRESSIVE_MODE"]
        self.assertTrue(agg["security_association"]["present"])
        self.assertTrue(agg["key_exchange"]["present"])
        self.assertTrue(agg["nonce"]["present"])
        self.assertTrue(agg["identification"]["present"])
        self.assertEqual(agg["identification"]["data"], "10.1.1.1")

    def test_quick_mode_with_traffic_selectors(self):
        # Quick Mode: SA (proto 3 = ESP)
        t_esp = ISAKMP_payload_Transform(
            transform_count=1,
            transform_id=12,  # ESP_AES-CBC
            transforms=[
                (4, 1),  # EncapsulationMode = Tunnel
                (5, 2),  # AuthenticationAlgorithm = HMAC-SHA
                (1, 1),  # LifeType = seconds
                (2, 3600),  # LifeDuration = 3600
            ]
        )
        p_esp = ISAKMP_payload_Proposal(
            proposal=1,
            proto=3,
            SPIsize=4,
            SPI=b"\x01\x02\x03\x04",
            trans_nb=1,
            trans=t_esp
        )
        sa = ISAKMP_payload_SA(doi=1, situation=1, prop=p_esp)
        nonce = ISAKMP_payload_Nonce(nonce=b"\x99" * 16)

        # IDci (initiator subnet 192.168.10.0/24) and IDcr (responder subnet 10.0.0.0/8)
        idci = ISAKMP_payload_ID(IDtype=4, IdentData=bytes([192, 168, 10, 0, 255, 255, 255, 0]))
        idcr = ISAKMP_payload_ID(IDtype=4, IdentData=bytes([10, 0, 0, 0, 255, 0, 0, 0]))

        pkt = (
            IP(src="192.168.1.1", dst="192.168.1.2") /
            UDP(sport=500, dport=500) /
            ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8, exch_type=32, id=0x12345678) /
            sa / nonce / idci / idcr
        )
        meta = extract_ikeV1_metadata(IP(bytes(pkt)))

        self.assertIsNotNone(meta)
        self.assertEqual(meta["common"]["exchange_type"], "Quick Mode")
        self.assertEqual(meta["common"]["message_id"], 0x12345678)
        self.assertIn("QUICK_MODE", meta)

        qm = meta["QUICK_MODE"]
        self.assertTrue(qm["security_association"]["present"])
        self.assertEqual(len(qm["security_association"]["proposals"]), 1)
        prop = qm["security_association"]["proposals"][0]
        self.assertEqual(prop["protocol_id"], 3)
        self.assertEqual(prop["spi"], "0x01020304")
        self.assertEqual(prop["transforms"]["encapsulation_mode"][0]["value"], "Tunnel")

        self.assertTrue(qm["nonce"]["present"])
        self.assertEqual(len(qm["traffic_selectors"]["initiator"]), 1)
        self.assertEqual(len(qm["traffic_selectors"]["responder"]), 1)
        self.assertEqual(qm["traffic_selectors"]["initiator"][0]["data"], "192.168.10.0/255.255.255.0")
        self.assertEqual(qm["traffic_selectors"]["responder"][0]["data"], "10.0.0.0/255.0.0.0")

    def test_informational_notify_and_delete(self):
        notif = ISAKMP_payload_Notify(
            doi=1,
            proto=1,
            notify_msg_type=24578,  # INITIAL-CONTACT
            SPIsize=8,
            SPI=b"\x11" * 8,
            notify_data=b"notify_payload_data"
        )
        dele = ISAKMP_payload_Delete(
            doi=1,
            proto=3,
            SPIsize=4,
            SPIcount=2,
            SPIs=[b"\xaa\xbb\xcc\xdd", b"\x11\x22\x33\x44"]
        )
        pkt = (
            IP(src="1.1.1.1", dst="2.2.2.2") /
            UDP(sport=500, dport=500) /
            ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8, exch_type=5) /
            notif / dele
        )
        meta = extract_ikeV1_metadata(IP(bytes(pkt)))

        self.assertIsNotNone(meta)
        self.assertIn("INFORMATIONAL", meta)
        info = meta["INFORMATIONAL"]
        self.assertEqual(len(info["notify"]), 1)
        self.assertEqual(info["notify"][0]["type"], 24578)
        self.assertEqual(info["notify"][0]["type_name"], "INITIAL-CONTACT")
        self.assertEqual(info["notify"][0]["spi"], "0x1111111111111111")
        self.assertEqual(info["notify"][0]["data"], f"0x{b'notify_payload_data'.hex()}")

        self.assertEqual(len(info["delete"]), 1)
        self.assertEqual(info["delete"][0]["protocol_id"], 3)
        self.assertEqual(info["delete"][0]["spi_count"], 2)
        self.assertEqual(info["delete"][0]["spis"], ["0xaabbccdd", "0x11223344"])

        # Also verify top-level notify
        self.assertIn("notify", meta)
        self.assertTrue(meta["notify"]["present"])
        self.assertEqual(meta["notify"]["notify_types"], [24578])

    def test_certificate_extraction(self):
        # CERT payload (next_payload=6): encoding=4 (X.509 Certificate - Signature)
        cert_body = struct.pack("!B", 4) + b"MIIB..."
        raw_cert = struct.pack("!BBH", 0, 0, 4 + len(cert_body)) + cert_body
        pkt = (
            IP(src="1.1.1.1", dst="2.2.2.2") /
            UDP(sport=500, dport=500) /
            ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x02" * 8, next_payload=6, exch_type=2) /
            raw_cert
        )
        meta = extract_ikeV1_metadata(IP(bytes(pkt)))

        self.assertIsNotNone(meta)
        mm = meta["MAIN_MODE"]
        self.assertTrue(mm["certificate"]["present"])
        self.assertEqual(mm["certificate"]["encoding"], "X.509 Certificate - Signature")
        self.assertEqual(mm["certificate"]["data"], f"0x{b'MIIB...'.hex()}")

    def test_new_group_mode(self):
        t1 = ISAKMP_payload_Transform(
            transform_count=1,
            transform_id=1,
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
        meta = extract_ikeV1_metadata(IP(bytes(pkt)))
        self.assertIsNotNone(meta)
        self.assertEqual(meta["common"]["exchange_type"], "New Group Mode")
        self.assertIn("NEW_GROUP_MODE", meta)
        self.assertTrue(meta["NEW_GROUP_MODE"]["security_association"]["present"])

    def test_ipv6_and_missing_udp(self):
        pkt = (
            IPv6(src="2001:db8::1", dst="2001:db8::2") /
            UDP(sport=500, dport=500) /
            ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x00" * 8, exch_type=2)
        )
        meta = extract_ikeV1_metadata(IPv6(bytes(pkt)))
        self.assertIsNotNone(meta)
        self.assertEqual(meta["common"]["src_ip"], "2001:db8::1")
        self.assertEqual(meta["common"]["dst_ip"], "2001:db8::2")

        # Missing UDP (raw ISAKMP directly over IP)
        pkt_no_udp = (
            IP(src="10.0.0.1", dst="10.0.0.2") /
            ISAKMP(init_cookie=b"\x01" * 8, resp_cookie=b"\x00" * 8, exch_type=2)
        )
        meta_no_udp = extract_ikeV1_metadata(pkt_no_udp)
        self.assertIsNotNone(meta_no_udp)
        self.assertIsNone(meta_no_udp["common"]["src_port"])
        self.assertIsNone(meta_no_udp["common"]["dst_port"])


if __name__ == "__main__":
    unittest.main()
