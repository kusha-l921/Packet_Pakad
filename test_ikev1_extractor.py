import sys
import os
import unittest
import pyshark

from metadataExtractor import extract_ikeV1_metadata


FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_fixtures")


def load_pyshark_packet(pcap_filename):
    """Load the first packet from a pcap fixture via PyShark."""
    path = os.path.join(FIXTURE_DIR, pcap_filename)
    cap = pyshark.FileCapture(path)
    pkt = next(iter(cap))
    cap.close()
    return pkt


class TestIKEv1MetadataExtractor(unittest.TestCase):

    def test_non_isakmp_returns_none(self):
        """A packet without an isakmp layer should return None.
        We use the IKEv2 fixture (major version 2) which should be rejected by
        the IKEv1 extractor's version check."""
        pkt = load_pyshark_packet("ikev2_sa_init_notify.pcap")
        self.assertIsNone(extract_ikeV1_metadata(pkt))

    def test_main_mode_sa_multi_proposal_multi_transform(self):
        """
        Critical test: Verify that proposals[] contains exactly 2 proposal dicts,
        and each proposal contains all its transforms' attributes, avoiding the bug
        where proposal dict was created inside transform loop.
        """
        pkt = load_pyshark_packet("ikev1_main_mode_sa.pcap")
        meta = extract_ikeV1_metadata(pkt)

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
        # IKEv1 attr values are now ints from raw parsing
        self.assertEqual(prop1["transforms"]["encryption"][0]["value"], 7)   # AES-CBC
        self.assertEqual(prop1["transforms"]["encryption"][1]["value"], 5)   # 3DES-CBC
        self.assertEqual(len(prop1["transforms"]["hash"]), 2)
        self.assertEqual(prop1["transforms"]["hash"][0]["value"], 4)         # SHA2-256
        self.assertEqual(prop1["transforms"]["hash"][1]["value"], 2)         # SHA
        self.assertEqual(len(prop1["transforms"]["key_length"]), 1)
        self.assertEqual(prop1["transforms"]["key_length"][0]["value"], 256)

        # Proposal 2
        prop2 = proposals[1]
        self.assertEqual(prop2["proposal_num"], 2)
        self.assertEqual(prop2["protocol_id"], 1)
        self.assertEqual(len(prop2["transforms"]["encryption"]), 1)
        self.assertEqual(prop2["transforms"]["encryption"][0]["value"], 7)   # AES-CBC
        self.assertEqual(prop2["transforms"]["auth_method"][0]["value"], 3)  # RSA Sig

    def test_main_mode_ke_nonce(self):
        pkt = load_pyshark_packet("ikev1_main_mode_ke_nonce.pcap")
        meta = extract_ikeV1_metadata(pkt)

        self.assertIsNotNone(meta)
        mm = meta["MAIN_MODE"]
        self.assertTrue(mm["key_exchange"]["present"])
        self.assertEqual(mm["key_exchange"]["value"], f"0x{(b'\xab' * 64).hex()}")
        self.assertTrue(mm["nonce"]["present"])
        self.assertEqual(mm["nonce"]["value"], f"0x{(b'\xcd' * 32).hex()}")

    def test_main_mode_id_and_auth_hash(self):
        pkt = load_pyshark_packet("ikev1_main_mode_id_hash.pcap")
        meta = extract_ikeV1_metadata(pkt)

        self.assertIsNotNone(meta)
        mm = meta["MAIN_MODE"]
        self.assertTrue(mm["identification"]["present"])
        self.assertEqual(mm["identification"]["data"], "192.168.1.10")
        self.assertTrue(mm["authentication"]["present"])
        self.assertEqual(mm["authentication"]["method"], "pre-shared key")
        self.assertEqual(mm["authentication"]["data"], f"0x{(b'\xee' * 20).hex()}")

    def test_main_mode_auth_sig(self):
        pkt = load_pyshark_packet("ikev1_main_mode_sig.pcap")
        meta = extract_ikeV1_metadata(pkt)

        self.assertIsNotNone(meta)
        mm = meta["MAIN_MODE"]
        self.assertTrue(mm["authentication"]["present"])
        self.assertEqual(mm["authentication"]["method"], "signature")
        self.assertEqual(mm["authentication"]["data"], f"0x{(b'\x77' * 64).hex()}")

    def test_aggressive_mode(self):
        pkt = load_pyshark_packet("ikev1_aggressive.pcap")
        meta = extract_ikeV1_metadata(pkt)

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
        pkt = load_pyshark_packet("ikev1_quick_mode.pcap")
        meta = extract_ikeV1_metadata(pkt)

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
        # Encapsulation mode is attr type 4, value 1 = Tunnel
        self.assertEqual(prop["transforms"]["encapsulation_mode"][0]["value"], 1)

        self.assertTrue(qm["nonce"]["present"])
        self.assertEqual(len(qm["traffic_selectors"]["initiator"]), 1)
        self.assertEqual(len(qm["traffic_selectors"]["responder"]), 1)
        self.assertEqual(qm["traffic_selectors"]["initiator"][0]["data"], "192.168.10.0/255.255.255.0")
        self.assertEqual(qm["traffic_selectors"]["responder"][0]["data"], "10.0.0.0/255.0.0.0")

    def test_informational_notify_and_delete(self):
        pkt = load_pyshark_packet("ikev1_informational.pcap")
        meta = extract_ikeV1_metadata(pkt)

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
        pkt = load_pyshark_packet("ikev1_cert.pcap")
        meta = extract_ikeV1_metadata(pkt)

        self.assertIsNotNone(meta)
        mm = meta["MAIN_MODE"]
        self.assertTrue(mm["certificate"]["present"])
        self.assertEqual(mm["certificate"]["encoding"], "X.509 Certificate - Signature")
        self.assertEqual(mm["certificate"]["data"], f"0x{b'MIIB...'.hex()}")

    def test_new_group_mode(self):
        pkt = load_pyshark_packet("ikev1_new_group.pcap")
        meta = extract_ikeV1_metadata(pkt)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["common"]["exchange_type"], "New Group Mode")
        self.assertIn("NEW_GROUP_MODE", meta)
        self.assertTrue(meta["NEW_GROUP_MODE"]["security_association"]["present"])

    def test_ipv6_packet(self):
        pkt = load_pyshark_packet("ikev1_ipv6.pcap")
        meta = extract_ikeV1_metadata(pkt)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["common"]["src_ip"], "2001:db8::1")
        self.assertEqual(meta["common"]["dst_ip"], "2001:db8::2")


if __name__ == "__main__":
    unittest.main()
