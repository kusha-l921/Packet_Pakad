"""Unit tests for FlowSelector."""

import unittest
from rag_report_generator.src.context.flow_selector import FlowSelector


class TestFlowSelector(unittest.TestCase):
    """Test deterministic flow ranking and prioritization."""

    def setUp(self):
        self.raw_flows = [
            {
                "flow_id": "flow_low_risk_bulk",
                "risk_score": 5,
                "indicators": [],
                "bytes": 500000,
                "packets": 500,
                "duration_seconds": 10.0,
                "is_ipsec": False,
            },
            {
                "flow_id": "flow_critical_risk",
                "risk_score": 75,
                "indicators": ["UNUSUAL_HIGH_UPLOAD_VOLUME", "UNUSUAL_BURST_ACTIVITY"],
                "bytes": 1000000,
                "packets": 1200,
                "duration_seconds": 30.0,
                "is_ipsec": False,
            },
            {
                "flow_id": "flow_ipsec_proto50",
                "risk_score": 15,
                "indicators": ["PERIODIC_LOW_VOLUME_ACTIVITY"],
                "bytes": 20000,
                "packets": 50,
                "duration_seconds": 5.0,
                "is_ipsec": True,
            },
            {
                "flow_id": "flow_medium_risk",
                "risk_score": 30,
                "indicators": ["STRONG_DIRECTIONAL_ASYMMETRY"],
                "bytes": 300000,
                "packets": 300,
                "duration_seconds": 15.0,
                "is_ipsec": False,
            },
        ]

    def test_flow_selection_prioritizes_high_risk(self):
        selected = FlowSelector.select_notable_flows(self.raw_flows, max_flows=2)
        self.assertEqual(len(selected), 2)
        # First selected flow must be the critical risk flow
        self.assertEqual(selected[0].flow_id, "flow_critical_risk")
        self.assertEqual(selected[0].risk_score, 75)

    def test_flow_selection_respects_max_flows(self):
        selected = FlowSelector.select_notable_flows(self.raw_flows, max_flows=1)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].flow_id, "flow_critical_risk")

    def test_flow_selection_empty(self):
        selected = FlowSelector.select_notable_flows([], max_flows=5)
        self.assertEqual(selected, [])

    def test_parse_flow_detects_esp_5tuple(self):
        raw = {
            "flow_id": "f_esp",
            "five_tuple": {
                "src_ip": "1.1.1.1",
                "dst_ip": "2.2.2.2",
                "src_port": 0,
                "dst_port": 0,
                "protocol": "50",
            },
            "packets": 10,
            "bytes": 1000,
        }
        flow = FlowSelector.parse_flow(raw)
        self.assertTrue(flow.is_ipsec)


if __name__ == "__main__":
    unittest.main()
