"""
RogueByte WhatsApp Forensics Ultimate v2.0 - Network Forensics Test Suite
Brand: RogueByteOfficial
"""

import unittest
import tempfile
import shutil
from pathlib import Path

from roguebyte_forensics.network.models import IPClassification, CallCorrelationClass
from roguebyte_forensics.network.ip_analyzer import IPAddressAnalyzer
from roguebyte_forensics.network.whois_asn import NetworkOwnershipResolver
from roguebyte_forensics.network.pcap_parser import PacketAnalysisEngine
from roguebyte_forensics.network.pcap_generator import SyntheticPCAPGenerator
from roguebyte_forensics.network.correlation import NetworkCorrelationEngine
from roguebyte_forensics.core.models import MessageRecord, MessageType


class TestNetworkForensics(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="rb_net_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_ip_classification(self):
        analyzer = IPAddressAnalyzer()

        # Public IPv4 & IPv6
        rec1 = analyzer.ingest_ip("157.240.22.35", "test.log")
        self.assertIsNotNone(rec1)
        self.assertEqual(rec1.classification, IPClassification.PUBLIC)
        self.assertEqual(rec1.address_family, "IPv4")

        rec2 = analyzer.ingest_ip("2a03:2880:f10c:83:face:b00c:0:25de", "test.log")
        self.assertIsNotNone(rec2)
        self.assertEqual(rec2.classification, IPClassification.PUBLIC)
        self.assertEqual(rec2.address_family, "IPv6")

        # Private IPv4
        rec3 = analyzer.ingest_ip("192.168.1.100", "test.log")
        self.assertEqual(rec3.classification, IPClassification.PRIVATE)

        rec4 = analyzer.ingest_ip("10.0.0.1", "test.log")
        self.assertEqual(rec4.classification, IPClassification.PRIVATE)

        # Loopback & Link-local
        rec5 = analyzer.ingest_ip("127.0.0.1", "test.log")
        self.assertEqual(rec5.classification, IPClassification.LOOPBACK)

        rec6 = analyzer.ingest_ip("169.254.1.20", "test.log")
        self.assertEqual(rec6.classification, IPClassification.LINK_LOCAL)

        # Multicast
        rec7 = analyzer.ingest_ip("224.0.0.251", "test.log")
        self.assertEqual(rec7.classification, IPClassification.MULTICAST)

        # Invalid IP rejected
        rec_invalid = analyzer.ingest_ip("999.999.999.999", "test.log")
        self.assertIsNone(rec_invalid)

    def test_02_asn_ownership_lookup(self):
        # Meta Platforms / WhatsApp
        asn_meta = NetworkOwnershipResolver.lookup_asn("157.240.22.35")
        self.assertIsNotNone(asn_meta)
        self.assertEqual(asn_meta.asn, 32934)
        self.assertTrue(asn_meta.is_meta_infrastructure)
        self.assertIn("Meta Platforms", asn_meta.organization)

        # Cloudflare
        asn_cf = NetworkOwnershipResolver.lookup_asn("1.1.1.1")
        self.assertIsNotNone(asn_cf)
        self.assertEqual(asn_cf.asn, 13335)

        # Private IP returns AS0
        asn_priv = NetworkOwnershipResolver.lookup_asn("192.168.1.1")
        self.assertEqual(asn_priv.asn, 0)
        self.assertEqual(asn_priv.as_name, "NON_ROUTABLE")

    def test_03_pcap_parsing_synthetic(self):
        pcap_path = str(Path(self.test_dir) / "capture.pcap")
        SyntheticPCAPGenerator.create_test_pcap(pcap_path, base_epoch=1773440400.0)

        parser = PacketAnalysisEngine(pcap_path)
        summary = parser.parse()

        self.assertTrue(summary["valid"])
        self.assertEqual(summary["capture_format"], "Classic PCAP")
        self.assertEqual(summary["total_packets"], 6)
        self.assertGreater(summary["unique_flows_reconstructed"], 0)
        self.assertEqual(summary["dns_queries_extracted"], 1)

        # Verify DNS extraction
        dns = parser.dns_records[0]
        self.assertEqual(dns.query_name, "e1.whatsapp.net")
        self.assertIn("157.240.22.35", dns.response_ips)

        # Verify public vs private IP extraction
        public_ips = [r.ip_address for r in parser.ip_analyzer.get_public_ips()]
        self.assertIn("157.240.22.35", public_ips)
        self.assertIn("31.13.86.36", public_ips)
        self.assertIn("195.186.210.88", public_ips)

    def test_04_call_network_correlation(self):
        pcap_path = str(Path(self.test_dir) / "capture.pcap")
        base_epoch = 1773440400.0
        SyntheticPCAPGenerator.create_test_pcap(pcap_path, base_epoch=base_epoch)

        parser = PacketAnalysisEngine(pcap_path)
        parser.parse()

        correlator = NetworkCorrelationEngine(list(parser.flows.values()), parser.ip_analyzer.records)

        # Test Case 1: Call occurring during the STUN packet (epoch 1773440400 + 120s)
        call_corr = correlator.correlate_call(
            call_id="CALL-001",
            participant_jid="12065550843@s.whatsapp.net",
            start_epoch=base_epoch + 115.0,
            end_epoch=base_epoch + 125.0,
            call_type="voice"
        )

        self.assertGreater(len(call_corr.candidate_flows), 0)
        # Verify strict disclaimer is attached
        self.assertIn("STUN/TURN relays", call_corr.attribution_disclaimer)
        self.assertIn("does NOT establish that an observed IP address belongs directly to the remote participant", call_corr.attribution_disclaimer)

        # Test Case 2: Call occurring in a window with zero network traffic -> INSUFFICIENT_EVIDENCE
        empty_call = correlator.correlate_call(
            call_id="CALL-EMPTY",
            participant_jid="14155550192@s.whatsapp.net",
            start_epoch=base_epoch + 9999.0,
            end_epoch=base_epoch + 10050.0,
            call_type="video"
        )
        self.assertEqual(empty_call.classification, CallCorrelationClass.INSUFFICIENT_EVIDENCE)
        self.assertEqual(len(empty_call.candidate_flows), 0)

    def test_05_message_network_correlation(self):
        pcap_path = str(Path(self.test_dir) / "capture.pcap")
        base_epoch = 1773440400.0
        SyntheticPCAPGenerator.create_test_pcap(pcap_path, base_epoch=base_epoch)

        parser = PacketAnalysisEngine(pcap_path)
        parser.parse()

        correlator = NetworkCorrelationEngine(list(parser.flows.values()), parser.ip_analyzer.records)

        # Message matching TCP SYN at base_epoch + 1.0
        msg = MessageRecord(
            message_id="3EB0TESTMSG01",
            remote_jid="12065550843@s.whatsapp.net",
            sender_jid="Examiner/Account Owner",
            is_from_me=True,
            timestamp_ms=int((base_epoch + 1.0) * 1000),
            timestamp_utc="2026-03-13 22:20:01.000 UTC",
            text_content="Correlated test transmission"
        )

        msg_corr = correlator.correlate_message(msg)
        self.assertGreater(len(msg_corr.candidate_flows), 0)
        self.assertEqual(msg_corr.confidence_level, "HIGH_TEMPORAL_ALIGNMENT")
        self.assertIn("centralized Meta edge infrastructure", msg_corr.attribution_disclaimer)


if __name__ == "__main__":
    unittest.main()
