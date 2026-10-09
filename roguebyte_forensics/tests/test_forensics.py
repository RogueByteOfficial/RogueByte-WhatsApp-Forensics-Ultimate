"""
RogueByte WhatsApp Forensics Ultimate - Automated Unit & Integration Tests
Author: RogueByteOfficial
"""

import unittest
import os
import shutil
import tempfile
from pathlib import Path

from roguebyte_forensics.acquisition.ingest import EvidenceAcquisitionEngine
from roguebyte_forensics.integrity.audit import ChainOfCustodyAuditManager
from roguebyte_forensics.database.inspector import SQLiteDatabaseInspector
from roguebyte_forensics.parsers.whatsapp_db import WhatsAppDatabaseParser
from roguebyte_forensics.recovery.carver import DeletedArtifactCarver
from roguebyte_forensics.timeline.engine import ForensicTimelineEngine
from roguebyte_forensics.reporting.generator import ForensicReportGenerator
from roguebyte_forensics.benchmarks.benchmark import ForensicBenchmarkRunner


class TestRogueByteForensics(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="rb_test_")
        self.runner = ForensicBenchmarkRunner(work_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_acquisition_and_hashing(self):
        # Create a sample file
        dummy_file = Path(self.test_dir) / "sample.db"
        with open(dummy_file, "wb") as f:
            f.write(b"SQLite format 3\x00" + b"\x00" * 84)

        acq = EvidenceAcquisitionEngine(str(Path(self.test_dir) / "evidence"))
        artifact = acq.acquire_file(str(dummy_file), "EVID-TEST-001")

        self.assertEqual(artifact.evidence_id, "EVID-TEST-001")
        self.assertTrue(len(artifact.sha256_hash) == 64)
        self.assertTrue(artifact.is_read_only)
        self.assertIn("SQLite 3 Database", artifact.metadata["format_description"])

    def test_02_database_header_and_integrity(self):
        db_path, truth = self.runner.generate_synthetic_ground_truth_db()
        inspector = SQLiteDatabaseInspector(db_path)
        header = inspector.parse_header()

        self.assertTrue(header["valid"])
        self.assertEqual(header["page_size"], 4096)
        self.assertEqual(header["text_encoding"], "UTF-8")

        integrity = inspector.run_integrity_check()
        self.assertTrue(integrity["passed"])
        self.assertEqual(integrity["foreign_key_violations"], [])

    def test_03_whatsapp_parsing(self):
        db_path, truth = self.runner.generate_synthetic_ground_truth_db()
        parser = WhatsAppDatabaseParser(db_path)
        messages = parser.parse_messages()
        chats = parser.parse_conversations()

        self.assertEqual(len(messages), truth["expected_active_messages"])
        self.assertEqual(len(chats), truth["expected_chats"])
        self.assertTrue(any("suspect" in c.display_name.lower() for c in chats))

    def test_04_timeline_anomaly_detection(self):
        db_path, truth = self.runner.generate_synthetic_ground_truth_db()
        parser = WhatsAppDatabaseParser(db_path)
        messages = parser.parse_messages()

        engine = ForensicTimelineEngine()
        events = engine.build_timeline(messages, acquisition_time_ms=1710000000000)

        anomalies = [e for e in events if e.has_chronology_anomaly]
        self.assertEqual(len(anomalies), 1)
        self.assertIn("future relative to acquisition", anomalies[0].anomaly_explanation)

    def test_05_deleted_carver(self):
        db_path, truth = self.runner.generate_synthetic_ground_truth_db()
        carver = DeletedArtifactCarver(db_path)
        carved = carver.scan_sqlite_unallocated(page_size=4096)

        # Unallocated carver should find remnants of the deleted records
        self.assertGreater(len(carved), 0)
        # Verify confidence matrix is respected
        for c in carved:
            self.assertIn(c.confidence.value, ["CONFIRMED", "PARTIAL", "INFERRED", "UNVERIFIED", "UNRECOVERABLE"])
            self.assertIsNotNone(c.byte_offset)

    def test_06_audit_and_report_generation(self):
        db_path, truth = self.runner.generate_synthetic_ground_truth_db()
        audit_path = Path(self.test_dir) / "audit.json"
        audit = ChainOfCustodyAuditManager(str(audit_path))
        audit.record_action("ACQUISITION_IMPORT", "Acquired test evidence", "EXAMINER-99", "EVID-01")

        report_gen = ForensicReportGenerator(
            case_id="RB-TEST-001",
            case_title="Synthetic Benchmark Test",
            examiner_name="Special Agent J. Vance",
            examiner_id="EX-9912"
        )

        parser = WhatsAppDatabaseParser(db_path)
        messages = parser.parse_messages()
        carver = DeletedArtifactCarver(db_path)
        carved = carver.scan_sqlite_unallocated()
        engine = ForensicTimelineEngine()
        events = engine.build_timeline(messages)

        acq = EvidenceAcquisitionEngine(str(Path(self.test_dir) / "evidence"))
        artifact = acq.acquire_file(db_path, "EVID-01")

        html_rep = report_gen.generate_html_report([artifact], messages, carved, events, audit.entries, [])
        self.assertIn("ROGUEBYTE DIGITAL FORENSIC EXAMINATION REPORT", html_rep)
        self.assertIn("RB-TEST-001", html_rep)

    def test_07_full_benchmark_suite(self):
        benchmark_results = self.runner.run_benchmark()
        self.assertEqual(benchmark_results["status"], "PASS")
        self.assertEqual(benchmark_results["metrics"]["active_message_precision"], 100.0)
        self.assertEqual(benchmark_results["metrics"]["active_message_recall"], 100.0)


if __name__ == "__main__":
    unittest.main()
