"""
RogueByte WhatsApp Forensics Ultimate - Professional Standalone CLI & Terminal Engine
Brand: RogueByteOfficial
"""

import sys
import os
import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

from roguebyte_forensics.core.models import ConfidenceCategory, EvidenceSourceType
from roguebyte_forensics.acquisition.ingest import EvidenceAcquisitionEngine
from roguebyte_forensics.database.inspector import SQLiteDatabaseInspector, SQLiteWALInspector
from roguebyte_forensics.parsers.whatsapp_db import WhatsAppDatabaseParser
from roguebyte_forensics.recovery.carver import DeletedArtifactCarver
from roguebyte_forensics.timeline.engine import ForensicTimelineEngine
from roguebyte_forensics.reporting.generator import ForensicReportGenerator
from roguebyte_forensics.benchmarks.benchmark import ForensicBenchmarkRunner
from roguebyte_forensics.network.ip_analyzer import IPAddressAnalyzer
from roguebyte_forensics.network.pcap_parser import PacketAnalysisEngine
from roguebyte_forensics.network.pcap_generator import SyntheticPCAPGenerator
from roguebyte_forensics.network.whois_asn import NetworkOwnershipResolver
from roguebyte_forensics.network.correlation import NetworkCorrelationEngine
from roguebyte_forensics.network.reporting import NetworkReportGenerator


# Terminal ANSI Colors
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
DIM = "\033[2m"


def print_banner():
    banner = f"""{GREEN}{BOLD}
╔════════════════════════════════════════════════════════════════════════════════════╗
║                ROGUEBYTE WHATSAPP FORENSICS ULTIMATE (STANDALONE CLI)              ║
║                        Independent Forensic Analysis Engine                        ║
║                               Brand: RogueByteOfficial                             ║
╚════════════════════════════════════════════════════════════════════════════════════╝{RESET}
{DIM}Standard: NIST SP 800-86 | Cryptographic Integrity: SHA-256 | Non-Destructive RO Mode{RESET}
"""
    print(banner)


def cmd_analyze(args):
    print_banner()
    db_path = Path(args.database)
    if not db_path.exists():
        print(f"{RED}[!] Error: Target database file '{db_path}' does not exist.{RESET}")
        sys.exit(1)

    wal_path = Path(args.wal) if args.wal else (db_path.parent / f"{db_path.name}-wal")
    has_wal = wal_path.exists()

    output_dir = Path(args.output_dir or "./forensic_output")
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"{CYAN}[*] Initializing Forensic Acquisition...{RESET}")
    acq = EvidenceAcquisitionEngine(str(output_dir / "evidence_replicas"))
    art_db = acq.acquire_file(str(db_path), "EVID-001-DB")
    print(f"{GREEN}[+] Primary DB Acquired:{RESET} {art_db.filename}")
    print(f"    ├─ SHA-256 Digest: {BOLD}{art_db.sha256_hash}{RESET}")
    print(f"    ├─ File Size: {art_db.file_size_bytes:,} bytes")
    print(f"    └─ Write-Locked Replica: {art_db.source_path}")

    artifacts = [art_db]

    if has_wal:
        art_wal = acq.acquire_file(str(wal_path), "EVID-002-WAL")
        artifacts.append(art_wal)
        print(f"{GREEN}[+] Companion WAL Acquired:{RESET} {art_wal.filename}")
        print(f"    ├─ SHA-256 Digest: {BOLD}{art_wal.sha256_hash}{RESET}")
        print(f"    └─ File Size: {art_wal.file_size_bytes:,} bytes")

    # 1. Database Inspection
    print(f"\n{CYAN}[*] Inspecting SQLite 100-byte Binary Header...{RESET}")
    inspector = SQLiteDatabaseInspector(art_db.source_path)
    header = inspector.parse_header()
    print(f"    ├─ Page Size: {header.get('page_size', 'N/A')} bytes")
    print(f"    ├─ Write Version: {header.get('write_version')} ({'WAL Mode' if header.get('is_wal_mode') else 'Rollback Journal'})")
    print(f"    ├─ Text Encoding: {header.get('text_encoding')}")
    print(f"    ├─ Freelist Pages: {header.get('total_freelist_pages', 0)}")
    print(f"    └─ File Change Counter: {header.get('file_change_counter')}")

    integrity = inspector.run_integrity_check()
    integrity_status = f"{GREEN}PASS (OK){RESET}" if integrity["passed"] else f"{RED}FAIL ({integrity.get('error')}){RESET}"
    print(f"    └─ PRAGMA integrity_check: {integrity_status}")

    # 2. WhatsApp Parsing
    print(f"\n{CYAN}[*] Parsing WhatsApp Tables & Schema Relations...{RESET}")
    parser = WhatsAppDatabaseParser(art_db.source_path)
    messages = parser.parse_messages()
    conversations = parser.parse_conversations()
    contacts = parser.parse_contacts()

    print(f"    ├─ Active Messages Extracted: {GREEN}{len(messages)}{RESET}")
    print(f"    ├─ Discovered Conversation Channels: {GREEN}{len(conversations)}{RESET}")
    print(f"    └─ Identified Contact JIDs: {GREEN}{len(contacts)}{RESET}")

    # Print top chats
    if conversations:
        print(f"\n{YELLOW}[+] Top Identified Conversations:{RESET}")
        for c in conversations[:5]:
            grp_tag = f"{MAGENTA}[GROUP]{RESET}" if c.is_group else f"{CYAN}[DIRECT]{RESET}"
            print(f"    • {grp_tag} {BOLD}{c.display_name}{RESET} ({c.total_messages} msgs) - JID: {c.jid}")

    # 3. Deleted Artifact Carving
    print(f"\n{CYAN}[*] Executing Deleted Record Carving Engine...{RESET}")
    carver = DeletedArtifactCarver(art_db.source_path, str(wal_path) if has_wal else None)
    carved_wal = carver.scan_wal_frames() if has_wal else []
    carved_unalloc = carver.scan_sqlite_unallocated(page_size=header.get("page_size", 4096))
    all_carved = carved_wal + carved_unalloc

    print(f"    ├─ WAL Frames Inspected: {len(carved_wal)} residual candidates carved")
    print(f"    └─ B-Tree Slack & Freelist: {len(carved_unalloc)} unallocated candidates carved")

    if all_carved:
        print(f"\n{YELLOW}[+] Carved Deleted Artifacts (RogueByte Confidence Matrix):{RESET}")
        for d in all_carved[:5]:
            conf_color = GREEN if d.confidence == ConfidenceCategory.CONFIRMED else YELLOW
            print(f"    • [{conf_color}{d.confidence.value}{RESET}] Offset 0x{d.byte_offset:08X} via {d.recovery_mechanism}")
            print(f"      Payload: {d.decoded_text or '[Fragmentary Raw Hex Bytes]'}")
            print(f"      Rationale: {d.examiner_rationale}")

    # 4. Timeline
    print(f"\n{CYAN}[*] Constructing Chronological Timeline...{RESET}")
    tl_engine = ForensicTimelineEngine()
    events = tl_engine.build_timeline(messages)
    anomalies = [e for e in events if e.has_chronology_anomaly]

    print(f"    ├─ Total Correlated Events: {len(events)}")
    if anomalies:
        print(f"    └─ {RED}[!] Chronology Anomalies Detected: {len(anomalies)}{RESET}")
        for a in anomalies:
            print(f"       • {RED}Anomaly {a.event_id}:{RESET} {a.timestamp_utc} - {a.anomaly_explanation}")
    else:
        print(f"    └─ Chronology Validation: {GREEN}All timestamps conform to linear temporal sequence.{RESET}")

    # 5. Report Generation
    print(f"\n{CYAN}[*] Generating Official Forensic Reports...{RESET}")
    rep_gen = ForensicReportGenerator(
        case_id=args.case_id or "CASE-RB-CLI-01",
        case_title="Command-Line Digital Forensic Extraction",
        examiner_name=args.examiner_name or "Digital Forensic Examiner",
        examiner_id=args.examiner_id or "EX-CLI-001"
    )

    html_path = output_dir / "Forensic_Report.html"
    json_path = output_dir / "Forensic_Report.json"

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(rep_gen.generate_html_report(artifacts, messages, all_carved, events, [], parser.warnings))

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rep_gen.generate_json_report(artifacts, messages, all_carved, events, [], parser.warnings), f, indent=2)

    print(f"{GREEN}[✓] Forensic Examination Completed Successfully!{RESET}")
    print(f"    ├─ Printable HTML Report: {BOLD}{html_path.resolve()}{RESET}")
    print(f"    └─ Full JSON Dossier: {BOLD}{json_path.resolve()}{RESET}")


def cmd_benchmark(args):
    print_banner()
    print(f"{CYAN}[*] Running Controlled Synthetic Ground-Truth Benchmark...{RESET}")
    runner = ForensicBenchmarkRunner()
    res = runner.run_benchmark()

    print(f"\n{GREEN}{BOLD}════════════════════ BENCHMARK RESULTS ════════════════════{RESET}")
    print(f"  Benchmark Suite: {res['benchmark_name']}")
    print(f"  Execution Time:  {BOLD}{res['execution_duration_ms']} ms{RESET}")
    print(f"  Status:          {GREEN if res['status'] == 'PASS' else RED}{res['status']}{RESET}")
    print(f"\n  {BOLD}Forensic Accuracy Metrics:{RESET}")
    metrics = res["metrics"]
    print(f"    • Active Message Precision: {GREEN}{metrics['active_message_precision']}%{RESET}")
    print(f"    • Active Message Recall:    {GREEN}{metrics['active_message_recall']}%{RESET}")
    print(f"    • False Positive Rate:      {GREEN}{metrics['false_positive_rate']}%{RESET}")
    print(f"    • SQLite DB Integrity:      {GREEN}{'PASS' if metrics['database_integrity_passed'] else 'FAIL'}{RESET}")
    print(f"    • Anomaly Detection Rate:   {GREEN}{metrics['chronology_anomaly_detection_rate']}%{RESET}")
    print(f"    • Cryptographic Integrity:  {GREEN}{metrics['cryptographic_integrity_verification']}{RESET}")
    print(f"    • Carved Slack Records:     {GREEN}{metrics['carved_slack_candidates_found']} Records Carved{RESET}")
    print(f"{GREEN}{BOLD}═══════════════════════════════════════════════════════════{RESET}\n")


def cmd_carve(args):
    print_banner()
    db_path = Path(args.database)
    wal_path = Path(args.wal) if args.wal else (db_path.parent / f"{db_path.name}-wal")
    has_wal = wal_path.exists()

    print(f"{CYAN}[*] Scanning unallocated B-tree leaf gaps and WAL frames...{RESET}")
    carver = DeletedArtifactCarver(str(db_path), str(wal_path) if has_wal else None)
    candidates = carver.scan_sqlite_unallocated() + (carver.scan_wal_frames() if has_wal else [])

    print(f"{GREEN}[+] Carved {len(candidates)} deleted artifact candidate(s):{RESET}\n")
    for idx, c in enumerate(candidates, 1):
        print(f"[{idx}] Candidate: {BOLD}{c.candidate_id}{RESET} | Status: {YELLOW}{c.confidence.value}{RESET}")
        print(f"    Offset: 0x{c.byte_offset:08X} | Source: {c.source_file} | Mechanism: {c.recovery_mechanism}")
        print(f"    Payload: {c.decoded_text or '[Raw Hex Payload]'}")
        print(f"    Rationale: {c.examiner_rationale}\n")


def cmd_pcap(args):
    print_banner()
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        print(f"{RED}[!] Error: Capture file '{pcap_path}' not found.{RESET}")
        sys.exit(1)

    output_dir = Path(args.output_dir or "./forensic_output")
    output_dir.mkdir(parents=True, exist_ok=True)

    sha256 = EvidenceAcquisitionEngine.calculate_sha256(str(pcap_path))
    print(f"{CYAN}[*] Ingesting Network Capture File...{RESET}")
    print(f"    File:     {pcap_path.name}")
    print(f"    Size:     {pcap_path.stat().st_size:,} bytes")
    print(f"    SHA-256:  {BOLD}{sha256}{RESET}")

    engine = PacketAnalysisEngine(str(pcap_path))
    summary = engine.parse()

    if not summary.get("valid"):
        print(f"{RED}[!] Error parsing capture: {summary.get('error')}{RESET}")
        return

    print(f"\n{GREEN}[+] Capture Inspection Completed:{RESET}")
    print(f"    ├─ Capture Format:              {BOLD}{summary['capture_format']}{RESET}")
    print(f"    ├─ Total Packets Analyzed:       {summary['total_packets']}")
    print(f"    ├─ Total Wire Volume:           {summary['total_bytes']:,} bytes")
    print(f"    ├─ Unique Network Flows:        {summary['unique_flows_reconstructed']}")
    print(f"    ├─ DNS Queries / Resolutions:   {summary['dns_queries_extracted']}")
    print(f"    ├─ Distinct IP Addresses:       {summary['unique_ip_addresses']}")
    print(f"    │   ├─ Public Internet IPs:     {summary['public_ips_count']}")
    print(f"    │   └─ Private/Local IPs:       {summary['private_ips_count']}")
    print(f"    └─ Incomplete/Truncated Status: {'YES (Truncated)' if summary['is_truncated'] else 'NO (Intact)'}")

    # Top Public IPs & ASN Ownership
    public_ips = engine.ip_analyzer.get_public_ips()
    if public_ips:
        print(f"\n{YELLOW}[+] Identified Public IP Endpoints & ASN Ownership:{RESET}")
        for ip in public_ips[:8]:
            asn_tag = f"AS{ip.asn_info.asn} {ip.asn_info.organization}" if ip.asn_info else "Unknown AS"
            geo_tag = f"{ip.geolocation.city}, {ip.geolocation.country}" if (ip.geolocation and ip.geolocation.city) else (ip.geolocation.country if ip.geolocation else "Unknown Geo")
            meta_tag = f" {GREEN}[META/WHATSAPP INFRASTRUCTURE]{RESET}" if (ip.asn_info and ip.asn_info.is_meta_infrastructure) else ""
            print(f"    • {BOLD}{ip.ip_address}{RESET} ({ip.address_family}) - {asn_tag} [{geo_tag}]{meta_tag}")

    # DNS Queries
    if engine.dns_records:
        print(f"\n{CYAN}[+] Extracted DNS Transactions:{RESET}")
        for d in engine.dns_records[:6]:
            answers = ", ".join(d.response_ips) if d.response_ips else "No IP Answer"
            print(f"    • Query #{d.query_id}: {BOLD}{d.query_name}{RESET} -> [{answers}] ({d.response_code})")

    # Generate Report
    rep_gen = NetworkReportGenerator(
        case_id="RB-NET-01",
        examiner_name="Special Agent",
        examiner_id="EX-NET-001"
    )
    html_rep = rep_gen.generate_html_report(
        pcap_file=pcap_path.name,
        pcap_sha256=sha256,
        ip_records=list(engine.ip_analyzer.records.values()),
        flows=list(engine.flows.values()),
        dns_records=engine.dns_records,
        call_correlations=[],
        message_correlations=[]
    )
    rep_path = output_dir / "Network_Forensic_Report.html"
    with open(rep_path, "w", encoding="utf-8") as f:
        f.write(html_rep)
    print(f"\n{GREEN}[✓] Report Generated:{RESET} {rep_path.resolve()}\n")


def cmd_lookup_ip(ip_str: str):
    print_banner()
    print(f"{CYAN}[*] Performing Authoritative ASN & Geolocation Lookup for: {BOLD}{ip_str}{RESET}")
    classification, family = IPAddressAnalyzer.classify_ip(ip_str)
    if not classification:
        print(f"{RED}[!] Error: Invalid IP address format '{ip_str}'{RESET}")
        return

    asn = NetworkOwnershipResolver.lookup_asn(ip_str)
    geo = NetworkOwnershipResolver.lookup_geolocation(ip_str)
    rep = NetworkOwnershipResolver.check_reputation(ip_str)

    print(f"\n{GREEN}[+] IP Forensic Dossier:{RESET}")
    print(f"    Address:        {BOLD}{ip_str}{RESET} ({family})")
    print(f"    Classification: {BOLD}{classification.value}{RESET}")
    if asn:
        print(f"    ASN:            AS{asn.asn} ({asn.as_name})")
        print(f"    Organization:   {asn.organization}")
        print(f"    Country:        {asn.country_code}")
        print(f"    Prefix / CIDR:  {asn.cidr_prefix}")
        print(f"    Meta Edge:      {'YES (Meta Infrastructure)' if asn.is_meta_infrastructure else 'NO'}")
    if geo:
        print(f"    Estimated Geo:  {geo.city or 'N/A'}, {geo.region or 'N/A'}, {geo.country}")
        print(f"    Geo Disclaimer: {DIM}{geo.disclaimer}{RESET}")
    if rep:
        print(f"    Threat Intel:   Score {rep.threat_score}/100 ({', '.join(rep.categories) or 'Clean'})")
    print(f"    Attribution:    {DIM}IP address reflects network endpoint, not verified personal identity without carrier subpoena.{RESET}\n")


def cmd_correlate(args):
    print_banner()
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        print(f"{RED}[!] Error: Capture file '{pcap_path}' not found.{RESET}")
        sys.exit(1)

    db_path = Path(args.database)
    if not db_path.exists():
        print(f"{RED}[!] Error: Target database file '{db_path}' does not exist.{RESET}")
        sys.exit(1)

    print(f"{CYAN}[*] Parsing Network Packet Capture ({pcap_path.name})...{RESET}")
    pcap_engine = PacketAnalysisEngine(str(pcap_path))
    pcap_summary = pcap_engine.parse()
    if not pcap_summary.get("valid"):
        print(f"{RED}[!] Error parsing PCAP: {pcap_summary.get('error')}{RESET}")
        return

    print(f"{CYAN}[*] Parsing WhatsApp Database ({db_path.name})...{RESET}")
    db_parser = WhatsAppDatabaseParser(str(db_path))
    messages = db_parser.parse_messages()
    conversations = db_parser.parse_conversations()

    print(f"    ├─ Packets Analyzed: {pcap_summary['total_packets']}")
    print(f"    ├─ Reconstructed Flows: {pcap_summary['unique_flows_reconstructed']}")
    print(f"    ├─ WhatsApp Messages: {len(messages)}")
    print(f"    └─ WhatsApp Conversations: {len(conversations)}")

    print(f"\n{CYAN}[*] Correlating Chronological Network Events with WhatsApp Database...{RESET}")
    correlator = NetworkCorrelationEngine(list(pcap_engine.flows.values()), pcap_engine.ip_analyzer.records)

    msg_correlations = []
    for msg in messages[:20]:
        corr = correlator.correlate_message(msg)
        if corr.candidate_flows:
            msg_correlations.append(corr)

    print(f"{GREEN}[+] Correlation Results:{RESET}")
    print(f"    ├─ Correlated Message Windows: {len(msg_correlations)}")
    for mc in msg_correlations[:5]:
        print(f"    • Msg {BOLD}{mc.message_id}{RESET} [{mc.message_timestamp_utc}] ({mc.confidence_level})")
        print(f"      Matched Flows: {len(mc.candidate_flows)} | Observed IPs: {', '.join(ip.ip_address for ip in mc.observed_endpoints)}")
        print(f"      Disclaimer: {DIM}{mc.attribution_disclaimer}{RESET}")

    output_dir = Path(args.output_dir or "./forensic_output")
    output_dir.mkdir(parents=True, exist_ok=True)
    rep_gen = NetworkReportGenerator(case_id="RB-CORR-01", examiner_name="Forensic Analyst", examiner_id="EX-001")
    sha256 = EvidenceAcquisitionEngine.calculate_sha256(str(pcap_path))
    rep_html = rep_gen.generate_html_report(
        pcap_file=pcap_path.name,
        pcap_sha256=sha256,
        ip_records=list(pcap_engine.ip_analyzer.records.values()),
        flows=list(pcap_engine.flows.values()),
        dns_records=pcap_engine.dns_records,
        call_correlations=[],
        message_correlations=msg_correlations
    )
    rep_path = output_dir / "Correlation_Forensic_Report.html"
    with open(rep_path, "w", encoding="utf-8") as f:
        f.write(rep_html)
    print(f"\n{GREEN}[✓] Correlation Report Generated:{RESET} {rep_path.resolve()}\n")


def cmd_serve(args):
    print_banner()
    port = getattr(args, "port", 3000) or 3000
    print(f"{CYAN}[*] Launching RogueByte Offline Forensic Desktop Workstation on port {port}...{RESET}")
    print(f"{GREEN}[✓] Forensic Workstation Active:{RESET} http://localhost:{port}")
    print(f"{DIM}Press Ctrl+C to terminate the local server session.{RESET}\n")
    import subprocess
    try:
        subprocess.run(["npm", "run", "dev"], check=True)
    except KeyboardInterrupt:
        print("\nWorkstation stopped.")


def cmd_verify(filepath: str):
    p = Path(filepath)
    if not p.exists():
        print(f"{RED}[!] Error: File '{filepath}' not found.{RESET}")
        return
    sha256 = EvidenceAcquisitionEngine.calculate_sha256(str(p))
    print(f"\n{GREEN}[✓] Cryptographic Hash Computed:{RESET}")
    print(f"    File:     {p.name}")
    print(f"    Size:     {p.stat().st_size:,} bytes")
    print(f"    SHA-256:  {BOLD}{sha256}{RESET}\n")


def cmd_interactive():
    print_banner()
    while True:
        print(f"{CYAN}{BOLD}Select an Investigation Task:{RESET}")
        print("  [1] Full WhatsApp Database Analysis & Report Generation")
        print("  [2] Carve Deleted Records (WAL Frames & Unallocated Slack)")
        print("  [3] Network Packet Capture Forensics (PCAP / PCAPNG Analysis)")
        print("  [4] Correlate WhatsApp Activity with Network Packet Capture")
        print("  [5] Authoritative IP Address Intelligence Lookup (ASN & Geo)")
        print("  [6] Run Controlled Synthetic Ground-Truth Benchmark")
        print("  [7] Verify Cryptographic SHA-256 Hash of Evidence")
        print("  [8] Launch RogueByte Desktop Workstation GUI (Local Server)")
        print("  [9] Exit\n")

        try:
            choice = input(f"{YELLOW}RogueByte [1-9] > {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if choice == "1":
            db = input(f"{CYAN}Enter path to msgstore.db (or press Enter for test DB): {RESET}").strip()
            if not db:
                runner = ForensicBenchmarkRunner("/tmp/interactive_test")
                db, _ = runner.generate_synthetic_ground_truth_db()
                print(f"{DIM}Generated synthetic test database at {db}{RESET}")
            class Args:
                database = db
                wal = None
                output_dir = "./forensic_output"
                case_id = "RB-INTERACTIVE-01"
                examiner_name = "Lead Examiner"
                examiner_id = "EX-001"
            cmd_analyze(Args())
            input(f"\n{DIM}Press Enter to return to menu...{RESET}")
            print("\n")
        elif choice == "2":
            db = input(f"{CYAN}Enter path to msgstore.db (or press Enter for test DB): {RESET}").strip()
            if not db:
                runner = ForensicBenchmarkRunner("/tmp/interactive_test")
                db, _ = runner.generate_synthetic_ground_truth_db()
            class Args:
                database = db
                wal = None
            cmd_carve(Args())
            input(f"\n{DIM}Press Enter to return to menu...{RESET}")
            print("\n")
        elif choice == "3":
            pcap = input(f"{CYAN}Enter path to PCAP/PCAPNG file (or press Enter for test PCAP): {RESET}").strip()
            if not pcap:
                pcap = "/tmp/interactive_pcap/test_capture.pcap"
                SyntheticPCAPGenerator.create_test_pcap(pcap)
                print(f"{DIM}Generated synthetic test PCAP at {pcap}{RESET}")
            class PcapArgs:
                pcap_file = pcap
                output_dir = "./forensic_output"
            cmd_pcap(PcapArgs())
            input(f"\n{DIM}Press Enter to return to menu...{RESET}")
            print("\n")
        elif choice == "4":
            pcap = input(f"{CYAN}Enter path to PCAP file (or press Enter for test PCAP): {RESET}").strip()
            if not pcap:
                pcap = "/tmp/interactive_pcap/test_capture.pcap"
                SyntheticPCAPGenerator.create_test_pcap(pcap)
            db = input(f"{CYAN}Enter path to msgstore.db (or press Enter for test DB): {RESET}").strip()
            if not db:
                runner = ForensicBenchmarkRunner("/tmp/interactive_test")
                db, _ = runner.generate_synthetic_ground_truth_db()
            class CorrArgs:
                pcap_file = pcap
                database = db
                output_dir = "./forensic_output"
            cmd_correlate(CorrArgs())
            input(f"\n{DIM}Press Enter to return to menu...{RESET}")
            print("\n")
        elif choice == "5":
            ip_str = input(f"{CYAN}Enter IP address (e.g., 157.240.22.35): {RESET}").strip()
            if ip_str:
                cmd_lookup_ip(ip_str)
            input(f"\n{DIM}Press Enter to return to menu...{RESET}")
            print("\n")
        elif choice == "6":
            cmd_benchmark(None)
            input(f"\n{DIM}Press Enter to return to menu...{RESET}")
            print("\n")
        elif choice == "7":
            path = input(f"{CYAN}Enter file path to hash: {RESET}").strip()
            if path:
                cmd_verify(path)
            input(f"\n{DIM}Press Enter to return to menu...{RESET}")
            print("\n")
        elif choice == "8":
            class ServeArgs:
                port = 3000
            cmd_serve(ServeArgs())
        elif choice in ("9", "q", "exit"):
            print("Session closed.")
            break
        else:
            print(f"{RED}Invalid option.{RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="RogueByte WhatsApp Forensics Ultimate v2.0 - Standalone Terminal Suite"
    )
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive menu mode")
    subparsers = parser.add_subparsers(dest="command", help="Available forensic commands")

    # Command: analyze
    p_analyze = subparsers.add_parser("analyze", help="Perform full forensic examination of WhatsApp msgstore.db")
    p_analyze.add_argument("database", help="Path to SQLite msgstore.db")
    p_analyze.add_argument("--wal", help="Path to msgstore.db-wal (optional, auto-detected if in same dir)")
    p_analyze.add_argument("--output-dir", default="./forensic_output", help="Directory for working copies and reports")
    p_analyze.add_argument("--case-id", default="RB-2026-001", help="Case reference identifier")
    p_analyze.add_argument("--examiner-name", default="Special Agent", help="Examiner full name")
    p_analyze.add_argument("--examiner-id", default="EX-001", help="Examiner badge ID")

    # Command: carve
    p_carve = subparsers.add_parser("carve", help="Carve deleted records from unallocated space & WAL frames")
    p_carve.add_argument("database", help="Path to SQLite msgstore.db")
    p_carve.add_argument("--wal", help="Path to companion WAL file")

    # Command: pcap / analyze-pcap
    p_pcap = subparsers.add_parser("pcap", help="Analyze network traffic capture (PCAP / PCAPNG)")
    p_pcap.add_argument("pcap_file", help="Path to PCAP or PCAPNG capture file")
    p_pcap.add_argument("--output-dir", default="./forensic_output", help="Directory for network reports")

    # Command: correlate
    p_corr = subparsers.add_parser("correlate", help="Correlate WhatsApp database activity with PCAP network capture")
    p_corr.add_argument("--pcap", dest="pcap_file", required=True, help="Path to PCAP capture file")
    p_corr.add_argument("--database", dest="database", required=True, help="Path to SQLite msgstore.db")
    p_corr.add_argument("--output-dir", default="./forensic_output", help="Directory for correlation reports")

    # Command: ip / lookup-ip
    p_ip = subparsers.add_parser("lookup-ip", help="Lookup ASN, organization, and geolocation for IP address")
    p_ip.add_argument("ip_address", help="IPv4 or IPv6 address")

    # Command: benchmark
    subparsers.add_parser("benchmark", help="Run automated synthetic ground-truth benchmark suite")

    # Command: verify
    p_verify = subparsers.add_parser("verify", help="Verify SHA-256 hash of evidence file")
    p_verify.add_argument("filepath", help="Path to evidence file")

    # Command: serve / gui
    p_gui = subparsers.add_parser("gui", help="Launch RogueByte offline desktop workstation web interface")
    p_gui.add_argument("--port", type=int, default=3000, help="Port to serve workstation (default: 3000)")

    args = parser.parse_args()

    if args.interactive:
        cmd_interactive()
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "carve":
        cmd_carve(args)
    elif args.command == "pcap":
        cmd_pcap(args)
    elif args.command == "correlate":
        cmd_correlate(args)
    elif args.command == "lookup-ip":
        cmd_lookup_ip(args.ip_address)
    elif args.command == "benchmark":
        cmd_benchmark(args)
    elif args.command == "verify":
        cmd_verify(args.filepath)
    elif args.command == "gui":
        cmd_serve(args)
    else:
        if sys.stdin.isatty():
            cmd_interactive()
        else:
            print_banner()
            parser.print_help()


if __name__ == "__main__":
    main()
