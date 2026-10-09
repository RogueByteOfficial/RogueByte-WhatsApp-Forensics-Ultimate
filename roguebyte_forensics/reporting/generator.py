"""
RogueByte WhatsApp Forensics Ultimate - Professional Forensic Report Generator
Author: RogueByteOfficial
"""

import json
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from roguebyte_forensics.core.models import (
    EvidenceArtifact,
    MessageRecord,
    DeletedCandidate,
    TimelineEvent,
    AuditLogEntry
)


class ForensicReportGenerator:
    def __init__(
        self,
        case_id: str,
        case_title: str,
        examiner_name: str,
        examiner_id: str,
        agency_name: str = "Digital Forensics & Incident Response Laboratory"
    ):
        self.case_id = case_id
        self.case_title = case_title
        self.examiner_name = examiner_name
        self.examiner_id = examiner_id
        self.agency_name = agency_name
        self.tool_version = "RogueByte WhatsApp Forensics Ultimate v2.5"

    def generate_json_report(
        self,
        artifacts: List[EvidenceArtifact],
        messages: List[MessageRecord],
        deleted_candidates: List[DeletedCandidate],
        timeline_events: List[TimelineEvent],
        audit_entries: List[AuditLogEntry],
        warnings: List[str]
    ) -> Dict[str, Any]:
        return {
            "forensic_report_header": {
                "case_id": self.case_id,
                "case_title": self.case_title,
                "examiner_name": self.examiner_name,
                "examiner_id": self.examiner_id,
                "agency": self.agency_name,
                "tool": self.tool_version,
                "generation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "methodology": "Read-only evidence acquisition, SHA-256 verification, WAL frame inspection, SQLite B-Tree unallocated slack space carving."
            },
            "evidence_inventory": [
                {
                    "evidence_id": a.evidence_id,
                    "filename": a.filename,
                    "size_bytes": a.file_size_bytes,
                    "sha256": a.sha256_hash,
                    "type": a.source_type.value,
                    "acquired_utc": a.import_timestamp_utc
                }
                for a in artifacts
            ],
            "metrics_summary": {
                "total_artifacts_ingested": len(artifacts),
                "total_active_messages_parsed": len(messages),
                "total_deleted_candidates_carved": len(deleted_candidates),
                "total_timeline_events": len(timeline_events),
                "chronology_anomalies_detected": sum(1 for e in timeline_events if e.has_chronology_anomaly)
            },
            "parser_warnings_and_limitations": warnings,
            "chain_of_custody_audit_trail": [a.__dict__ for a in audit_entries],
            "deleted_artifacts_classification": [d.__dict__ for d in deleted_candidates],
            "messages_sample": [m.__dict__ for m in messages[:100]]
        }

    def generate_html_report(
        self,
        artifacts: List[EvidenceArtifact],
        messages: List[MessageRecord],
        deleted_candidates: List[DeletedCandidate],
        timeline_events: List[TimelineEvent],
        audit_entries: List[AuditLogEntry],
        warnings: List[str]
    ) -> str:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        artifacts_rows = "".join(f"""
        <tr>
            <td style="font-family: monospace; font-size: 11px;">{a.evidence_id}</td>
            <td><strong>{a.filename}</strong></td>
            <td>{a.file_size_bytes:,} B</td>
            <td style="font-family: monospace; font-size: 11px; word-break: break-all;">{a.sha256_hash}</td>
            <td>{a.source_type.value}</td>
            <td>{a.import_timestamp_utc}</td>
        </tr>
        """ for a in artifacts)

        deleted_rows = "".join(f"""
        <tr>
            <td style="font-family: monospace; font-size: 11px;">{d.candidate_id}</td>
            <td><span class="badge badge-{d.confidence.value.lower()}">{d.confidence.value}</span></td>
            <td style="font-family: monospace;">0x{d.byte_offset:08X}</td>
            <td>{d.recovery_mechanism}</td>
            <td style="font-family: monospace; font-size: 11px;">{d.decoded_text or '<em>[Raw Payload Fragment]</em>'}</td>
            <td style="font-size: 11px;">{d.examiner_rationale}</td>
        </tr>
        """ for d in deleted_candidates)

        anomalies_rows = "".join(f"""
        <tr style="background: rgba(239, 68, 68, 0.05);">
            <td style="font-family: monospace;">{e.event_id}</td>
            <td>{e.timestamp_utc}</td>
            <td>{e.primary_participant}</td>
            <td>{e.summary}</td>
            <td style="color: #ef4444; font-size: 11px;">{e.anomaly_explanation}</td>
        </tr>
        """ for e in timeline_events if e.has_chronology_anomaly)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Examination Report - {self.case_id}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f141c; color: #e2e8f0; margin: 0; padding: 40px; }}
    .container {{ max-width: 1100px; margin: 0 auto; background: #161f2e; border: 1px solid #2d3b52; border-radius: 8px; padding: 32px; }}
    h1, h2, h3 {{ color: #38bdf8; margin-top: 24px; }}
    .header-box {{ border-bottom: 2px solid #0284c7; padding-bottom: 16px; margin-bottom: 24px; }}
    .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 14px; margin-bottom: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
    th, td {{ border: 1px solid #2d3b52; padding: 8px 12px; text-align: left; }}
    th {{ background: #1f2b3e; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
    .badge {{ padding: 3px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; }}
    .badge-confirmed {{ background: #065f46; color: #6ee7b7; }}
    .badge-partial {{ background: #854d0e; color: #fde047; }}
    .badge-unverified {{ background: #374151; color: #d1d5db; }}
    .disclaimer {{ background: #1e293b; border-left: 4px solid #f59e0b; padding: 12px; font-size: 12px; margin-top: 32px; color: #cbd5e1; }}
</style>
</head>
<body>
<div class="container">
    <div class="header-box">
        <h1 style="margin: 0; font-size: 24px;">ROGUEBYTE DIGITAL FORENSIC EXAMINATION REPORT</h1>
        <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 13px;">Evidence-Driven WhatsApp Forensic Acquisition & Relational Verification</p>
    </div>

    <div class="meta-grid">
        <div><strong>Case Reference:</strong> {self.case_id} - {self.case_title}</div>
        <div><strong>Report Generated:</strong> {now_str}</div>
        <div><strong>Lead Examiner:</strong> {self.examiner_name} (ID: {self.examiner_id})</div>
        <div><strong>Examination Agency:</strong> {self.agency_name}</div>
        <div><strong>Analysis Platform:</strong> {self.tool_version}</div>
        <div><strong>Evidence Hash Standard:</strong> SHA-256 Cryptographic Verification</div>
    </div>

    <h2>1. Evidence Ingestion & Cryptographic Chain of Custody</h2>
    <table>
        <thead>
            <tr>
                <th>Evidence ID</th>
                <th>Filename</th>
                <th>Size</th>
                <th>SHA-256 Hash</th>
                <th>Artifact Type</th>
                <th>Acquired (UTC)</th>
            </tr>
        </thead>
        <tbody>
            {artifacts_rows}
        </tbody>
    </table>

    <h2>2. Deleted Artifact Investigation & Recovery Provenance</h2>
    <p style="font-size: 12px; color: #94a3b8;">
        All carved items are classified under the RogueByte Confidence Matrix: 
        <strong>CONFIRMED</strong> (intact fields), <strong>PARTIAL</strong> (fragmentary string with JID), <strong>UNVERIFIED</strong> (unallocated string carver hit).
    </p>
    <table>
        <thead>
            <tr>
                <th>Candidate ID</th>
                <th>Confidence</th>
                <th>Source Offset</th>
                <th>Recovery Method</th>
                <th>Carved Payload</th>
                <th>Examiner Rationale</th>
            </tr>
        </thead>
        <tbody>
            {deleted_rows if deleted_candidates else '<tr><td colspan="6">No deleted artifacts identified in unallocated blocks or WAL frames.</td></tr>'}
        </tbody>
    </table>

    <h2>3. Chronology Inconsistencies & Timeline Anomalies</h2>
    <table>
        <thead>
            <tr>
                <th>Event ID</th>
                <th>Timestamp (UTC)</th>
                <th>Participant</th>
                <th>Summary</th>
                <th>Technical Explanation</th>
            </tr>
        </thead>
        <tbody>
            {anomalies_rows if anomalies_rows else '<tr><td colspan="5">No timeline anomalies detected. All timestamps conform to chronological constraints.</td></tr>'}
        </tbody>
    </table>

    <div class="disclaimer">
        <strong>FORENSIC INTEGRITY NOTICE:</strong> 
        This report reflects examination conducted exclusively on legally authorized evidence copies. 
        Cryptographic SHA-256 hashes must be verified against source acquisition manifests prior to court submission.
    </div>
</div>
</body>
</html>
"""
