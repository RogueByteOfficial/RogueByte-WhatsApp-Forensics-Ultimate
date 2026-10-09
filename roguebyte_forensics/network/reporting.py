"""
RogueByte WhatsApp Forensics Ultimate v2.0 - Network Forensic Reporting Generator
Brand: RogueByteOfficial
"""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from roguebyte_forensics.network.models import (
    IPRecord,
    NetworkFlow,
    DNSRecord,
    CallNetworkCorrelation,
    MessageNetworkCorrelation
)


class NetworkReportGenerator:
    """Generates official network forensic reports in HTML and JSON."""

    def __init__(self, case_id: str, examiner_name: str, examiner_id: str):
        self.case_id = case_id
        self.examiner_name = examiner_name
        self.examiner_id = examiner_id
        self.tool_version = "RogueByte WhatsApp Forensics Ultimate v2.0 (Network Edition)"

    def generate_html_report(
        self,
        pcap_file: str,
        pcap_sha256: str,
        ip_records: List[IPRecord],
        flows: List[NetworkFlow],
        dns_records: List[DNSRecord],
        call_correlations: List[CallNetworkCorrelation],
        message_correlations: List[MessageNetworkCorrelation]
    ) -> str:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        ip_rows = "".join(f"""
        <tr>
            <td style="font-family: monospace; font-weight: bold;">{ip.ip_address}</td>
            <td style="font-family: monospace;">{ip.address_family}</td>
            <td><span class="badge badge-{ip.classification.value.lower()}">{ip.classification.value}</span></td>
            <td>{ip.asn_info.organization if ip.asn_info else 'N/A'}</td>
            <td>AS{ip.asn_info.asn if ip.asn_info else '0'} ({ip.asn_info.country_code if ip.asn_info else '--'})</td>
            <td>{ip.geolocation.city + ', ' + ip.geolocation.country if ip.geolocation and ip.geolocation.city else (ip.geolocation.country if ip.geolocation else 'N/A')}</td>
            <td style="font-size: 11px;">{', '.join(ip.associated_protocols) or 'N/A'}</td>
        </tr>
        """ for ip in ip_records)

        flow_rows = "".join(f"""
        <tr>
            <td style="font-family: monospace;">{f.flow_id}</td>
            <td style="font-family: monospace;">{f.src_ip}:{f.src_port}</td>
            <td style="font-family: monospace;">{f.dst_ip}:{f.dst_port}</td>
            <td><span class="badge">{f.protocol.value}</span></td>
            <td>{f.packet_count} pkts ({f.byte_count:,} B)</td>
            <td style="font-size: 11px;">{f.duration_seconds:.2f}s</td>
            <td style="font-size: 11px;">{f.service_hint or 'Standard Traffic'}</td>
        </tr>
        """ for f in flows[:50])

        call_sections = "".join(f"""
        <div class="correlation-card">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 8px;">
                <strong>Call #{c.call_id} ({c.call_type.upper()})</strong>
                <span class="badge badge-{c.classification.value.lower()}">{c.classification.value}</span>
            </div>
            <div style="margin-top: 8px; font-size: 12px; color: #94a3b8;">
                <div>Target Participant: <strong style="color: #e2e8f0;">{c.participant_jid}</strong></div>
                <div>Call Time Window: {c.call_start_utc} → {c.call_end_utc} ({c.call_duration_seconds}s)</div>
                <div>Candidate Network Flows Identified: {len(c.candidate_flows)}</div>
            </div>
            <div class="disclaimer-box" style="margin-top: 8px;">
                <strong>EXAMINER RATIONALE:</strong> {c.examiner_rationale}
            </div>
            <div class="disclaimer-box" style="margin-top: 6px; border-left-color: #f43f5e; color: #fecdd3;">
                <strong>LEGAL LIMITATION:</strong> {c.attribution_disclaimer}
            </div>
        </div>
        """ for c in call_correlations)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Forensic Examination Report - {self.case_id}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f141c; color: #e2e8f0; margin: 0; padding: 40px; }}
    .container {{ max-width: 1150px; margin: 0 auto; background: #161f2e; border: 1px solid #2d3b52; border-radius: 8px; padding: 32px; }}
    h1, h2, h3 {{ color: #38bdf8; margin-top: 24px; }}
    .header-box {{ border-bottom: 2px solid #0284c7; padding-bottom: 16px; margin-bottom: 24px; }}
    .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 14px; margin-bottom: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }}
    th, td {{ border: 1px solid #2d3b52; padding: 8px 10px; text-align: left; }}
    th {{ background: #1f2b3e; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
    .badge {{ padding: 3px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; font-family: monospace; }}
    .badge-public {{ background: #065f46; color: #6ee7b7; }}
    .badge-private {{ background: #1e293b; color: #94a3b8; }}
    .badge-loopback {{ background: #334155; color: #cbd5e1; }}
    .badge-identified_service_infrastructure {{ background: #075985; color: #7dd3fc; }}
    .badge-remote_participant_ip_unconfirmed {{ background: #854d0e; color: #fde047; }}
    .badge-insufficient_evidence {{ background: #475569; color: #cbd5e1; }}
    .correlation-card {{ background: #111827; border: 1px solid #374151; border-radius: 6px; padding: 14px; margin-top: 12px; }}
    .disclaimer-box {{ background: #1e293b; border-left: 4px solid #f59e0b; padding: 10px; font-size: 11px; color: #cbd5e1; border-radius: 0 4px 4px 0; }}
</style>
</head>
<body>
<div class="container">
    <div class="header-box">
        <h1 style="margin: 0; font-size: 22px;">ROGUEBYTE NETWORK FORENSIC EXAMINATION REPORT</h1>
        <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 13px;">PCAP/PCAPNG Packet Traffic Analysis, Public IP Attribution, & Call Correlation</p>
    </div>

    <div class="meta-grid">
        <div><strong>Case Identifier:</strong> {self.case_id}</div>
        <div><strong>Report Generated:</strong> {now_str}</div>
        <div><strong>Lead Examiner:</strong> {self.examiner_name} (ID: {self.examiner_id})</div>
        <div><strong>Tool:</strong> {self.tool_version}</div>
        <div><strong>Evidence Capture:</strong> {pcap_file}</div>
        <div><strong>Capture SHA-256:</strong> <span style="font-family: monospace; font-size: 11px;">{pcap_sha256}</span></div>
    </div>

    <h2>1. Public & Private IP Address Inventory</h2>
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Family</th>
                <th>Classification</th>
                <th>Registered Organization (ASN)</th>
                <th>Autonomous System</th>
                <th>Estimated Geolocation</th>
                <th>Protocols</th>
            </tr>
        </thead>
        <tbody>
            {ip_rows}
        </tbody>
    </table>

    <h2>2. WhatsApp Voice & Video Call Traffic Correlation</h2>
    {call_sections if call_correlations else '<p style="color: #94a3b8;">No call events were supplied for network correlation.</p>'}

    <h2>3. Observed Reconstructed Network Flows (Top 50)</h2>
    <table>
        <thead>
            <tr>
                <th>Flow ID</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Traffic Volume</th>
                <th>Duration</th>
                <th>Service Identification Hint</th>
            </tr>
        </thead>
        <tbody>
            {flow_rows}
        </tbody>
    </table>

    <div class="disclaimer-box" style="margin-top: 32px;">
        <strong>FORENSIC ATTRIBUTION INTEGRITY NOTICE:</strong> 
        All IP addresses and flows documented above reflect direct observations from the supplied packet capture. 
        In accordance with forensic science standards, observed service infrastructure IP addresses (Meta Platforms AS32934) 
        do not identify individual end-user identity without subscriber session logs from the carrier.
    </div>
</div>
</body>
</html>
"""
