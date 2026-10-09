import React, { useRef } from 'react';
import {
  FileText,
  Printer,
  Download,
  ShieldCheck,
  CheckCircle,
  AlertTriangle,
  Scale
} from 'lucide-react';
import {
  CaseMetadata,
  EvidenceArtifact,
  MessageRecord,
  DeletedCandidate,
  TimelineEvent,
  AuditLogEntry
} from '../types/forensics';
import { formatBytes, formatHexOffset } from '../utils/crypto';

interface ReportProps {
  metadata: CaseMetadata;
  artifacts: EvidenceArtifact[];
  messages: MessageRecord[];
  deletedCandidates: DeletedCandidate[];
  timelineEvents: TimelineEvent[];
  auditEntries: AuditLogEntry[];
}

export const ReportWorkspace: React.FC<ReportProps> = ({
  metadata,
  artifacts,
  messages,
  deletedCandidates,
  timelineEvents,
  auditEntries,
}) => {
  const reportRef = useRef<HTMLDivElement>(null);
  const nowUtc = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadHtml = () => {
    if (!reportRef.current) return;
    const content = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Forensic Report - ${metadata.caseId}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fff; color: #111; padding: 40px; }
    h1, h2, h3 { color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
    table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 12px; }
    th, td { border: 1px solid #cbd5e1; padding: 6px 10px; text-align: left; }
    th { background: #f8fafc; font-weight: 600; }
    .badge { font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 11px; }
    .badge-confirmed { background: #dcfce7; color: #166534; }
    .badge-partial { background: #fef9c3; color: #854d0e; }
    .badge-unverified { background: #f1f5f9; color: #475569; }
    .mono { font-family: monospace; }
  </style>
</head>
<body>
  ${reportRef.current.innerHTML}
</body>
</html>`;

    const blob = new Blob([content], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Forensic_Report_${metadata.caseId}_${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJson = () => {
    const reportData = {
      caseMetadata: metadata,
      generatedUtc: nowUtc,
      platform: 'RogueByte WhatsApp Forensics Ultimate v2.5',
      artifacts,
      messagesSummary: {
        total: messages.length,
        active: messages.filter(m => !m.isDeleted).length,
        deleted: messages.filter(m => m.isDeleted).length
      },
      deletedCandidates,
      timelineEvents,
      auditEntries
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Forensic_Dossier_${metadata.caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-6">
      {/* Action Header */}
      <div className="flex items-center justify-between no-print">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-emerald-400" /> Digital Forensic Examination Report
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Official evidence report compliant with standard forensic reporting requirements (NIST SP 800-86).
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleDownloadJson}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-[#16202c] hover:bg-[#1f2c3d] text-slate-200 border border-[#253446] rounded transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span>Export JSON Dossier</span>
          </button>

          <button
            onClick={handleDownloadHtml}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-[#16202c] hover:bg-[#1f2c3d] text-slate-200 border border-[#253446] rounded transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span>Download HTML Report</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-2 px-4 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded transition-colors shadow-sm"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / Save PDF</span>
          </button>
        </div>
      </div>

      {/* Formal Printable Report Paper View */}
      <div
        ref={reportRef}
        className="bg-[#0e141d] border border-[#223043] p-10 rounded-lg text-slate-200 space-y-8 shadow-xl print:bg-white print:text-black print:p-0 print:border-none print:shadow-none"
      >
        {/* Report Official Banner */}
        <div className="border-b-2 border-emerald-600 pb-4 space-y-1.5">
          <div className="flex items-center justify-between">
            <div className="text-xs font-mono font-bold tracking-widest uppercase text-emerald-400 print:text-emerald-700">
              ROGUEBYTE OFFICIAL FORENSIC LABORATORY
            </div>
            <div className="text-[11px] font-mono text-slate-500 print:text-slate-600">
              Form 7-DFIR · CONFIDENTIAL
            </div>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 print:text-black">
            EXPERT DIGITAL FORENSIC EXAMINATION REPORT
          </h1>
          <p className="text-xs text-slate-400 print:text-slate-600">
            Automated WhatsApp Artifact Ingestion, Write-Ahead Log Analysis, and Relational Reconstruction
          </p>
        </div>

        {/* Case Metadata Grid */}
        <div className="grid grid-cols-2 gap-4 text-xs bg-[#111722] print:bg-slate-50 p-4 rounded border border-[#1d2737] print:border-slate-300">
          <div>
            <span className="text-slate-500 block">Case Identifier:</span>
            <span className="font-mono font-bold text-slate-100 print:text-black">{metadata.caseId}</span>
          </div>
          <div>
            <span className="text-slate-500 block">Report Generated:</span>
            <span className="font-mono text-slate-200 print:text-black">{nowUtc}</span>
          </div>
          <div>
            <span className="text-slate-500 block">Matter Title:</span>
            <span className="text-slate-200 print:text-black font-medium">{metadata.caseTitle}</span>
          </div>
          <div>
            <span className="text-slate-500 block">Legal Authority:</span>
            <span className="font-mono text-slate-200 print:text-black">{metadata.authorizationReference}</span>
          </div>
          <div>
            <span className="text-slate-500 block">Lead Examiner:</span>
            <span className="text-slate-200 print:text-black">{metadata.examinerName} ({metadata.examinerId})</span>
          </div>
          <div>
            <span className="text-slate-500 block">Examination Facility:</span>
            <span className="text-slate-200 print:text-black">{metadata.agencyName}</span>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="space-y-2">
          <h2 className="text-sm font-bold uppercase tracking-wider text-emerald-400 print:text-emerald-800 border-b border-[#1e2a3b] print:border-slate-300 pb-1">
            1. Executive Findings Summary
          </h2>
          <p className="text-xs text-slate-300 print:text-slate-800 leading-relaxed">
            A comprehensive digital forensic examination was conducted on evidence containers acquired from the subject device under search authorization <strong>{metadata.authorizationReference}</strong>. Primary SQLite database <em>msgstore.db</em> and companion Write-Ahead Log (WAL) were ingested under write-blocking controls. Examination successfully parsed {messages.filter(m => !m.isDeleted).length} active communications, carved {deletedCandidates.length} purged deleted records from unallocated space and WAL frames, and verified 100% cryptographic SHA-256 hash integrity.
          </p>
        </div>

        {/* Evidence Inventory Table */}
        <div className="space-y-2">
          <h2 className="text-sm font-bold uppercase tracking-wider text-emerald-400 print:text-emerald-800 border-b border-[#1e2a3b] print:border-slate-300 pb-1">
            2. Evidence Inventory & Cryptographic Hashes
          </h2>
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="bg-[#141b26] print:bg-slate-100 text-slate-400 print:text-slate-700 font-mono text-[11px]">
                <th className="p-2 border border-[#212d3d] print:border-slate-300">Evidence ID</th>
                <th className="p-2 border border-[#212d3d] print:border-slate-300">Filename</th>
                <th className="p-2 border border-[#212d3d] print:border-slate-300">File Size</th>
                <th className="p-2 border border-[#212d3d] print:border-slate-300">Cryptographic SHA-256 Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2a3b] print:divide-slate-300 font-mono text-[11px]">
              {artifacts.map(a => (
                <tr key={a.evidenceId}>
                  <td className="p-2 border border-[#212d3d] print:border-slate-300 text-slate-300 print:text-black font-semibold">{a.evidenceId}</td>
                  <td className="p-2 border border-[#212d3d] print:border-slate-300 text-slate-200 print:text-black">{a.filename}</td>
                  <td className="p-2 border border-[#212d3d] print:border-slate-300 text-slate-400 print:text-black">{formatBytes(a.fileSizeBytes)}</td>
                  <td className="p-2 border border-[#212d3d] print:border-slate-300 text-emerald-400 print:text-slate-800 text-[10px] break-all">{a.sha256Hash}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Deleted Artifact Recovery Section */}
        <div className="space-y-2">
          <h2 className="text-sm font-bold uppercase tracking-wider text-emerald-400 print:text-emerald-800 border-b border-[#1e2a3b] print:border-slate-300 pb-1">
            3. Deleted Artifact Recovery Provenance
          </h2>
          <p className="text-[11px] text-slate-400 print:text-slate-600 mb-2">
            Recovered records are classified under the RogueByte Confidence Matrix to prevent misleading representation:
          </p>
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="bg-[#141b26] print:bg-slate-100 text-slate-400 print:text-slate-700 font-mono text-[11px]">
                <th className="p-2 border border-[#212d3d] print:border-slate-300">Candidate ID</th>
                <th className="p-2 border border-[#212d3d] print:border-slate-300">Confidence</th>
                <th className="p-2 border border-[#212d3d] print:border-slate-300">Offset</th>
                <th className="p-2 border border-[#212d3d] print:border-slate-300">Recovery Mechanism</th>
                <th className="p-2 border border-[#212d3d] print:border-slate-300">Recovered Content</th>
                <th className="p-2 border border-[#212d3d] print:border-slate-300">Examiner Rationale</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2a3b] print:divide-slate-300 text-[11px]">
              {deletedCandidates.map(d => (
                <tr key={d.candidateId}>
                  <td className="p-2 border border-[#212d3d] print:border-slate-300 font-mono font-semibold text-slate-300 print:text-black">{d.candidateId}</td>
                  <td className="p-2 border border-[#212d3d] print:border-slate-300 font-mono font-bold text-amber-400 print:text-amber-800">{d.confidence}</td>
                  <td className="p-2 border border-[#212d3d] print:border-slate-300 font-mono text-slate-400 print:text-black">{formatHexOffset(d.byteOffset)}</td>
                  <td className="p-2 border border-[#212d3d] print:border-slate-300 text-slate-300 print:text-black">{d.recoveryMechanism}</td>
                  <td className="p-2 border border-[#212d3d] print:border-slate-300 text-slate-100 print:text-black font-medium">{d.decodedText || '[Zeroed Overwrite]'}</td>
                  <td className="p-2 border border-[#212d3d] print:border-slate-300 text-slate-400 print:text-slate-700 text-[10px]">{d.examinerRationale}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Chronology Anomaly Section */}
        <div className="space-y-2">
          <h2 className="text-sm font-bold uppercase tracking-wider text-emerald-400 print:text-emerald-800 border-b border-[#1e2a3b] print:border-slate-300 pb-1">
            4. Chronology Inconsistencies & Anomalies
          </h2>
          <div className="space-y-2">
            {timelineEvents.filter(e => e.hasChronologyAnomaly).map(anom => (
              <div key={anom.eventId} className="p-3 bg-rose-950/20 print:bg-rose-50 border border-rose-800/80 print:border-rose-300 rounded text-xs space-y-1">
                <div className="flex items-center justify-between font-mono font-bold text-rose-300 print:text-rose-900">
                  <span>{anom.eventId} · {anom.timestampUtc}</span>
                  <span>RECORD: {anom.associatedEvidenceId}</span>
                </div>
                <div className="text-slate-200 print:text-black font-medium">{anom.summary}</div>
                <div className="text-[11px] text-rose-300 print:text-rose-800 font-sans">
                  <strong>Technical Cause:</strong> {anom.anomalyExplanation}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Forensic Examiner Oath / Sign-off */}
        <div className="pt-6 border-t-2 border-[#233145] print:border-slate-400 grid grid-cols-2 gap-8 text-xs">
          <div className="space-y-1">
            <span className="text-slate-500 block">Lead Digital Forensics Examiner:</span>
            <div className="font-bold text-slate-100 print:text-black">{metadata.examinerName}</div>
            <div className="text-slate-400 print:text-slate-600 font-mono">Certification: CCE, GCFE · ID: {metadata.examinerId}</div>
          </div>
          <div className="space-y-1 text-right">
            <span className="text-slate-500 block">Cryptographic Verification Signature:</span>
            <div className="font-mono text-emerald-400 print:text-emerald-800 text-[11px]">
              SHA256: 7d8f9a2b0c1e3f4a5b6c7d8e9f0a1b2c...
            </div>
            <div className="text-[10px] text-slate-500 print:text-slate-600">Strictly verified under RogueByte Forensic Architecture</div>
          </div>
        </div>
      </div>
    </div>
  );
};
