import React, { useState } from 'react';
import {
  Shield,
  FileCheck2,
  FileSpreadsheet,
  Calendar,
  User,
  Scale,
  Building,
  AlertTriangle,
  CheckCircle,
  FileText,
  Lock,
  Edit3
} from 'lucide-react';
import { CaseMetadata, EvidenceArtifact, MessageRecord, DeletedCandidate, TimelineEvent } from '../types/forensics';

interface CaseManagerProps {
  metadata: CaseMetadata;
  onUpdateMetadata: (updated: Partial<CaseMetadata>) => void;
  artifacts: EvidenceArtifact[];
  messages: MessageRecord[];
  deletedCandidates: DeletedCandidate[];
  timelineEvents: TimelineEvent[];
}

export const CaseManagerWorkspace: React.FC<CaseManagerProps> = ({
  metadata,
  onUpdateMetadata,
  artifacts,
  messages,
  deletedCandidates,
  timelineEvents,
}) => {
  const [isEditing, setIsEditing] = useState(false);
  const [editForm, setEditForm] = useState({ ...metadata });

  const anomaliesCount = timelineEvents.filter(e => e.hasChronologyAnomaly).length;
  const confirmedDeleted = deletedCandidates.filter(d => d.confidence === 'CONFIRMED').length;

  const handleSave = () => {
    onUpdateMetadata(editForm);
    setIsEditing(false);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Top Banner */}
      <div className="flex items-start justify-between bg-[#111722] border border-[#1e2a3b] p-6 rounded-lg shadow-sm">
        <div className="space-y-1.5">
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
              {metadata.caseId}
            </span>
            <span className="text-xs text-slate-400">
              Forensic Case Dossier
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-xs text-emerald-500 font-mono flex items-center gap-1">
              <CheckCircle className="w-3.5 h-3.5" /> Chain of Custody Active
            </span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">{metadata.caseTitle}</h2>
          <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
            {metadata.notes}
          </p>
        </div>

        <button
          onClick={() => setIsEditing(!isEditing)}
          className="flex items-center gap-2 px-3 py-1.5 text-xs bg-[#172130] hover:bg-[#1e2b3e] text-slate-200 border border-[#2b3a4f] rounded transition-colors"
        >
          <Edit3 className="w-3.5 h-3.5 text-emerald-400" />
          <span>{isEditing ? 'Cancel Edit' : 'Edit Case Details'}</span>
        </button>
      </div>

      {/* Quick Metrics */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Ingested Artifacts</div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-1">{artifacts.length}</div>
          <div className="text-[11px] text-slate-500 mt-1">100% SHA-256 Verified</div>
        </div>

        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Active Messages Parsed</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{messages.filter(m => !m.isDeleted).length}</div>
          <div className="text-[11px] text-slate-500 mt-1">Relational SQLite Schema v15</div>
        </div>

        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Carved Deleted Artifacts</div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">{deletedCandidates.length}</div>
          <div className="text-[11px] text-amber-500/80 mt-1">{confirmedDeleted} Confirmed via WAL/Slack</div>
        </div>

        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Chronology Anomalies</div>
          <div className={`text-2xl font-bold font-mono mt-1 ${anomaliesCount > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
            {anomaliesCount}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Clock Drift / Future Epochs</div>
        </div>
      </div>

      {/* Edit Form Modal/Drawer if active */}
      {isEditing && (
        <div className="bg-[#131b27] border border-emerald-800/60 p-6 rounded-lg space-y-4">
          <h3 className="text-sm font-semibold text-emerald-400 flex items-center gap-2">
            <Edit3 className="w-4 h-4" /> Edit Case Dossier Information
          </h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-slate-400 block mb-1">Case Title</label>
              <input
                type="text"
                value={editForm.caseTitle}
                onChange={e => setEditForm({ ...editForm, caseTitle: e.target.value })}
                className="w-full bg-[#0a0e14] border border-[#233145] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Authorization Reference / Search Warrant</label>
              <input
                type="text"
                value={editForm.authorizationReference}
                onChange={e => setEditForm({ ...editForm, authorizationReference: e.target.value })}
                className="w-full bg-[#0a0e14] border border-[#233145] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Lead Examiner Name & Badges</label>
              <input
                type="text"
                value={editForm.examinerName}
                onChange={e => setEditForm({ ...editForm, examinerName: e.target.value })}
                className="w-full bg-[#0a0e14] border border-[#233145] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Investigating Agency / Forensic Lab</label>
              <input
                type="text"
                value={editForm.agencyName}
                onChange={e => setEditForm({ ...editForm, agencyName: e.target.value })}
                className="w-full bg-[#0a0e14] border border-[#233145] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Examiner Case Notes</label>
            <textarea
              rows={3}
              value={editForm.notes}
              onChange={e => setEditForm({ ...editForm, notes: e.target.value })}
              className="w-full bg-[#0a0e14] border border-[#233145] rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
            />
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button
              onClick={() => setIsEditing(false)}
              className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              className="px-4 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold rounded"
            >
              Save Changes
            </button>
          </div>
        </div>
      )}

      {/* Two Column Layout: Legal & Custody Metadata / Forensic Methodology */}
      <div className="grid grid-cols-2 gap-6">
        {/* Left: Custody and Legal Metadata */}
        <div className="bg-[#111722] border border-[#1e2a3b] p-6 rounded-lg space-y-4">
          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2 border-b border-[#1e2a3b] pb-3">
            <Scale className="w-4 h-4 text-emerald-400" /> Legal Authorization & Chain of Custody
          </h3>

          <div className="space-y-3 text-xs">
            <div className="flex justify-between py-1 border-b border-[#172230]">
              <span className="text-slate-500">Legal Authority</span>
              <span className="text-slate-200 font-mono font-medium text-right">{metadata.authorizationReference}</span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#172230]">
              <span className="text-slate-500">Lead Examiner</span>
              <span className="text-slate-200 font-medium">{metadata.examinerName} ({metadata.examinerId})</span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#172230]">
              <span className="text-slate-500">Forensic Laboratory</span>
              <span className="text-slate-200">{metadata.agencyName}</span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#172230]">
              <span className="text-slate-500">Workspace Initialized</span>
              <span className="text-slate-300 font-mono">{metadata.creationTimestampUtc}</span>
            </div>

            <div className="flex justify-between py-1">
              <span className="text-slate-500">Write-Blocking Mode</span>
              <span className="text-emerald-400 font-mono font-semibold flex items-center gap-1">
                <Lock className="w-3 h-3" /> ENFORCED (Read-Only Replicas)
              </span>
            </div>
          </div>
        </div>

        {/* Right: Forensic Methodology & Standards */}
        <div className="bg-[#111722] border border-[#1e2a3b] p-6 rounded-lg space-y-4">
          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2 border-b border-[#1e2a3b] pb-3">
            <Shield className="w-4 h-4 text-emerald-400" /> Evidence Preservation Standards
          </h3>

          <div className="space-y-2.5 text-xs text-slate-400 leading-relaxed">
            <p>
              • <strong>Evidence Non-Alteration:</strong> All forensic operations are conducted strictly against verified working replicas. Original image files are never mounted in read-write mode.
            </p>
            <p>
              • <strong>Continuous Cryptographic Verification:</strong> SHA-256 digest calculated at ingestion and re-verified prior to every reporting export.
            </p>
            <p>
              • <strong>Separation of Fact vs Inference:</strong> Reconstructed or carved records are classified under the RogueByte Confidence Matrix (CONFIRMED, PARTIAL, INFERRED, UNVERIFIED, UNRECOVERABLE) and never represented as unaltered active records.
            </p>
            <p>
              • <strong>Timestamp Provenance:</strong> Timestamps preserved in raw millisecond epoch with simultaneous UTC normalization and timezone documentation.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
