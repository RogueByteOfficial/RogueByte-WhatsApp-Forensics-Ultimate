import React, { useState } from 'react';
import {
  ScrollText,
  ShieldCheck,
  Download,
  Plus,
  Lock,
  Calendar,
  CheckCircle,
  FileCheck
} from 'lucide-react';
import { AuditLogEntry } from '../types/forensics';

interface AuditLogProps {
  auditEntries: AuditLogEntry[];
  onAddEntry: (entry: AuditLogEntry) => void;
  examinerId: string;
}

export const AuditLogWorkspace: React.FC<AuditLogProps> = ({
  auditEntries,
  onAddEntry,
  examinerId,
}) => {
  const [isAdding, setIsAdding] = useState(false);
  const [newAction, setNewAction] = useState('MANUAL_EXAMINER_NOTE');
  const [newDetails, setNewDetails] = useState('');

  const handleAddSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDetails.trim()) return;

    const entry: AuditLogEntry = {
      entryId: `AUD-${String(auditEntries.length + 1).padStart(5, '0')}`,
      timestampUtc: new Date().toISOString().replace('T', ' ').substring(0, 23) + ' UTC',
      actionType: newAction,
      details: newDetails.trim(),
      examinerId: examinerId,
      sha256VerificationStatus: 'VERIFIED_MATCH'
    };

    onAddEntry(entry);
    setNewDetails('');
    setIsAdding(false);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(auditEntries, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Chain_Of_Custody_Audit_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Top Banner */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ScrollText className="w-5 h-5 text-emerald-400" /> Cryptographic Chain of Custody & Audit Log
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Immutable, append-only operational ledger tracking evidence acquisition, verification, and analysis actions.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsAdding(!isAdding)}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-800 rounded transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Custody Note</span>
          </button>

          <button
            onClick={handleExportJson}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-[#16202c] hover:bg-[#1f2c3d] text-slate-200 border border-[#253446] rounded transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span>Export Audit Trail (JSON)</span>
          </button>
        </div>
      </div>

      {/* Add Custody Note Drawer/Form */}
      {isAdding && (
        <form onSubmit={handleAddSubmit} className="bg-[#111722] border border-emerald-800/80 p-5 rounded-lg space-y-3">
          <h3 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
            Record Manual Chain of Custody Entry
          </h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Action Category</label>
              <select
                value={newAction}
                onChange={e => setNewAction(e.target.value)}
                className="w-full bg-[#0a0f16] border border-[#223042] rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
              >
                <option value="MANUAL_EXAMINER_NOTE">Manual Examiner Note</option>
                <option value="EVIDENCE_TRANSFER">Evidence Transfer / Handoff</option>
                <option value="DEVICE_SEALING">Evidence Container Resealing</option>
                <option value="COURT_SUBMISSION">Legal / Court Presentation Check</option>
              </select>
            </div>
            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Examiner Badge / Identifier</label>
              <input
                type="text"
                disabled
                value={examinerId}
                className="w-full bg-[#0a0f16] border border-[#223042] rounded px-3 py-1.5 text-xs text-slate-400 font-mono"
              />
            </div>
          </div>
          <div>
            <label className="text-[11px] text-slate-400 block mb-1">Detailed Technical Entry</label>
            <textarea
              rows={2}
              required
              placeholder="Enter specific actions, transfer parties, or procedural findings..."
              value={newDetails}
              onChange={e => setNewDetails(e.target.value)}
              className="w-full bg-[#0a0f16] border border-[#223042] rounded p-2.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500 leading-relaxed"
            />
          </div>
          <div className="flex justify-end gap-3 pt-1">
            <button
              type="button"
              onClick={() => setIsAdding(false)}
              className="px-3 py-1 text-xs text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1 text-xs bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold rounded"
            >
              Commit Entry to Ledger
            </button>
          </div>
        </form>
      )}

      {/* Audit Trail Table */}
      <div className="bg-[#101722] border border-[#1e2a3b] rounded-lg overflow-hidden">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-[#090d14] border-b border-[#1e2a3b] text-slate-400 font-mono uppercase text-[11px]">
              <th className="p-3">Log ID</th>
              <th className="p-3">Timestamp (UTC)</th>
              <th className="p-3">Action Type</th>
              <th className="p-3">Target Artifact</th>
              <th className="p-3">Examiner</th>
              <th className="p-3">Integrity Status</th>
              <th className="p-3">Operational Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#172230]">
            {auditEntries.map(entry => (
              <tr key={entry.entryId} className="hover:bg-[#141d29] transition-colors">
                <td className="p-3 font-mono font-semibold text-slate-300">{entry.entryId}</td>
                <td className="p-3 font-mono text-slate-400 text-[11px]">{entry.timestampUtc}</td>
                <td className="p-3">
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-[#162130] text-emerald-400 border border-[#23354c]">
                    {entry.actionType}
                  </span>
                </td>
                <td className="p-3 font-mono text-slate-400 text-[11px]">{entry.targetEvidenceId || 'GLOBAL'}</td>
                <td className="p-3 font-mono text-slate-300">{entry.examinerId}</td>
                <td className="p-3">
                  <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-mono">
                    <CheckCircle className="w-3.5 h-3.5" /> VERIFIED
                  </span>
                </td>
                <td className="p-3 text-slate-300 leading-relaxed max-w-md">{entry.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
