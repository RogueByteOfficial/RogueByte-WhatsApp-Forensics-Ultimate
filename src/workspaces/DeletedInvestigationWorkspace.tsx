import React, { useState } from 'react';
import {
  SearchCode,
  ShieldAlert,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  FileQuestion,
  Terminal,
  Binary,
  Download,
  Info
} from 'lucide-react';
import { DeletedCandidate, ConfidenceCategory } from '../types/forensics';
import { formatHexOffset } from '../utils/crypto';

interface DeletedInvestigationProps {
  candidates: DeletedCandidate[];
}

export const DeletedInvestigationWorkspace: React.FC<DeletedInvestigationProps> = ({ candidates }) => {
  const [selectedCandidate, setSelectedCandidate] = useState<DeletedCandidate | null>(
    candidates.length > 0 ? candidates[0] : null
  );
  const [filterConfidence, setFilterConfidence] = useState<string>('ALL');

  const filtered = candidates.filter(c => {
    if (filterConfidence === 'ALL') return true;
    return c.confidence === filterConfidence;
  });

  const getConfidenceBadge = (cat: ConfidenceCategory) => {
    switch (cat) {
      case 'CONFIRMED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-800">CONFIRMED</span>;
      case 'PARTIAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-amber-950 text-amber-300 border border-amber-800">PARTIAL</span>;
      case 'INFERRED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-indigo-950 text-indigo-300 border border-indigo-800">INFERRED</span>;
      case 'UNVERIFIED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-800 text-slate-300 border border-slate-700">UNVERIFIED</span>;
      case 'UNRECOVERABLE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-950 text-rose-300 border border-rose-800">UNRECOVERABLE</span>;
    }
  };

  const handleExportCarved = () => {
    const blob = new Blob([JSON.stringify(candidates, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Carved_Deleted_Artifacts_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Left / Center Table List */}
      <div className="flex-1 flex flex-col bg-[#0b0f15] border-r border-[#1e293b] overflow-hidden">
        {/* Workspace Top Header & Filter Bar */}
        <div className="p-4 bg-[#0e141d] border-b border-[#1e293b] space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 uppercase tracking-wide">
                <SearchCode className="w-4 h-4 text-amber-400" /> Deleted Artifact Recovery Subsystem
              </h2>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Examines surviving SQLite WAL frames, freelist blocks, and unallocated page slack space.
              </p>
            </div>

            <button
              onClick={handleExportCarved}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#16202c] hover:bg-[#1f2c3d] text-slate-200 border border-[#253446] rounded transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>Export Carved JSON</span>
            </button>
          </div>

          {/* Segmented Filter Bar by RogueByte Confidence Matrix */}
          <div className="flex items-center gap-1.5 bg-[#090d14] p-1 rounded border border-[#1b2533] text-xs font-mono">
            {['ALL', 'CONFIRMED', 'PARTIAL', 'INFERRED', 'UNVERIFIED', 'UNRECOVERABLE'].map(cat => (
              <button
                key={cat}
                onClick={() => setFilterConfidence(cat)}
                className={`px-2.5 py-1 rounded text-[11px] transition-colors ${
                  filterConfidence === cat
                    ? 'bg-[#182330] text-emerald-400 font-bold border border-emerald-800/60'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Evidence Candidates Table */}
        <div className="flex-1 overflow-auto p-4">
          <div className="bg-[#101722] border border-[#1e2a3b] rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="bg-[#090d14] border-b border-[#1e2a3b] text-slate-400 text-[11px] uppercase tracking-wider">
                  <th className="p-3">Candidate ID</th>
                  <th className="p-3">Classification</th>
                  <th className="p-3">Offset</th>
                  <th className="p-3">Source File</th>
                  <th className="p-3">Mechanism</th>
                  <th className="p-3">Decoded Payload</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#172230]">
                {filtered.map(c => {
                  const isSelected = selectedCandidate?.candidateId === c.candidateId;
                  return (
                    <tr
                      key={c.candidateId}
                      onClick={() => setSelectedCandidate(c)}
                      className={`hover:bg-[#15202e] cursor-pointer transition-colors ${
                        isSelected ? 'bg-[#152233] border-l-2 border-emerald-500' : ''
                      }`}
                    >
                      <td className="p-3 text-slate-200 font-semibold">{c.candidateId}</td>
                      <td className="p-3">{getConfidenceBadge(c.confidence)}</td>
                      <td className="p-3 text-slate-400">{formatHexOffset(c.byteOffset)}</td>
                      <td className="p-3 text-slate-400">{c.sourceFile}</td>
                      <td className="p-3 text-slate-300 font-sans text-[11px]">{c.recoveryMechanism}</td>
                      <td className="p-3 text-slate-200 font-sans text-xs truncate max-w-sm">
                        {c.decodedText || <span className="text-slate-600 italic">[Overwritten Zeroed Block]</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Right Pane: Detailed Hex Inspector & Forensic Rationale */}
      <div className="w-96 bg-[#0d1219] flex flex-col shrink-0 p-5 overflow-y-auto space-y-4">
        {selectedCandidate ? (
          <>
            <div className="border-b border-[#1e293b] pb-3">
              <div className="text-[10px] text-slate-500 font-mono">RECORD PROVENANCE</div>
              <h3 className="text-sm font-bold text-slate-100 font-mono mt-0.5">{selectedCandidate.candidateId}</h3>
              <div className="mt-2 flex items-center justify-between">
                {getConfidenceBadge(selectedCandidate.confidence)}
                <span className="text-[11px] text-slate-400 font-mono">
                  Offset: {formatHexOffset(selectedCandidate.byteOffset)}
                </span>
              </div>
            </div>

            {/* Field Integrity Checklist */}
            <div className="bg-[#101722] p-3.5 rounded border border-[#1d2737] space-y-2">
              <div className="text-[10px] uppercase font-semibold text-slate-400 font-mono tracking-wider">
                Structural Validation
              </div>
              <div className="space-y-1.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Remote JID Intact</span>
                  <span className={selectedCandidate.fieldIntegrity.jidIntact ? 'text-emerald-400' : 'text-slate-600'}>
                    {selectedCandidate.fieldIntegrity.jidIntact ? '✓ YES' : '✗ NO'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Payload String Intact</span>
                  <span className={selectedCandidate.fieldIntegrity.payloadIntact ? 'text-emerald-400' : 'text-slate-600'}>
                    {selectedCandidate.fieldIntegrity.payloadIntact ? '✓ YES' : '✗ NO'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Primary Key Row ID Intact</span>
                  <span className={selectedCandidate.fieldIntegrity.keyIdIntact ? 'text-emerald-400' : 'text-slate-600'}>
                    {selectedCandidate.fieldIntegrity.keyIdIntact ? '✓ YES' : '✗ TRUNCATED'}
                  </span>
                </div>
              </div>
            </div>

            {/* Decoded Text Box */}
            <div className="space-y-1.5">
              <div className="text-[10px] uppercase font-semibold text-slate-400 font-mono tracking-wider">
                Recovered Text Content
              </div>
              <div className="p-3 bg-[#080c12] border border-[#1f2b3c] rounded text-xs text-emerald-300 leading-relaxed font-sans select-text">
                {selectedCandidate.decodedText || '[No readable UTF-8 string found in block]'}
              </div>
            </div>

            {/* Raw Hex Dump View */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[10px] uppercase font-semibold text-slate-400 font-mono tracking-wider">
                <span>Raw Hex Payload</span>
                <span>Offset: {formatHexOffset(selectedCandidate.byteOffset)}</span>
              </div>
              <div className="p-2.5 bg-[#06090e] border border-[#1a2533] rounded font-mono text-[10px] text-slate-400 break-all select-all leading-tight">
                {selectedCandidate.rawPayloadHex}
              </div>
            </div>

            {/* Examiner Rationale */}
            <div className="bg-[#121924] p-3.5 rounded border border-[#202d3f] space-y-1.5 text-xs">
              <div className="text-[10px] uppercase font-bold text-amber-400 font-mono flex items-center gap-1">
                <Info className="w-3.5 h-3.5" /> Examiner Forensic Rationale
              </div>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                {selectedCandidate.examinerRationale}
              </p>
            </div>
          </>
        ) : (
          <div className="text-center py-20 text-xs text-slate-500">
            Select a candidate from the table to view raw hex bytes and structural validation.
          </div>
        )}
      </div>
    </div>
  );
};
