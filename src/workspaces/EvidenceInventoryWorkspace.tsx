import React, { useState } from 'react';
import {
  ShieldCheck,
  Copy,
  Check,
  Download,
  Lock,
  FileCode,
  Search,
  ExternalLink,
  RefreshCw
} from 'lucide-react';
import { EvidenceArtifact } from '../types/forensics';
import { formatBytes } from '../utils/crypto';

interface EvidenceInventoryProps {
  artifacts: EvidenceArtifact[];
  onVerifyHashes: () => void;
  isVerifying: boolean;
}

export const EvidenceInventoryWorkspace: React.FC<EvidenceInventoryProps> = ({
  artifacts,
  onVerifyHashes,
  isVerifying,
}) => {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [filterText, setFilterText] = useState('');
  const [selectedArtifact, setSelectedArtifact] = useState<EvidenceArtifact | null>(null);

  const handleCopy = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleExportManifest = () => {
    const manifest = {
      exportTimestampUtc: new Date().toISOString(),
      tool: 'RogueByte WhatsApp Forensics Ultimate v2.5',
      artifactCount: artifacts.length,
      artifacts: artifacts.map(a => ({
        evidenceId: a.evidenceId,
        filename: a.filename,
        sha256: a.sha256Hash,
        fileSizeBytes: a.fileSizeBytes,
        sourceType: a.sourceType,
        magicBytes: a.magicBytes,
        importTimestampUtc: a.importTimestampUtc
      }))
    };

    const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Evidence_Manifest_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filtered = artifacts.filter(a =>
    a.filename.toLowerCase().includes(filterText.toLowerCase()) ||
    a.evidenceId.toLowerCase().includes(filterText.toLowerCase()) ||
    a.sha256Hash.toLowerCase().includes(filterText.toLowerCase())
  );

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Top Bar */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" /> Evidence Inventory & Cryptographic Registry
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Complete inventory of ingested forensic containers with immutable SHA-256 hashes and write-blocked status.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Filter by name, ID, or hash..."
              value={filterText}
              onChange={e => setFilterText(e.target.value)}
              className="bg-[#101722] border border-[#223042] rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500 w-64"
            />
          </div>

          <button
            onClick={onVerifyHashes}
            disabled={isVerifying}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-800 rounded transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin' : ''}`} />
            <span>{isVerifying ? 'Verifying Integrity...' : 'Verify Cryptographic Hashes'}</span>
          </button>

          <button
            onClick={handleExportManifest}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-[#162232] hover:bg-[#1d2d42] text-slate-200 border border-[#2b3d54] rounded transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span>Export Manifest (.json)</span>
          </button>
        </div>
      </div>

      {/* High-Density Evidence Table */}
      <div className="bg-[#101722] border border-[#1e2a3b] rounded-lg overflow-hidden">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-[#0b1017] border-b border-[#1e2a3b] text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
              <th className="p-3">Evidence ID</th>
              <th className="p-3">Filename</th>
              <th className="p-3">Size</th>
              <th className="p-3">Source Type</th>
              <th className="p-3">Magic Bytes</th>
              <th className="p-3">SHA-256 Digest</th>
              <th className="p-3">Lock Status</th>
              <th className="p-3">Acquired (UTC)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#182333]">
            {filtered.map(artifact => (
              <tr
                key={artifact.evidenceId}
                onClick={() => setSelectedArtifact(artifact)}
                className="hover:bg-[#15202e] cursor-pointer transition-colors group"
              >
                <td className="p-3 font-mono font-semibold text-slate-300">{artifact.evidenceId}</td>
                <td className="p-3 font-medium text-slate-100 flex items-center gap-1.5">
                  <span>{artifact.filename}</span>
                </td>
                <td className="p-3 font-mono text-slate-400">{formatBytes(artifact.fileSizeBytes)}</td>
                <td className="p-3">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#172436] text-slate-300 border border-[#253952]">
                    {artifact.sourceType}
                  </span>
                </td>
                <td className="p-3 font-mono text-slate-500 text-[11px]">
                  {artifact.magicBytes.substring(0, 16)}...
                </td>
                <td className="p-3">
                  <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-400 group-hover:text-emerald-400">
                    <span className="truncate max-w-[150px]">{artifact.sha256Hash}</span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCopy(artifact.sha256Hash);
                      }}
                      className="p-1 hover:text-slate-100"
                      title="Copy full SHA-256 hash"
                    >
                      {copiedHash === artifact.sha256Hash ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                </td>
                <td className="p-3">
                  <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-mono">
                    <Lock className="w-3 h-3" /> Read-Only
                  </span>
                </td>
                <td className="p-3 font-mono text-slate-400 text-[11px]">{artifact.importTimestampUtc}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Selected Artifact Detail Modal / Drawer */}
      {selectedArtifact && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-[#111722] border border-[#26374d] rounded-lg max-w-2xl w-full p-6 space-y-4 shadow-xl">
            <div className="flex justify-between items-start border-b border-[#1e2a3b] pb-3">
              <div>
                <span className="text-xs font-mono text-emerald-400">{selectedArtifact.evidenceId}</span>
                <h3 className="text-base font-bold text-slate-100">{selectedArtifact.filename}</h3>
              </div>
              <button
                onClick={() => setSelectedArtifact(null)}
                className="text-slate-500 hover:text-slate-300 text-xs px-2 py-1"
              >
                ✕ Close
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-500 block mb-1">Cryptographic SHA-256 Digest:</span>
                <div className="p-2.5 bg-[#0a0f16] border border-[#1f2c3d] rounded font-mono text-emerald-400 text-[11px] break-all select-all">
                  {selectedArtifact.sha256Hash}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-slate-500 block">Exact File Size:</span>
                  <span className="text-slate-200 font-mono">{selectedArtifact.fileSizeBytes.toLocaleString()} bytes ({formatBytes(selectedArtifact.fileSizeBytes)})</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Identified Format / Schema:</span>
                  <span className="text-slate-200 font-mono">{selectedArtifact.schemaVersion || selectedArtifact.sourceType}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Magic Bytes Signature:</span>
                  <span className="text-slate-200 font-mono">{selectedArtifact.magicBytes}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Acquisition Timestamp:</span>
                  <span className="text-slate-200 font-mono">{selectedArtifact.importTimestampUtc}</span>
                </div>
              </div>

              <div>
                <span className="text-slate-500 block mb-1">Acquisition & Custody Notes:</span>
                <p className="text-slate-300 bg-[#0a0f16] p-2.5 rounded border border-[#1f2c3d] leading-relaxed">
                  {selectedArtifact.notes || 'Evidence replica acquired and verified.'}
                </p>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedArtifact(null)}
                className="px-4 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold rounded"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
