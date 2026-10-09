import React, { useState } from 'react';
import {
  UploadCloud,
  FileCheck,
  ShieldCheck,
  AlertCircle,
  Database,
  FileText,
  Archive,
  Layers,
  Sparkles,
  HardDrive
} from 'lucide-react';
import { EvidenceArtifact, EvidenceSourceType } from '../types/forensics';
import { calculateSha256, formatBytes } from '../utils/crypto';
import { SAMPLE_ARTIFACTS } from '../data/sampleEvidence';

interface EvidenceImportProps {
  artifacts: EvidenceArtifact[];
  onAddArtifact: (artifact: EvidenceArtifact) => void;
  onLoadSampleCase: () => void;
  onLoadSyntheticBenchmark: () => void;
}

export const EvidenceImportWorkspace: React.FC<EvidenceImportProps> = ({
  artifacts,
  onAddArtifact,
  onLoadSampleCase,
  onLoadSyntheticBenchmark,
}) => {
  const [isProcessing, setIsProcessing] = useState(false);
  const [progressMsg, setProgressMsg] = useState('');

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    setIsProcessing(true);
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      setProgressMsg(`Hashing & acquiring: ${file.name} (${formatBytes(file.size)})`);

      try {
        const buffer = await file.arrayBuffer();
        const sha256 = await calculateSha256(buffer);
        const headerSlice = new Uint8Array(buffer.slice(0, 16));
        const magicHex = Array.from(headerSlice).map(b => b.toString(16).padStart(2, '0')).join('');

        // Detect source type
        let sourceType: EvidenceSourceType = 'SQLITE_ACTIVE';
        let schemaVer = 'Custom Uploaded Artifact';
        const fn = file.name.toLowerCase();

        if (magicHex.startsWith('53514c69746520666f726d6174203300')) {
          sourceType = 'SQLITE_ACTIVE';
          schemaVer = 'SQLite 3 Database Container';
        } else if (fn.endsWith('-wal') || magicHex.startsWith('377f0682') || magicHex.startsWith('377f0683')) {
          sourceType = 'SQLITE_WAL';
          schemaVer = 'SQLite Write-Ahead Log';
        } else if (fn.includes('crypt12') || fn.includes('crypt14') || fn.includes('crypt15')) {
          sourceType = 'BACKUP_CRYPT';
          schemaVer = 'Encrypted WhatsApp Backup';
        } else if (fn.endsWith('.txt')) {
          sourceType = 'CHAT_EXPORT';
          schemaVer = 'Exported WhatsApp Chat Archive';
        } else if (/\.(jpg|jpeg|png|opus|mp3|mp4|pdf|webp)$/i.test(fn)) {
          sourceType = 'MEDIA_FILE';
          schemaVer = 'Media Attachment';
        }

        const newArtifact: EvidenceArtifact = {
          evidenceId: `EVID-${Date.now().toString().slice(-4)}-${file.name.slice(0, 8).toUpperCase()}`,
          filename: file.name,
          fileSizeBytes: file.size,
          sha256Hash: sha256,
          importTimestampUtc: new Date().toISOString().replace('T', ' ').replace('Z', ' UTC'),
          sourceType,
          magicBytes: magicHex,
          isReadOnly: true,
          devicePlatform: 'Android',
          schemaVersion: schemaVer,
          notes: 'Examiner file acquired via local workstation ingest interface with read-only lock.'
        };

        onAddArtifact(newArtifact);
      } catch (err) {
        console.error('Error processing file:', err);
      }
    }

    setIsProcessing(false);
    setProgressMsg('');
    if (e.target) e.target.value = '';
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Workspace Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <UploadCloud className="w-5 h-5 text-emerald-400" /> Evidence Ingestion & Cryptographic Acquisition
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Import legally acquired WhatsApp SQLite databases, WAL files, encrypted containers, or load controlled reference cases.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onLoadSampleCase}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-[#172333] hover:bg-[#1e2f45] text-emerald-300 border border-emerald-800/60 rounded transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Load Reference Case (RB-2026-089)</span>
          </button>

          <button
            onClick={onLoadSyntheticBenchmark}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-[#172333] hover:bg-[#1e2f45] text-cyan-300 border border-cyan-800/60 rounded transition-colors"
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Load Ground-Truth Benchmark Case</span>
          </button>
        </div>
      </div>

      {/* Drag & Drop Acquisition Zone */}
      <div className="relative border-2 border-dashed border-[#233347] hover:border-emerald-600/60 bg-[#0d131c] rounded-xl p-10 text-center transition-colors">
        <input
          type="file"
          multiple
          onChange={handleFileUpload}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          disabled={isProcessing}
        />
        <div className="flex flex-col items-center justify-center space-y-3 pointer-events-none">
          <div className="w-12 h-12 rounded-full bg-[#131c28] border border-[#233347] flex items-center justify-center text-emerald-400">
            <UploadCloud className="w-6 h-6" />
          </div>
          <div>
            <div className="text-sm font-semibold text-slate-200">
              Drop forensic files here or click to browse
            </div>
            <div className="text-xs text-slate-400 mt-1">
              Supports: <code className="text-slate-300 font-mono">msgstore.db</code>, <code className="text-slate-300 font-mono">*-wal</code>, <code className="text-slate-300 font-mono">wa.db</code>, <code className="text-slate-300 font-mono">*.crypt12/14/15</code>, <code className="text-slate-300 font-mono">_chat.txt</code>, Media Archives
            </div>
          </div>
          <div className="flex items-center gap-4 text-[11px] text-slate-500 pt-2">
            <span className="flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" /> Automatic SHA-256 Hashing
            </span>
            <span className="flex items-center gap-1">
              <HardDrive className="w-3.5 h-3.5 text-emerald-500" /> Read-Only Working Replica Creation
            </span>
          </div>
        </div>
      </div>

      {isProcessing && (
        <div className="bg-emerald-950/40 border border-emerald-800 p-3 rounded flex items-center gap-3 text-xs text-emerald-300 animate-pulse">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></div>
          <span>{progressMsg || 'Ingesting evidence artifact...'}</span>
        </div>
      )}

      {/* Supported Artifact Profiles Grid */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg space-y-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <Database className="w-4 h-4 text-emerald-400" /> SQLite Databases & WAL
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Parses Android WhatsApp <code className="text-slate-300 font-mono">msgstore.db</code> schemas (v1 to v15), companion <code className="text-slate-300 font-mono">-wal</code> files, and <code className="text-slate-300 font-mono">wa.db</code> contact records.
          </p>
        </div>

        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg space-y-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <Archive className="w-4 h-4 text-emerald-400" /> Encrypted Containers
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Inspects crypt12/14/15 backup containers, extracts PBKDF2 salt parameters, and verifies format headers without key fabrication.
          </p>
        </div>

        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg space-y-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <FileText className="w-4 h-4 text-emerald-400" /> Exported Chat Archives
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Parses exported conversation text logs, correlates timestamps to UTC, and preserves unaltered source lines for chain of custody.
          </p>
        </div>
      </div>
    </div>
  );
};
