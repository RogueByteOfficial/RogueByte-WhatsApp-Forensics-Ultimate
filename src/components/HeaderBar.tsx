import React, { useState, useEffect } from 'react';
import { Shield, Search, RefreshCw, AlertTriangle, CheckCircle2, Lock } from 'lucide-react';
import { CaseMetadata } from '../types/forensics';

interface HeaderBarProps {
  metadata: CaseMetadata;
  activeWorkspaceName: string;
  onVerifyHashes: () => void;
  isVerifying: boolean;
  onSearchOpen: () => void;
  onResetToSample: () => void;
}

export const HeaderBar: React.FC<HeaderBarProps> = ({
  metadata,
  activeWorkspaceName,
  onVerifyHashes,
  isVerifying,
  onSearchOpen,
  onResetToSample,
}) => {
  const [utcTime, setUtcTime] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-14 bg-[#0f151f] border-b border-[#1e293b] flex items-center justify-between px-6 shrink-0 z-10">
      {/* Workspace Breadcrumb & Authorization */}
      <div className="flex items-center gap-3">
        <h1 className="text-sm font-semibold text-slate-100 uppercase tracking-wide flex items-center gap-2">
          <span>{activeWorkspaceName}</span>
        </h1>
        <span className="text-slate-600">/</span>
        <div className="flex items-center gap-1.5 text-xs text-slate-400">
          <span className="text-slate-300 font-medium">{metadata.caseId}:</span>
          <span className="text-slate-400 truncate max-w-[280px]">{metadata.caseTitle}</span>
        </div>
      </div>

      {/* Center / Right Control Panel */}
      <div className="flex items-center gap-3">
        {/* Global Search Trigger */}
        <button
          onClick={onSearchOpen}
          className="flex items-center gap-2 px-3 py-1.5 bg-[#16202e] hover:bg-[#1d2a3d] border border-[#2b3a4f] rounded text-xs text-slate-400 hover:text-slate-200 transition-colors"
          title="Search messages, JIDs, files, and carved payloads"
        >
          <Search className="w-3.5 h-3.5 text-slate-400" />
          <span>Forensic Search...</span>
          <kbd className="text-[10px] bg-[#0d1219] px-1.5 py-0.5 rounded text-slate-500 font-mono">⌘K</kbd>
        </button>

        {/* Cryptographic Hash Verification Button */}
        <button
          onClick={onVerifyHashes}
          disabled={isVerifying}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded font-medium transition-colors border ${
            isVerifying
              ? 'bg-amber-950/40 text-amber-300 border-amber-800 animate-pulse'
              : 'bg-emerald-950/40 hover:bg-emerald-900/50 text-emerald-400 border-emerald-800/60'
          }`}
          title="Recalculate SHA-256 across all evidence working copies"
        >
          {isVerifying ? (
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <Shield className="w-3.5 h-3.5" />
          )}
          <span>{isVerifying ? 'Hashing Evidence...' : 'Verify Hashes'}</span>
        </button>

        {/* Examiner Badge & Time */}
        <div className="flex items-center gap-3 pl-3 border-l border-[#1e293b] text-xs">
          <div className="text-right">
            <div className="text-[11px] font-mono text-emerald-400 font-semibold">{utcTime}</div>
            <div className="text-[10px] text-slate-500 truncate">{metadata.examinerId} · {metadata.examinerName.split(',')[0]}</div>
          </div>
          <div className="w-7 h-7 rounded-full bg-[#1b2535] border border-[#2e3e57] flex items-center justify-center text-slate-300 font-bold text-xs">
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
          </div>
        </div>
      </div>
    </header>
  );
};
