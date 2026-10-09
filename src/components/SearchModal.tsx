import React, { useState } from 'react';
import { Search, X, MessageSquare, SearchCode, Shield, ArrowRight } from 'lucide-react';
import { MessageRecord, DeletedCandidate, EvidenceArtifact } from '../types/forensics';

interface SearchModalProps {
  isOpen: boolean;
  onClose: () => void;
  messages: MessageRecord[];
  deletedCandidates: DeletedCandidate[];
  artifacts: EvidenceArtifact[];
  onSelectResult: (type: 'message' | 'deleted' | 'artifact', id: string) => void;
}

export const SearchModal: React.FC<SearchModalProps> = ({
  isOpen,
  onClose,
  messages,
  deletedCandidates,
  artifacts,
  onSelectResult,
}) => {
  const [query, setQuery] = useState('');

  if (!isOpen) return null;

  const q = query.toLowerCase().trim();

  const matchedMessages = q
    ? messages.filter(
        m =>
          (m.textContent && m.textContent.toLowerCase().includes(q)) ||
          m.senderJid.toLowerCase().includes(q) ||
          m.remoteJid.toLowerCase().includes(q) ||
          m.messageId.toLowerCase().includes(q)
      )
    : [];

  const matchedCarved = q
    ? deletedCandidates.filter(
        d =>
          (d.decodedText && d.decodedText.toLowerCase().includes(q)) ||
          d.candidateId.toLowerCase().includes(q) ||
          d.sourceFile.toLowerCase().includes(q)
      )
    : [];

  const matchedArtifacts = q
    ? artifacts.filter(
        a =>
          a.filename.toLowerCase().includes(q) ||
          a.evidenceId.toLowerCase().includes(q) ||
          a.sha256Hash.toLowerCase().includes(q)
      )
    : [];

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-xs flex items-start justify-center pt-24 p-4 z-50">
      <div className="bg-[#101722] border border-[#27394f] rounded-xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[70vh]">
        {/* Search Input Bar */}
        <div className="p-4 border-b border-[#1e2a3b] flex items-center gap-3">
          <Search className="w-4 h-4 text-emerald-400 shrink-0" />
          <input
            type="text"
            autoFocus
            placeholder="Search all messages, JIDs, carved payloads, SHA-256 hashes..."
            value={query}
            onChange={e => setQuery(e.target.value)}
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
          />
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 p-1"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {!q ? (
            <div className="text-center py-12 text-xs text-slate-500">
              Type keywords, participant phone numbers, message IDs, or hex strings.
            </div>
          ) : (
            <>
              {/* Messages Group */}
              {matchedMessages.length > 0 && (
                <div className="space-y-2">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold flex items-center gap-1.5">
                    <MessageSquare className="w-3 h-3 text-emerald-400" /> Confirmed Messages ({matchedMessages.length})
                  </div>
                  <div className="space-y-1.5">
                    {matchedMessages.slice(0, 5).map(m => (
                      <div
                        key={m.messageId}
                        onClick={() => {
                          onSelectResult('message', m.messageId);
                          onClose();
                        }}
                        className="p-2.5 bg-[#141d29] hover:bg-[#1a2636] border border-[#1f2d3f] rounded cursor-pointer transition-colors text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                          <span className="text-emerald-400 font-semibold">{m.senderName || m.senderJid}</span>
                          <span>{m.timestampUtc}</span>
                        </div>
                        <p className="text-slate-200 line-clamp-2">{m.textContent}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Carved Deleted Group */}
              {matchedCarved.length > 0 && (
                <div className="space-y-2">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold flex items-center gap-1.5">
                    <SearchCode className="w-3 h-3 text-amber-400" /> Carved Deleted Artifacts ({matchedCarved.length})
                  </div>
                  <div className="space-y-1.5">
                    {matchedCarved.slice(0, 5).map(c => (
                      <div
                        key={c.candidateId}
                        onClick={() => {
                          onSelectResult('deleted', c.candidateId);
                          onClose();
                        }}
                        className="p-2.5 bg-amber-950/20 hover:bg-amber-950/30 border border-amber-800/60 rounded cursor-pointer transition-colors text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between text-[11px] font-mono text-amber-300">
                          <span>{c.candidateId} · {c.confidence}</span>
                          <span>Offset: 0x{c.byteOffset.toString(16).toUpperCase()}</span>
                        </div>
                        <p className="text-amber-100">{c.decodedText}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Artifacts Group */}
              {matchedArtifacts.length > 0 && (
                <div className="space-y-2">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold flex items-center gap-1.5">
                    <Shield className="w-3 h-3 text-cyan-400" /> Evidence Artifacts ({matchedArtifacts.length})
                  </div>
                  <div className="space-y-1.5">
                    {matchedArtifacts.slice(0, 3).map(a => (
                      <div
                        key={a.evidenceId}
                        onClick={() => {
                          onSelectResult('artifact', a.evidenceId);
                          onClose();
                        }}
                        className="p-2.5 bg-[#141d29] hover:bg-[#1a2636] border border-[#1f2d3f] rounded cursor-pointer transition-colors text-xs flex justify-between items-center"
                      >
                        <div>
                          <div className="font-semibold text-slate-200">{a.filename}</div>
                          <div className="text-[10px] text-slate-500 font-mono truncate max-w-md">{a.sha256Hash}</div>
                        </div>
                        <span className="text-[10px] font-mono text-slate-400">{a.evidenceId}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {matchedMessages.length === 0 && matchedCarved.length === 0 && matchedArtifacts.length === 0 && (
                <div className="text-center py-12 text-xs text-slate-500">
                  No records matched &quot;{query}&quot;.
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};
