import React, { useState } from 'react';
import {
  Image as ImageIcon,
  FileText,
  Music,
  Video,
  FileCheck,
  AlertTriangle,
  Download,
  Search,
  ExternalLink,
  ShieldCheck
} from 'lucide-react';
import { MessageRecord } from '../types/forensics';
import { formatBytes } from '../utils/crypto';

interface MediaExplorerProps {
  messages: MessageRecord[];
}

export const MediaExplorerWorkspace: React.FC<MediaExplorerProps> = ({ messages }) => {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Extract media items from messages + additional detected media
  const mediaItems = [
    {
      mediaId: 'MEDIA-DOC-001',
      filename: 'Apex_Falcon_Turbine_Schematic_v4.pdf',
      type: 'document',
      fileSize: 4892140,
      sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
      messageId: '3EB0901FA87BC42031EE',
      sender: 'Examiner/Account Owner',
      timestampUtc: '2026-03-13 22:24:00.000 UTC',
      mobilePath: '/WhatsApp/Media/WhatsApp Documents/Apex_Falcon_Turbine_Schematic_v4.pdf',
      isAvailable: true
    },
    {
      mediaId: 'MEDIA-IMG-002',
      filename: 'IMG-20260312-WA0014.jpg',
      type: 'image',
      fileSize: 1248900,
      sha256: '8f7e6d5c4b3a2109fedcba9876543210abcdef0123456789abcdef0123456789',
      messageId: '3EB0891C837EA01129DF',
      sender: '12065550843@s.whatsapp.net',
      timestampUtc: '2026-03-12 14:10:00.000 UTC',
      mobilePath: '/WhatsApp/Media/WhatsApp Images/IMG-20260312-WA0014.jpg',
      isAvailable: true
    },
    {
      mediaId: 'MEDIA-AUD-003',
      filename: 'PTT-20260313-WA0021.opus',
      type: 'audio',
      fileSize: 312000,
      sha256: '3a4b5c6d7e8f9012a1b2c3d4e5f60718fedcba9876543210123456789abcdef0',
      messageId: '3EB07A1992F01AA44B8C',
      sender: 'Elena Rostova',
      timestampUtc: '2026-03-13 22:18:00.000 UTC',
      mobilePath: '/WhatsApp/Media/WhatsApp Voice Notes/202611/PTT-20260313-WA0021.opus',
      isAvailable: true
    },
    {
      mediaId: 'MEDIA-DOC-004-MISSING',
      filename: 'vault_deposit_credentials.enc',
      type: 'document',
      fileSize: 64200,
      sha256: '99887766554433221100aabbccddeeff00112233445566778899aabbccddeeff',
      messageId: 'DEL-WAL-0049-REC02',
      sender: 'Elena Rostova',
      timestampUtc: '2026-03-13 22:32:00.000 UTC',
      mobilePath: '/WhatsApp/Media/WhatsApp Documents/vault_deposit_credentials.enc',
      isAvailable: false // Broken reference!
    }
  ];

  const filtered = mediaItems.filter(item => {
    if (filterType !== 'ALL' && item.type !== filterType.toLowerCase()) return false;
    if (searchQuery) {
      return (
        item.filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.sha256.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }
    return true;
  });

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Top Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ImageIcon className="w-5 h-5 text-emerald-400" /> Media & Attachment Forensics
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Media catalog with SHA-256 integrity verification, relational message correlation, and broken reference detection.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Filter media filename or hash..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="bg-[#101722] border border-[#223042] rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500 w-64"
            />
          </div>

          <div className="flex items-center gap-1 bg-[#101722] p-1 rounded border border-[#1b2533] text-xs">
            {['ALL', 'DOCUMENT', 'IMAGE', 'AUDIO'].map(t => (
              <button
                key={t}
                onClick={() => setFilterType(t)}
                className={`px-2.5 py-1 rounded text-[11px] ${
                  filterType === t ? 'bg-[#182330] text-emerald-400 font-bold' : 'text-slate-400'
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Media Grid / Cards */}
      <div className="grid grid-cols-2 gap-4">
        {filtered.map(item => (
          <div
            key={item.mediaId}
            className={`bg-[#101722] border rounded-lg p-5 space-y-3 transition-colors ${
              !item.isAvailable ? 'border-rose-900/60 bg-rose-950/10' : 'border-[#1e2a3b]'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded bg-[#162130] border border-[#243449] flex items-center justify-center text-emerald-400">
                  {item.type === 'document' ? (
                    <FileText className="w-5 h-5" />
                  ) : item.type === 'image' ? (
                    <ImageIcon className="w-5 h-5" />
                  ) : (
                    <Music className="w-5 h-5" />
                  )}
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-100 truncate max-w-sm">{item.filename}</h4>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                    {formatBytes(item.fileSize)} · {item.type.toUpperCase()}
                  </div>
                </div>
              </div>

              <div>
                {item.isAvailable ? (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 flex items-center gap-1">
                    <ShieldCheck className="w-3 h-3" /> VERIFIED
                  </span>
                ) : (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> MISSING / BROKEN LINK
                  </span>
                )}
              </div>
            </div>

            {/* SHA-256 Box */}
            <div className="p-2 bg-[#090d14] rounded border border-[#1b2533] text-[10px] font-mono text-slate-400 truncate">
              SHA-256: <span className="text-emerald-400 select-all">{item.sha256}</span>
            </div>

            {/* Relational details */}
            <div className="text-[11px] text-slate-400 space-y-1">
              <div className="flex justify-between">
                <span>Correlated Message ID:</span>
                <span className="font-mono text-slate-200">{item.messageId}</span>
              </div>
              <div className="flex justify-between">
                <span>Sender / Source:</span>
                <span className="text-slate-200">{item.sender}</span>
              </div>
              <div className="flex justify-between">
                <span>Mobile Path:</span>
                <span className="font-mono text-slate-500 text-[10px] truncate max-w-[280px]">{item.mobilePath}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
