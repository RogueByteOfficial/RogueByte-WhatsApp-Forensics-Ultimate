import React, { useState } from 'react';
import {
  Database,
  Play,
  Download,
  Table as TableIcon,
  Code,
  FileCode,
  CheckCircle,
  AlertCircle,
  Copy
} from 'lucide-react';
import { EvidenceArtifact } from '../types/forensics';

interface DatabaseExplorerProps {
  artifacts: EvidenceArtifact[];
}

interface TableColumn {
  name: string;
  type: string;
  pk?: boolean;
}

interface TableSchema {
  name: string;
  rowCount: number;
  columns: TableColumn[];
}

const SCHEMAS: TableSchema[] = [
  {
    name: 'message',
    rowCount: 20,
    columns: [
      { name: '_id', type: 'INTEGER', pk: true },
      { name: 'chat_row_id', type: 'INTEGER' },
      { name: 'from_me', type: 'INTEGER' },
      { name: 'key_id', type: 'TEXT' },
      { name: 'sender_jid_row_id', type: 'INTEGER' },
      { name: 'timestamp', type: 'INTEGER' },
      { name: 'text_data', type: 'TEXT' },
      { name: 'message_type', type: 'INTEGER' },
      { name: 'status', type: 'INTEGER' }
    ]
  },
  {
    name: 'jid',
    rowCount: 5,
    columns: [
      { name: '_id', type: 'INTEGER', pk: true },
      { name: 'user', type: 'TEXT' },
      { name: 'server', type: 'TEXT' },
      { name: 'raw_string', type: 'TEXT' }
    ]
  },
  {
    name: 'chat',
    rowCount: 4,
    columns: [
      { name: '_id', type: 'INTEGER', pk: true },
      { name: 'jid_row_id', type: 'INTEGER' },
      { name: 'subject', type: 'TEXT' },
      { name: 'sort_timestamp', type: 'INTEGER' }
    ]
  },
  {
    name: 'message_media',
    rowCount: 2,
    columns: [
      { name: 'message_row_id', type: 'INTEGER', pk: true },
      { name: 'file_path', type: 'TEXT' },
      { name: 'file_size', type: 'INTEGER' },
      { name: 'file_hash', type: 'TEXT' }
    ]
  }
];

export const DatabaseExplorerWorkspace: React.FC<DatabaseExplorerProps> = ({ artifacts }) => {
  const [selectedTable, setSelectedTable] = useState<string>('message');
  const [sqlQuery, setSqlQuery] = useState<string>(
    'SELECT _id, key_id, from_me, timestamp, text_data, status FROM message ORDER BY timestamp DESC LIMIT 15;'
  );
  const [queryDurationMs, setQueryDurationMs] = useState<number>(0.84);

  // Simulated live query results based on selected query
  const [queryResult, setQueryResult] = useState<{
    columns: string[];
    rows: (string | number | null)[][];
  }>({
    columns: ['_id', 'key_id', 'from_me', 'timestamp', 'text_data', 'status'],
    rows: [
      [199, '3EB09999999999999999', 1, 2060000000000, 'Meeting notes draft scheduled for sync.', 0],
      [192, '3EB0AA4182910FF49821', 0, 1773440800000, 'Blueprint received and checksum verified. Wire transfer confirmed.', 13],
      [190, '3EB0901FA87BC42031EE', 1, 1773440640000, 'Sending the encrypted PDF blueprint now. Make sure you delete the chat...', 13],
      [189, '3EB0891C837EA01129DF', 1, 1773440520000, 'I extracted the CAD models and materials stress tables from the vault...', 13],
      [188, '3EB07A1992F01AA44B8C', 0, 1773440400000, 'Are you prepared to provide the telemetry schemas for the Falcon...', 13],
      [142, '3EB09918204918290123', 0, 1773426000000, 'Team, please review the latest stress report before the board meeting...', 0]
    ]
  });

  const runQuery = (query: string) => {
    const qLower = query.toLowerCase().trim();
    const start = performance.now();

    if (qLower.includes('integrity_check')) {
      setQueryResult({
        columns: ['integrity_check'],
        rows: [['ok']]
      });
    } else if (qLower.includes('freelist_count')) {
      setQueryResult({
        columns: ['freelist_count'],
        rows: [[12]]
      });
    } else if (qLower.includes('sqlite_master')) {
      setQueryResult({
        columns: ['type', 'name', 'tbl_name', 'rootpage'],
        rows: [
          ['table', 'jid', 'jid', 2],
          ['table', 'chat', 'chat', 3],
          ['table', 'message', 'message', 4],
          ['table', 'message_media', 'message_media', 5]
        ]
      });
    } else if (qLower.includes('from jid')) {
      setQueryResult({
        columns: ['_id', 'user', 'server', 'raw_string'],
        rows: [
          [1, '12065550843', 's.whatsapp.net', '12065550843@s.whatsapp.net'],
          [2, '14155550192', 's.whatsapp.net', '14155550192@s.whatsapp.net'],
          [3, '14155550999', 's.whatsapp.net', '14155550999@s.whatsapp.net'],
          [4, '12036304918239101', 'g.us', '12036304918239101@g.us'],
          [5, '12036319847120934', 'g.us', '12036319847120934@g.us']
        ]
      });
    } else if (qLower.includes('from chat')) {
      setQueryResult({
        columns: ['_id', 'jid_row_id', 'subject', 'sort_timestamp'],
        rows: [
          [1, 1, 'Elena Rostova (Apex Competitor)', 1773440800000],
          [2, 4, 'Project Apex Falcon Core Engineering', 1773426000000],
          [3, 5, 'Off-Grid Offshore Transfer', 1773441000000],
          [4, 2, 'Dr. Gregory Finch', 1773400000000]
        ]
      });
    } else {
      // Default message query
      setQueryResult({
        columns: ['_id', 'key_id', 'from_me', 'timestamp', 'text_data', 'status'],
        rows: [
          [199, '3EB09999999999999999', 1, 2060000000000, 'Meeting notes draft scheduled for sync.', 0],
          [192, '3EB0AA4182910FF49821', 0, 1773440800000, 'Blueprint received and checksum verified. Wire transfer confirmed.', 13],
          [190, '3EB0901FA87BC42031EE', 1, 1773440640000, 'Sending the encrypted PDF blueprint now. Make sure you delete the chat...', 13],
          [189, '3EB0891C837EA01129DF', 1, 1773440520000, 'I extracted the CAD models and materials stress tables from the vault...', 13],
          [188, '3EB07A1992F01AA44B8C', 0, 1773440400000, 'Are you prepared to provide the telemetry schemas for the Falcon...', 13]
        ]
      });
    }

    setQueryDurationMs(Math.max(0.12, (performance.now() - start)));
  };

  const handleExportCsv = () => {
    const csvContent = [
      queryResult.columns.join(','),
      ...queryResult.rows.map(row => row.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SQL_QueryResult_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Left Pane: Database Header & Schema Explorer */}
      <div className="w-80 bg-[#0d1219] border-r border-[#1e293b] flex flex-col shrink-0">
        {/* SQLite 100-byte Header Stats */}
        <div className="p-4 border-b border-[#1e293b] space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5 uppercase tracking-wider">
              <Database className="w-4 h-4 text-emerald-400" /> msgstore.db
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
              PRAGMA OK
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-[11px] font-mono bg-[#111722] p-2.5 rounded border border-[#1d2737]">
            <div>
              <span className="text-slate-500 block">Page Size</span>
              <span className="text-slate-200 font-semibold">4096 bytes</span>
            </div>
            <div>
              <span className="text-slate-500 block">Write Version</span>
              <span className="text-emerald-400 font-semibold">2 (WAL Mode)</span>
            </div>
            <div>
              <span className="text-slate-500 block">Encoding</span>
              <span className="text-slate-200 font-semibold">UTF-8</span>
            </div>
            <div>
              <span className="text-slate-500 block">Freelist Pages</span>
              <span className="text-amber-400 font-semibold">12 pages</span>
            </div>
          </div>
        </div>

        {/* Tables & Schema List */}
        <div className="flex-1 overflow-y-auto p-3 space-y-3">
          <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 px-1">
            Database Schema Tables
          </div>

          {SCHEMAS.map(t => {
            const isSelected = selectedTable === t.name;
            return (
              <div
                key={t.name}
                onClick={() => {
                  setSelectedTable(t.name);
                  const q = `SELECT * FROM ${t.name} LIMIT 25;`;
                  setSqlQuery(q);
                  runQuery(q);
                }}
                className={`p-2.5 rounded cursor-pointer transition-colors border ${
                  isSelected
                    ? 'bg-[#15202e] border-emerald-800/80 text-emerald-300'
                    : 'bg-[#101620] border-[#1b2533] hover:bg-[#141b26] text-slate-300'
                }`}
              >
                <div className="flex items-center justify-between text-xs font-semibold">
                  <div className="flex items-center gap-1.5">
                    <TableIcon className="w-3.5 h-3.5 text-emerald-400" />
                    <span>{t.name}</span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500">~{t.rowCount} rows</span>
                </div>

                <div className="mt-2 text-[10px] text-slate-500 font-mono space-y-0.5 pl-5">
                  {t.columns.slice(0, 4).map(c => (
                    <div key={c.name} className="flex justify-between">
                      <span className={c.pk ? 'text-amber-400 font-bold' : ''}>
                        {c.name} {c.pk ? '(PK)' : ''}
                      </span>
                      <span className="text-slate-600">{c.type}</span>
                    </div>
                  ))}
                  {t.columns.length > 4 && (
                    <div className="text-slate-600 italic">+{t.columns.length - 4} more columns</div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Pane: Interactive SQL Console & Data Grid */}
      <div className="flex-1 flex flex-col bg-[#0b0f15] overflow-hidden">
        {/* SQL Query Editor Box */}
        <div className="p-4 bg-[#0e141d] border-b border-[#1e293b] space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
              <Code className="w-4 h-4 text-emerald-400" /> SQL Forensic Query Console
            </div>

            <div className="flex items-center gap-2">
              {/* Query Templates Dropdown buttons */}
              <button
                onClick={() => {
                  const q = 'PRAGMA integrity_check;';
                  setSqlQuery(q);
                  runQuery(q);
                }}
                className="text-[11px] px-2 py-1 rounded bg-[#16202c] hover:bg-[#1e2b3c] text-slate-300 border border-[#243346]"
              >
                PRAGMA integrity_check
              </button>
              <button
                onClick={() => {
                  const q = 'PRAGMA freelist_count;';
                  setSqlQuery(q);
                  runQuery(q);
                }}
                className="text-[11px] px-2 py-1 rounded bg-[#16202c] hover:bg-[#1e2b3c] text-slate-300 border border-[#243346]"
              >
                PRAGMA freelist_count
              </button>
              <button
                onClick={() => {
                  const q = 'SELECT _id, key_id, from_me, timestamp, text_data, status FROM message ORDER BY timestamp DESC LIMIT 15;';
                  setSqlQuery(q);
                  runQuery(q);
                }}
                className="text-[11px] px-2 py-1 rounded bg-[#16202c] hover:bg-[#1e2b3c] text-slate-300 border border-[#243346]"
              >
                Recent Messages
              </button>
            </div>
          </div>

          <div className="relative">
            <textarea
              rows={3}
              value={sqlQuery}
              onChange={e => setSqlQuery(e.target.value)}
              className="w-full bg-[#080c12] border border-[#223042] rounded p-3 text-xs font-mono text-emerald-300 focus:outline-none focus:border-emerald-500 leading-relaxed resize-none"
            />
          </div>

          <div className="flex items-center justify-between text-xs">
            <span className="text-[11px] text-slate-500 font-mono">
              Executed in {queryDurationMs.toFixed(2)} ms · {queryResult.rows.length} rows returned
            </span>

            <div className="flex items-center gap-2">
              <button
                onClick={handleExportCsv}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#16202c] hover:bg-[#1e2b3c] text-slate-200 border border-[#253548] rounded transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-slate-400" />
                <span>Export CSV</span>
              </button>

              <button
                onClick={() => runQuery(sqlQuery)}
                className="flex items-center gap-1.5 px-4 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold rounded transition-colors shadow-sm"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Run Query (F5)</span>
              </button>
            </div>
          </div>
        </div>

        {/* Query Results Table Grid */}
        <div className="flex-1 overflow-auto p-4">
          <div className="bg-[#101722] border border-[#1e2a3b] rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="bg-[#090d14] border-b border-[#1e2a3b] text-slate-400 text-[11px] uppercase tracking-wider">
                  {queryResult.columns.map((col, idx) => (
                    <th key={idx} className="p-2.5 font-semibold text-slate-300 border-r border-[#172230] last:border-r-0">
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#172230]">
                {queryResult.rows.map((row, rIdx) => (
                  <tr key={rIdx} className="hover:bg-[#141d29] transition-colors">
                    {row.map((cell, cIdx) => (
                      <td key={cIdx} className="p-2.5 text-slate-300 border-r border-[#172230] last:border-r-0 truncate max-w-xs">
                        {cell === null ? (
                          <span className="text-slate-600 italic">NULL</span>
                        ) : (
                          String(cell)
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
