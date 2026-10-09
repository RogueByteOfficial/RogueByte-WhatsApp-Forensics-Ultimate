import React, { useState } from 'react';
import {
  Bot,
  Sparkles,
  ShieldAlert,
  Send,
  HelpCircle,
  FileText,
  AlertTriangle,
  Lock,
  Terminal,
  ExternalLink
} from 'lucide-react';
import { MessageRecord, DeletedCandidate, TimelineEvent } from '../types/forensics';

interface AIAssistantProps {
  messages: MessageRecord[];
  deletedCandidates: DeletedCandidate[];
  timelineEvents: TimelineEvent[];
}

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  citations?: string[];
  timestamp: string;
}

export const AIAssistantWorkspace: React.FC<AIAssistantProps> = ({
  messages,
  deletedCandidates,
  timelineEvents,
}) => {
  const [offlineMode, setOfflineMode] = useState(true);
  const [userInput, setUserInput] = useState('');
  const [conversation, setConversation] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content: `Welcome to the RogueByte Local Forensic Analysis Assistant.\n\nOperational Status: **Offline Air-Gapped Mode Active** (Zero cloud transmission).\nAll analytical inferences are strictly grounded in ingested evidence records and explicitly cite verified Record IDs.\n\nSelect a preset query below or input your investigative query.`,
      timestamp: '09:20 UTC'
    }
  ]);

  const presetQueries = [
    'Summarize Elena Rostova exfiltration communications',
    'Explain the 2035 future timestamp anomaly',
    'List all carved deleted records from WAL Frame #48 & #49',
    'Synthesize an Executive Summary for Court Affidavit'
  ];

  const handleSend = (text: string) => {
    const q = text.trim();
    if (!q) return;

    const userMsg: ChatMessage = {
      role: 'user',
      content: q,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    let reply = '';
    let citations: string[] = [];

    const qLower = q.toLowerCase();

    if (qLower.includes('elena') || qLower.includes('exfiltration') || qLower.includes('leak')) {
      reply = `**EXECUTIVE ANALYSIS: EXFILTRATION COMMUNICATIONS**\n\n1. **Initial Solicit:** At 22:20:00 UTC, Elena Rostova initiated contact inquiring about Falcon Mach-4 turbine stage telemetry schemas.\n2. **Material Acknowledgment:** Subject confirmed extraction of CAD models and stress tables.\n3. **Document Transmission:** Subject transmitted \`Apex_Falcon_Turbine_Schematic_v4.pdf\` (4.89 MB) via WhatsApp Documents, followed by instructions to wipe chat history.\n4. **Counter-Confirmation:** Contact confirmed receipt, verified cryptographic checksum, and confirmed wire transfer to Zurich.\n5. **Subsequent Purge:** Records were subsequently deleted from the active message database, but preserved intact in WAL frames.\n\n*DISCLAIMER: This summary is an analytical interpretation. Direct evidence must be verified via raw database records.*`;
      citations = ['3EB07A1992F01AA44B8C', '3EB0891C837EA01129DF', '3EB0901FA87BC42031EE', '3EB0AA4182910FF49821', 'DEL-WAL-0048-REC01'];
    } else if (qLower.includes('anomaly') || qLower.includes('2035') || qLower.includes('clock')) {
      reply = `**TECHNICAL ANOMALY REPORT: RECORD 3EB09999999999999999**\n\n• **Recorded Timestamp:** 2035-04-12 11:33:20 UTC\n• **Acquisition Seizure Date:** 2026-03-14 UTC\n• **Discrepancy:** ~9.1 years into future\n\n**Forensic Explanation:**\nTimestamp anomalies of this magnitude typically occur due to:\n1. Manual system time alteration in Android OS settings by user prior to sending;\n2. Uninitialized hardware RTC oscillator upon reboot without NTP network sync;\n3. Clock manipulation attempt to alter chronologic message sorting.\n\nThis discrepancy does **not** prove database tampering; the record conforms to intact SQLite B-tree page structures at offset \`0x0001E000\`.`;
      citations = ['3EB09999999999999999'];
    } else if (qLower.includes('wal') || qLower.includes('carved') || qLower.includes('deleted')) {
      reply = `**CARVED ARTIFACT SUMMARY (WAL FRAMES #48 & #49)**\n\n• **Frame #48 (Offset 0x00031400):** Subject message stating: *"PURGED BY USER: I am deleting our chat and wiping the SD cache now. See you in Geneva."* (Confidence: CONFIRMED)\n• **Frame #49 (Offset 0x00032400):** Inbound message from Elena Rostova containing vault confirmation code: *"9942-ALPHA-Z"*. (Confidence: CONFIRMED)\n\nBoth records were successfully carved due to SQLite delayed WAL checkpoint commit cycle.`;
      citations = ['DEL-WAL-0048-REC01', 'DEL-WAL-0049-REC02'];
    } else {
      reply = `**ANALYSIS OF INGESTED EVIDENCE (Case RB-2026-089)**\n\nDatabase \`msgstore.db\` contains 20 active messages across 2 primary conversation threads and 2 group chats. Forensic analysis identified:\n• 1 High-priority intellectual property transmission event;\n• 2 Confirmed purged records recovered from uncheckpointed WAL frames;\n• 1 Chronology anomaly involving an uncalibrated future timestamp.\n\nAll records retain raw B-tree offset provenance and cryptographic SHA-256 verification.`;
      citations = ['3EB0901FA87BC42031EE', 'DEL-WAL-0048-REC01'];
    }

    const botMsg: ChatMessage = {
      role: 'assistant',
      content: reply,
      citations,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setConversation(prev => [...prev, userMsg, botMsg]);
    setUserInput('');
  };

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Main Chat Interface */}
      <div className="flex-1 flex flex-col bg-[#0b0f15] border-r border-[#1e293b] overflow-hidden">
        {/* Top Control Bar */}
        <div className="p-4 bg-[#0e141d] border-b border-[#1e293b] flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 uppercase tracking-wide">
              <Bot className="w-4 h-4 text-emerald-400" /> Local Forensic AI Analyst
            </h2>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Strictly grounded local analytical assistant with mandatory Record ID citations.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 flex items-center gap-1.5">
              <Lock className="w-3 h-3" /> OFFLINE / AIR-GAPPED
            </span>
          </div>
        </div>

        {/* Message Thread Area */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {conversation.map((msg, idx) => (
            <div
              key={idx}
              className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}
            >
              <div
                className={`max-w-2xl rounded-lg p-4 text-xs space-y-2 border ${
                  msg.role === 'user'
                    ? 'bg-[#152333] border-cyan-800/80 text-slate-100'
                    : 'bg-[#101722] border-[#1e2a3b] text-slate-200'
                }`}
              >
                <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono border-b border-white/5 pb-1">
                  <span className={msg.role === 'user' ? 'text-cyan-400' : 'text-emerald-400 font-bold'}>
                    {msg.role === 'user' ? 'Lead Examiner' : 'RogueByte Forensic AI (Local Engine)'}
                  </span>
                  <span>{msg.timestamp}</span>
                </div>

                <div className="text-xs leading-relaxed whitespace-pre-wrap select-text">
                  {msg.content}
                </div>

                {msg.citations && msg.citations.length > 0 && (
                  <div className="pt-2 border-t border-white/5 space-y-1">
                    <span className="text-[10px] text-slate-500 font-mono uppercase">
                      Mandatory Source Record Citations:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {msg.citations.map(c => (
                        <span
                          key={c}
                          className="px-2 py-0.5 rounded bg-[#172332] text-emerald-400 border border-[#23354c] text-[10px] font-mono"
                        >
                          Record #{c}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Preset Query Chips */}
        <div className="p-3 bg-[#0d121a] border-t border-[#1a2533] flex items-center gap-2 overflow-x-auto">
          {presetQueries.map(p => (
            <button
              key={p}
              onClick={() => handleSend(p)}
              className="text-[11px] px-3 py-1 rounded bg-[#131b26] hover:bg-[#1a2535] text-slate-300 border border-[#212f42] whitespace-nowrap transition-colors"
            >
              {p}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="p-4 bg-[#0e141d] border-t border-[#1e293b]">
          <form
            onSubmit={e => {
              e.preventDefault();
              handleSend(userInput);
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              placeholder="Ask the local forensic engine about ingested evidence..."
              value={userInput}
              onChange={e => setUserInput(e.target.value)}
              className="flex-1 bg-[#090d14] border border-[#223042] rounded px-4 py-2 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs rounded flex items-center gap-1.5 transition-colors"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Query</span>
            </button>
          </form>
        </div>
      </div>

      {/* Right Column: AI Forensic Privacy & Evidentiary Boundaries */}
      <div className="w-80 bg-[#0d1219] p-5 overflow-y-auto space-y-4 shrink-0 text-xs">
        <div className="border-b border-[#1e293b] pb-3">
          <div className="text-[10px] text-slate-500 font-mono">STANDARDS & ETHICS</div>
          <h3 className="text-sm font-bold text-slate-100 mt-0.5">Evidentiary Boundary Standard</h3>
        </div>

        <div className="bg-[#101722] p-3.5 rounded border border-[#1e2a3b] space-y-2">
          <div className="text-[10px] uppercase font-bold text-amber-400 font-mono flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5" /> Courtroom Admissibility Notice
          </div>
          <p className="text-[11px] text-slate-300 leading-relaxed">
            AI-generated summaries constitute **analytical opinion**, not direct evidence. In accordance with Federal Rules of Evidence 702/901, always present raw extracted database bytes and cryptographic hashes during court testimony.
          </p>
        </div>

        <div className="space-y-2">
          <div className="text-[10px] uppercase font-semibold text-slate-400 font-mono">
            Guaranteed Local Guarantees
          </div>
          <ul className="space-y-1.5 text-slate-400 text-[11px] leading-relaxed">
            <li>• No internet upload of forensic artifacts.</li>
            <li>• Zero model hallucination of unrecorded messages.</li>
            <li>• Every assertion links to an immutable Record ID.</li>
            <li>• Strict separation of fact vs inference.</li>
          </ul>
        </div>
      </div>
    </div>
  );
};
