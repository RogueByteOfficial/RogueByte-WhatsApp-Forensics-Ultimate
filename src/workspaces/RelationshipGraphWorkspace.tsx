import React from 'react';
import {
  Network,
  Users,
  User,
  ArrowRight,
  TrendingUp,
  MessageSquare,
  ShieldCheck
} from 'lucide-react';
import { ContactRecord, ConversationRecord } from '../types/forensics';

interface RelationshipProps {
  contacts: ContactRecord[];
  conversations: ConversationRecord[];
}

export const RelationshipGraphWorkspace: React.FC<RelationshipProps> = ({ contacts, conversations }) => {
  const directChats = conversations.filter(c => !c.isGroup);
  const groupChats = conversations.filter(c => c.isGroup);

  const topContacts = [...contacts].sort((a, b) => b.messageCount - a.messageCount);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Top Banner */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Network className="w-5 h-5 text-emerald-400" /> Contact & Group Relationship Matrix
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Relational analysis of communication channels, interaction frequency, and cluster metadata.
        </p>
      </div>

      {/* Summary Stat Cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Identified Identities</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{contacts.length} JIDs</div>
          <div className="text-[11px] text-slate-500 mt-1">Synced via wa.db & jid tables</div>
        </div>

        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Direct 1-on-1 Threads</div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-1">{directChats.length} Channels</div>
          <div className="text-[11px] text-slate-500 mt-1">Private interlocutors</div>
        </div>

        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Group Workspaces</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">{groupChats.length} Multi-User</div>
          <div className="text-[11px] text-slate-500 mt-1">Enterprise & ad-hoc groups</div>
        </div>
      </div>

      {/* Two Column Grid: Top Interlocutors & Interaction Matrix */}
      <div className="grid grid-cols-2 gap-6">
        {/* Top Contacts Ranking */}
        <div className="bg-[#111722] border border-[#1e2a3b] p-5 rounded-lg space-y-4">
          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2 border-b border-[#1e2a3b] pb-3">
            <TrendingUp className="w-4 h-4 text-emerald-400" /> Communication Frequency Leaderboard
          </h3>

          <div className="space-y-3">
            {topContacts.map(c => (
              <div
                key={c.jid}
                className="p-3 bg-[#0e141e] border border-[#1c2738] rounded flex items-center justify-between text-xs"
              >
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                    c.isGroup ? 'bg-indigo-950 text-indigo-400 border border-indigo-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  }`}>
                    {c.isGroup ? <Users className="w-4 h-4" /> : <User className="w-4 h-4" />}
                  </div>
                  <div>
                    <div className="font-semibold text-slate-100">{c.displayName}</div>
                    <div className="text-[10px] text-slate-500 font-mono truncate max-w-[220px]">{c.jid}</div>
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-sm font-bold font-mono text-emerald-400">{c.messageCount}</div>
                  <div className="text-[10px] text-slate-500">messages</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Group & Cluster Details */}
        <div className="bg-[#111722] border border-[#1e2a3b] p-5 rounded-lg space-y-4">
          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2 border-b border-[#1e2a3b] pb-3">
            <Users className="w-4 h-4 text-emerald-400" /> Multi-Participant Group Channels
          </h3>

          <div className="space-y-3">
            {groupChats.map(g => (
              <div
                key={g.jid}
                className="p-3 bg-[#0e141e] border border-[#1c2738] rounded space-y-2 text-xs"
              >
                <div className="flex items-center justify-between">
                  <div className="font-semibold text-slate-100">{g.displayName}</div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#172435] text-slate-300">
                    {g.totalMessages} Messages
                  </span>
                </div>

                <div className="text-[10px] text-slate-500 font-mono truncate">
                  Group ID: {g.jid}
                </div>

                <div className="pt-2 border-t border-[#172230] text-[11px] text-slate-400">
                  <span className="text-slate-500">Key Participants:</span>{' '}
                  <span className="font-mono text-slate-300">
                    {g.participants.join(', ')}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
