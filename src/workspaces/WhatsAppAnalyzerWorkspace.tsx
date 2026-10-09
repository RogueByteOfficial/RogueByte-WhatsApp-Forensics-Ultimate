import React, { useState } from 'react';
import {
  MessageSquare,
  Users,
  User,
  Search,
  Filter,
  FileText,
  Clock,
  CheckCheck,
  Check,
  AlertTriangle,
  Download,
  ShieldAlert,
  ArrowRight
} from 'lucide-react';
import { ConversationRecord, MessageRecord, ContactRecord } from '../types/forensics';
import { formatUtcToLocal, formatHexOffset } from '../utils/crypto';

interface WhatsAppAnalyzerProps {
  conversations: ConversationRecord[];
  messages: MessageRecord[];
  contacts: ContactRecord[];
}

export const WhatsAppAnalyzerWorkspace: React.FC<WhatsAppAnalyzerProps> = ({
  conversations,
  messages,
  contacts,
}) => {
  const [selectedJid, setSelectedJid] = useState<string>(
    conversations.length > 0 ? conversations[0].jid : ''
  );
  const [chatFilter, setChatFilter] = useState<'all' | 'direct' | 'groups'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [msgFilter, setMsgFilter] = useState<'all' | 'deleted' | 'media'>('all');

  // Filter conversations
  const filteredConversations = conversations.filter(c => {
    if (chatFilter === 'direct' && c.isGroup) return false;
    if (chatFilter === 'groups' && !c.isGroup) return false;
    if (searchQuery) {
      return (
        c.displayName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.jid.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }
    return true;
  });

  const activeConversation = conversations.find(c => c.jid === selectedJid) || conversations[0];

  // Filter messages for active chat
  const threadMessages = messages.filter(m => {
    if (m.remoteJid !== selectedJid) return false;
    if (msgFilter === 'deleted' && !m.isDeleted) return false;
    if (msgFilter === 'media' && m.messageType === 'text') return false;
    return true;
  });

  const handleExportThread = () => {
    if (!activeConversation) return;
    const threadData = {
      conversation: activeConversation,
      messages: threadMessages,
      exportedUtc: new Date().toISOString()
    };
    const blob = new Blob([JSON.stringify(threadData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Thread_${activeConversation.jid.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Left Pane: Conversations List */}
      <div className="w-80 bg-[#0d1219] border-r border-[#1e293b] flex flex-col shrink-0">
        {/* Search & Filters */}
        <div className="p-3 border-b border-[#1e293b] space-y-2.5">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search conversations..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full bg-[#131b26] border border-[#202e40] rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="flex items-center gap-1 bg-[#101721] p-1 rounded border border-[#1a2636]">
            <button
              onClick={() => setChatFilter('all')}
              className={`flex-1 py-1 text-[11px] rounded transition-colors ${
                chatFilter === 'all' ? 'bg-[#1b2636] text-emerald-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({conversations.length})
            </button>
            <button
              onClick={() => setChatFilter('direct')}
              className={`flex-1 py-1 text-[11px] rounded transition-colors ${
                chatFilter === 'direct' ? 'bg-[#1b2636] text-emerald-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Direct
            </button>
            <button
              onClick={() => setChatFilter('groups')}
              className={`flex-1 py-1 text-[11px] rounded transition-colors ${
                chatFilter === 'groups' ? 'bg-[#1b2636] text-emerald-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Groups
            </button>
          </div>
        </div>

        {/* Conversation List Items */}
        <div className="flex-1 overflow-y-auto divide-y divide-[#151f2b]">
          {filteredConversations.map(conv => {
            const isSelected = conv.jid === selectedJid;
            return (
              <button
                key={conv.jid}
                onClick={() => setSelectedJid(conv.jid)}
                className={`w-full text-left p-3 transition-colors flex items-start gap-2.5 ${
                  isSelected ? 'bg-[#15202e] border-l-2 border-emerald-500' : 'hover:bg-[#111822]'
                }`}
              >
                <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${
                  conv.isGroup ? 'bg-indigo-950 text-indigo-400 border border-indigo-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                }`}>
                  {conv.isGroup ? <Users className="w-4 h-4" /> : <User className="w-4 h-4" />}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className={`text-xs font-semibold truncate ${isSelected ? 'text-slate-100' : 'text-slate-200'}`}>
                      {conv.displayName}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {conv.totalMessages} msgs
                    </span>
                  </div>

                  <div className="text-[10px] font-mono text-slate-500 truncate mt-0.5">
                    {conv.jid}
                  </div>

                  {conv.deletedRecoveredMessages > 0 && (
                    <div className="mt-1 flex items-center gap-1 text-[10px] text-amber-400 font-mono">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
                      <span>{conv.deletedRecoveredMessages} carved deleted msgs</span>
                    </div>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Right Pane: Thread Content */}
      <div className="flex-1 flex flex-col bg-[#0b0f15] overflow-hidden">
        {activeConversation ? (
          <>
            {/* Thread Header */}
            <div className="p-4 bg-[#0e141d] border-b border-[#1e293b] flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-slate-100">{activeConversation.displayName}</h3>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#172230] text-slate-400 border border-[#243449]">
                    {activeConversation.isGroup ? 'Group Conversation' : 'Direct 1-on-1'}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-slate-500 mt-0.5">
                  Target JID: {activeConversation.jid}
                </div>
              </div>

              <div className="flex items-center gap-3">
                {/* Filter buttons */}
                <div className="flex items-center gap-1 bg-[#121a24] p-1 rounded border border-[#1e2b3c] text-xs">
                  <button
                    onClick={() => setMsgFilter('all')}
                    className={`px-2 py-0.5 rounded text-[11px] ${msgFilter === 'all' ? 'bg-emerald-950 text-emerald-300 font-medium' : 'text-slate-400'}`}
                  >
                    All
                  </button>
                  <button
                    onClick={() => setMsgFilter('deleted')}
                    className={`px-2 py-0.5 rounded text-[11px] ${msgFilter === 'deleted' ? 'bg-amber-950 text-amber-300 font-medium' : 'text-slate-400'}`}
                  >
                    Carved Deleted Only
                  </button>
                  <button
                    onClick={() => setMsgFilter('media')}
                    className={`px-2 py-0.5 rounded text-[11px] ${msgFilter === 'media' ? 'bg-cyan-950 text-cyan-300 font-medium' : 'text-slate-400'}`}
                  >
                    Media / Docs
                  </button>
                </div>

                <button
                  onClick={handleExportThread}
                  className="flex items-center gap-1.5 px-3 py-1 text-xs bg-[#172433] hover:bg-[#1f3044] text-slate-200 border border-[#293d54] rounded transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Export Thread</span>
                </button>
              </div>
            </div>

            {/* Messages Scroll Area */}
            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {threadMessages.length === 0 ? (
                <div className="text-center py-20 text-xs text-slate-500">
                  No messages matched current filter criteria.
                </div>
              ) : (
                threadMessages.map(msg => {
                  const isOutbound = msg.isFromMe;
                  return (
                    <div
                      key={msg.messageId}
                      className={`flex flex-col ${isOutbound ? 'items-end' : 'items-start'}`}
                    >
                      {/* Message Bubble Card */}
                      <div
                        className={`max-w-2xl rounded-lg p-3.5 text-xs shadow-sm border ${
                          msg.isDeleted
                            ? 'bg-amber-950/20 border-amber-800/80 text-amber-100'
                            : isOutbound
                            ? 'bg-[#152726] border-emerald-800/60 text-slate-100'
                            : 'bg-[#121924] border-[#223042] text-slate-100'
                        }`}
                      >
                        {/* Header: Sender & Confidence */}
                        <div className="flex items-center justify-between gap-4 mb-1.5 border-b border-white/5 pb-1 text-[11px]">
                          <span className={`font-semibold ${isOutbound ? 'text-emerald-400' : 'text-cyan-400'}`}>
                            {msg.senderName || msg.senderJid}
                          </span>
                          <div className="flex items-center gap-1.5">
                            {msg.isDeleted && (
                              <span className="text-[10px] font-bold font-mono px-1.5 py-0.2 rounded bg-amber-900/60 text-amber-300 border border-amber-700">
                                {msg.confidence} DELETED CARVE
                              </span>
                            )}
                            <span className="text-[10px] text-slate-400 font-mono">
                              {msg.sourceFile}
                            </span>
                          </div>
                        </div>

                        {/* Body / Text */}
                        <div className="text-[13px] leading-relaxed whitespace-pre-wrap select-text">
                          {msg.textContent}
                        </div>

                        {/* Attachment Card if present */}
                        {msg.mediaPath && (
                          <div className="mt-2.5 p-2.5 bg-black/30 rounded border border-white/10 flex items-center justify-between text-[11px]">
                            <div className="flex items-center gap-2 truncate">
                              <FileText className="w-4 h-4 text-emerald-400 shrink-0" />
                              <div className="truncate">
                                <div className="font-mono text-slate-200 truncate">{msg.mediaPath.split('/').pop()}</div>
                                <div className="text-[10px] text-slate-500 font-mono truncate">SHA-256: {msg.mediaSha256?.substring(0, 24)}...</div>
                              </div>
                            </div>
                            <span className="text-[10px] font-mono text-emerald-400 shrink-0 ml-2">VERIFIED</span>
                          </div>
                        )}

                        {/* Recovery Notes if Deleted */}
                        {msg.notes && (
                          <div className="mt-2 pt-1.5 border-t border-amber-800/40 text-[10px] text-amber-300/90 font-mono">
                            ↳ {msg.notes}
                          </div>
                        )}

                        {/* Footer: Provenance & Timestamps */}
                        <div className="mt-2 pt-1 border-t border-white/5 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                          <span title="Raw B-Tree offset">
                            Offset: {formatHexOffset(msg.sourceOffset)} · ID: {msg.messageId.substring(0, 16)}
                          </span>

                          <div className="flex items-center gap-1.5">
                            <span title={formatUtcToLocal(msg.timestampUtc)}>
                              {msg.timestampUtc}
                            </span>
                            {isOutbound && (
                              <span title={`Status: ${msg.status}`}>
                                {msg.status === 'read' ? (
                                  <CheckCheck className="w-3.5 h-3.5 text-sky-400 inline" />
                                ) : msg.status === 'delivered' ? (
                                  <CheckCheck className="w-3.5 h-3.5 text-slate-400 inline" />
                                ) : (
                                  <Check className="w-3.5 h-3.5 text-slate-400 inline" />
                                )}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-xs text-slate-500">
            Select a conversation on the left to inspect messages.
          </div>
        )}
      </div>
    </div>
  );
};
