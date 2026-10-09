import React from 'react';
import {
  FolderKanban,
  FileDown,
  ShieldCheck,
  MessageSquare,
  Database,
  SearchCode,
  Image as ImageIcon,
  Clock,
  Network,
  ScrollText,
  FileText,
  Cpu,
  Bot,
  Globe,
  Activity,
  PhoneCall
} from 'lucide-react';

export type WorkspaceTab =
  | 'case-manager'
  | 'evidence-import'
  | 'evidence-inventory'
  | 'whatsapp-analyzer'
  | 'database-explorer'
  | 'deleted-investigation'
  | 'public-ip-analyzer'
  | 'network-capture'
  | 'call-network-correlation'
  | 'media-explorer'
  | 'timeline'
  | 'relationship-graph'
  | 'audit-log'
  | 'forensic-reports'
  | 'benchmark-suite'
  | 'ai-assistant';

interface NavigationProps {
  activeTab: WorkspaceTab;
  onTabChange: (tab: WorkspaceTab) => void;
  caseId: string;
  totalMessagesCount: number;
  deletedRecoveredCount: number;
  anomaliesCount: number;
}

export const Navigation: React.FC<NavigationProps> = ({
  activeTab,
  onTabChange,
  caseId,
  totalMessagesCount,
  deletedRecoveredCount,
  anomaliesCount,
}) => {
  const navItems: { id: WorkspaceTab; label: string; icon: React.ReactNode; badge?: string | number; badgeColor?: string }[] = [
    { id: 'case-manager', label: 'Case Manager', icon: <FolderKanban className="w-4 h-4" /> },
    { id: 'evidence-import', label: 'Evidence Acquisition', icon: <FileDown className="w-4 h-4" /> },
    { id: 'evidence-inventory', label: 'Evidence Inventory', icon: <ShieldCheck className="w-4 h-4" /> },
    { id: 'whatsapp-analyzer', label: 'WhatsApp Analyzer', icon: <MessageSquare className="w-4 h-4" />, badge: totalMessagesCount },
    { id: 'database-explorer', label: 'Database Explorer', icon: <Database className="w-4 h-4" /> },
    { 
      id: 'deleted-investigation', 
      label: 'Deleted Artifacts', 
      icon: <SearchCode className="w-4 h-4" />, 
      badge: deletedRecoveredCount > 0 ? `${deletedRecoveredCount} Carved` : undefined,
      badgeColor: 'text-amber-400 bg-amber-950/60 border border-amber-800/60'
    },
    { id: 'public-ip-analyzer', label: 'Public IP Analyzer', icon: <Globe className="w-4 h-4 text-emerald-400" /> },
    { id: 'network-capture', label: 'PCAP Traffic Analyzer', icon: <Activity className="w-4 h-4 text-cyan-400" /> },
    { id: 'call-network-correlation', label: 'Call Correlation', icon: <PhoneCall className="w-4 h-4 text-emerald-400" /> },
    { id: 'media-explorer', label: 'Media Forensics', icon: <ImageIcon className="w-4 h-4" /> },
    { 
      id: 'timeline', 
      label: 'Forensic Timeline', 
      icon: <Clock className="w-4 h-4" />,
      badge: anomaliesCount > 0 ? `${anomaliesCount} Anomaly` : undefined,
      badgeColor: 'text-rose-400 bg-rose-950/60 border border-rose-800/60'
    },
    { id: 'relationship-graph', label: 'Network Matrix', icon: <Network className="w-4 h-4" /> },
    { id: 'audit-log', label: 'Chain of Custody', icon: <ScrollText className="w-4 h-4" /> },
    { id: 'forensic-reports', label: 'Forensic Reports', icon: <FileText className="w-4 h-4" /> },
    { id: 'benchmark-suite', label: 'Benchmark & Testing', icon: <Cpu className="w-4 h-4" /> },
    { id: 'ai-assistant', label: 'Forensic AI Assistant', icon: <Bot className="w-4 h-4" /> },
  ];

  return (
    <aside className="w-64 bg-[#0d1219] border-r border-[#1e293b] flex flex-col h-screen shrink-0 select-none">
      {/* Brand Header */}
      <div className="p-4 border-b border-[#1e293b] flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded bg-emerald-950/80 border border-emerald-600/40 flex items-center justify-center text-emerald-400 font-mono font-bold text-sm shadow-sm shadow-emerald-950">
            RB
          </div>
          <div>
            <div className="text-xs font-bold tracking-wider uppercase text-emerald-400 flex items-center gap-1.5">
              <span>RogueByte</span>
              <span className="text-[10px] text-slate-500 font-normal">v2.5</span>
            </div>
            <div className="text-[11px] text-slate-400 font-medium truncate max-w-[140px]">
              WA Forensics Ultimate
            </div>
          </div>
        </div>
      </div>

      {/* Case Context Indicator */}
      <div className="px-4 py-2.5 bg-[#090d13] border-b border-[#1e293b]/70 flex items-center justify-between text-xs">
        <div className="flex items-center gap-1.5 text-slate-400 truncate">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
          <span className="font-mono text-slate-300 font-semibold truncate">{caseId}</span>
        </div>
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-mono">ENFORCE RO</span>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-1">
        <div className="px-2 pb-1 text-[10px] font-semibold tracking-wider text-slate-500 uppercase">
          Investigation Modules
        </div>
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`w-full flex items-center justify-between px-2.5 py-2 text-xs rounded transition-colors group text-left ${
                isActive
                  ? 'bg-emerald-950/50 text-emerald-300 font-medium border border-emerald-800/50 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-[#141d29]'
              }`}
            >
              <div className="flex items-center gap-2.5 truncate">
                <span className={isActive ? 'text-emerald-400' : 'text-slate-400 group-hover:text-slate-200'}>
                  {item.icon}
                </span>
                <span className="truncate">{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                    item.badgeColor || (isActive ? 'text-emerald-300 bg-emerald-900/60' : 'text-slate-400 bg-slate-800/80')
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer Security / Standards Banner */}
      <div className="p-3 bg-[#090d13] border-t border-[#1e293b] text-[11px] text-slate-500">
        <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
          <span>Standard: NIST SP 800-86</span>
          <span className="text-emerald-400 font-mono">SHA-256</span>
        </div>
        <div className="text-[10px] text-slate-500 truncate">
          RogueByte Official Lab Environment
        </div>
      </div>
    </aside>
  );
};
