import React, { useState } from 'react';
import {
  PhoneCall,
  PhoneForwarded,
  ShieldAlert,
  AlertTriangle,
  Info,
  Clock,
  ArrowRight,
  Server,
  Activity,
  UserCheck
} from 'lucide-react';
import { CallNetworkCorrelation, CallCorrelationClass } from '../types/forensics';
import { formatBytes } from '../utils/crypto';

interface CallCorrelationProps {
  callCorrelations: CallNetworkCorrelation[];
}

export const CallNetworkCorrelationWorkspace: React.FC<CallCorrelationProps> = ({ callCorrelations }) => {
  const [selectedCall, setSelectedCall] = useState<CallNetworkCorrelation | null>(
    callCorrelations.length > 0 ? callCorrelations[0] : null
  );

  const getClassBadge = (cls: CallCorrelationClass) => {
    switch (cls) {
      case 'IDENTIFIED_SERVICE_INFRASTRUCTURE':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
            IDENTIFIED SERVICE INFRASTRUCTURE
          </span>
        );
      case 'REMOTE_PARTICIPANT_IP_UNCONFIRMED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">
            REMOTE PARTICIPANT IP UNCONFIRMED
          </span>
        );
      case 'POSSIBLE_CALL_ASSOCIATION':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">
            POSSIBLE CALL ASSOCIATION
          </span>
        );
      case 'INSUFFICIENT_EVIDENCE':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
            INSUFFICIENT EVIDENCE
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-400">
            {cls}
          </span>
        );
    }
  };

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Left / Center List */}
      <div className="flex-1 flex flex-col bg-[#0b0f15] border-r border-[#1e293b] overflow-hidden">
        {/* Top Header */}
        <div className="p-4 bg-[#0e141d] border-b border-[#1e293b] space-y-2">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 uppercase tracking-wide">
              <PhoneCall className="w-4 h-4 text-emerald-400" /> WhatsApp Call Network Correlation Subsystem
            </h2>
          </div>
          <p className="text-[11px] text-slate-400">
            Correlates documented voice/video call session windows with observed STUN/TURN relays and real-time media flows.
          </p>
        </div>

        {/* Warning Banner */}
        <div className="p-3 bg-amber-950/20 border-b border-amber-900/60 flex items-start gap-2.5 text-xs text-amber-200">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="leading-relaxed text-[11px]">
            <strong>CRITICAL FORENSIC LIMITATION:</strong> WhatsApp calls utilize intermediary infrastructure (STUN/TURN relays) and carrier-grade NAT. Encrypted UDP flows observed during a call do <strong>not</strong> prove that an observed IP belongs directly to the remote participant.
          </div>
        </div>

        {/* Correlation Records Table */}
        <div className="flex-1 overflow-auto p-4 space-y-4">
          {callCorrelations.map(c => {
            const isSelected = selectedCall?.callId === c.callId;
            return (
              <div
                key={c.callId}
                onClick={() => setSelectedCall(c)}
                className={`p-5 rounded-lg border cursor-pointer transition-colors space-y-3 ${
                  isSelected ? 'bg-[#152233] border-emerald-800/80' : 'bg-[#101722] border-[#1e2a3b] hover:bg-[#131d2b]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-slate-100">{c.callId}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#172435] text-slate-300 uppercase">
                      {c.callType} call
                    </span>
                  </div>
                  {getClassBadge(c.classification)}
                </div>

                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div>
                    <span className="text-slate-500 block text-[11px]">Remote Participant JID</span>
                    <span className="text-slate-200 font-mono text-[11px] font-semibold">{c.participantJid}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[11px]">Call Window (UTC)</span>
                    <span className="text-slate-300 font-mono text-[11px]">{c.callStartUtc}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[11px]">Call Duration</span>
                    <span className="text-emerald-400 font-mono text-[11px] font-bold">{c.callDurationSeconds} seconds</span>
                  </div>
                </div>

                {/* Candidate Flows Preview */}
                <div className="pt-2 border-t border-[#172230] text-[11px] flex items-center justify-between text-slate-400">
                  <span>Candidate Flows Identified: <strong className="text-slate-200">{c.candidateFlows.length}</strong></span>
                  <span className="text-emerald-400 font-mono flex items-center gap-1">
                    Inspect Rationale & Endpoints <ArrowRight className="w-3 h-3" />
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Column: Detailed Candidate Flows & Attribution Rationale */}
      <div className="w-96 bg-[#0d1219] flex flex-col shrink-0 p-5 overflow-y-auto space-y-4">
        {selectedCall ? (
          <>
            <div className="border-b border-[#1e293b] pb-3">
              <div className="text-[10px] text-slate-500 font-mono">CALL CORRELATION DOSSIER</div>
              <h3 className="text-base font-bold text-slate-100 font-mono mt-0.5">{selectedCall.callId}</h3>
              <div className="mt-2">{getClassBadge(selectedCall.classification)}</div>
            </div>

            {/* Examiner Rationale */}
            <div className="bg-[#121924] p-3.5 rounded border border-[#202d3f] space-y-1.5 text-xs">
              <div className="text-[10px] uppercase font-bold text-emerald-400 font-mono flex items-center gap-1">
                <Info className="w-3.5 h-3.5" /> Technical Analysis & Findings
              </div>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                {selectedCall.examinerRationale}
              </p>
            </div>

            {/* Candidate Network Flows */}
            <div className="space-y-2">
              <div className="text-[10px] uppercase font-semibold text-slate-400 font-mono">
                Matching Reconstructed Network Flows ({selectedCall.candidateFlows.length})
              </div>

              {selectedCall.candidateFlows.map(flow => (
                <div key={flow.flowId} className="bg-[#101722] p-3 rounded border border-[#1e2a3b] text-xs font-mono space-y-1.5">
                  <div className="flex justify-between text-slate-300">
                    <span className="font-bold text-emerald-400">{flow.flowId}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#162130] text-slate-300">{flow.protocol}</span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    {flow.srcIp}:{flow.srcPort} ↔ {flow.dstIp}:{flow.dstPort}
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-500">
                    <span>{flow.packetCount} packets ({formatBytes(flow.byteCount)})</span>
                    <span>{flow.durationSeconds.toFixed(1)}s active</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Legal Attribution Limitation */}
            <div className="bg-rose-950/20 border border-rose-900/60 p-3.5 rounded space-y-1.5 text-xs">
              <div className="text-[10px] uppercase font-bold text-rose-400 font-mono flex items-center gap-1">
                <ShieldAlert className="w-3.5 h-3.5" /> Evidentiary Boundary Warning
              </div>
              <p className="text-rose-200/90 text-[11px] leading-relaxed">
                {selectedCall.attributionDisclaimer}
              </p>
            </div>
          </>
        ) : (
          <div className="text-center py-20 text-xs text-slate-500">
            Select a call record to view candidate network flows.
          </div>
        )}
      </div>
    </div>
  );
};
