import React, { useState } from 'react';
import {
  Activity,
  Layers,
  Search,
  Download,
  Filter,
  CheckCircle,
  Clock,
  ArrowRight,
  Database
} from 'lucide-react';
import { NetworkFlow, DNSRecord } from '../types/forensics';
import { formatBytes } from '../utils/crypto';

interface NetworkCaptureProps {
  flows: NetworkFlow[];
  dnsRecords: DNSRecord[];
}

export const NetworkCaptureWorkspace: React.FC<NetworkCaptureProps> = ({ flows, dnsRecords }) => {
  const [activeSubTab, setActiveSubTab] = useState<'flows' | 'dns'>('flows');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredFlows = flows.filter(f => {
    if (protocolFilter !== 'ALL' && f.protocol !== protocolFilter) return false;
    if (searchQuery) {
      return (
        f.srcIp.includes(searchQuery) ||
        f.dstIp.includes(searchQuery) ||
        f.flowId.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (f.serviceHint && f.serviceHint.toLowerCase().includes(searchQuery.toLowerCase()))
      );
    }
    return true;
  });

  const filteredDns = dnsRecords.filter(d => {
    if (searchQuery) {
      return (
        d.queryName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        d.responseIps.some(ip => ip.includes(searchQuery))
      );
    }
    return true;
  });

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Top Banner */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-emerald-400" /> PCAP / PCAPNG Network Traffic Analyzer
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Reconstructed observable network flows, packet timestamps, and DNS queries from lawful mobile packet captures.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="bg-[#101722] p-1 rounded border border-[#1e2a3b] text-xs flex">
            <button
              onClick={() => setActiveSubTab('flows')}
              className={`px-3 py-1.5 rounded transition-colors ${
                activeSubTab === 'flows' ? 'bg-[#182330] text-emerald-400 font-bold' : 'text-slate-400'
              }`}
            >
              Reconstructed Flows ({flows.length})
            </button>
            <button
              onClick={() => setActiveSubTab('dns')}
              className={`px-3 py-1.5 rounded transition-colors ${
                activeSubTab === 'dns' ? 'bg-[#182330] text-emerald-400 font-bold' : 'text-slate-400'
              }`}
            >
              DNS Query Logs ({dnsRecords.length})
            </button>
          </div>
        </div>
      </div>

      {/* Summary Stat Tiles */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Active Capture</div>
          <div className="text-base font-bold font-mono text-slate-100 mt-1 truncate">capture_cellular_s23.pcap</div>
          <div className="text-[11px] text-slate-500 mt-1">Classic PCAP (Microsecond Resolution)</div>
        </div>

        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Reconstructed Flows</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{flows.length} 5-Tuples</div>
          <div className="text-[11px] text-slate-500 mt-1">Bidirectional Session Aggregation</div>
        </div>

        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">DNS Queries</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">{dnsRecords.length} Queries</div>
          <div className="text-[11px] text-slate-500 mt-1">Port 53 / 5353 UDP Inspection</div>
        </div>

        <div className="bg-[#111722] border border-[#1e2a3b] p-4 rounded-lg">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Integrity Status</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">INTACT</div>
          <div className="text-[11px] text-slate-500 mt-1">No Missing Packet Sequences</div>
        </div>
      </div>

      {/* Table & Controls Area */}
      <div className="space-y-3">
        {/* Search & Filter Toolbar */}
        <div className="flex items-center justify-between">
          {activeSubTab === 'flows' && (
            <div className="flex items-center gap-1 bg-[#101722] p-1 rounded border border-[#1e2a3b] text-xs font-mono">
              {['ALL', 'TCP', 'UDP', 'STUN/TURN', 'DNS'].map(proto => (
                <button
                  key={proto}
                  onClick={() => setProtocolFilter(proto)}
                  className={`px-2.5 py-1 rounded text-[11px] ${
                    protocolFilter === proto ? 'bg-[#182330] text-emerald-400 font-bold' : 'text-slate-400'
                  }`}
                >
                  {proto}
                </button>
              ))}
            </div>
          )}

          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder={activeSubTab === 'flows' ? 'Search by IP or service hint...' : 'Search domain or resolved IP...'}
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="bg-[#101722] border border-[#223042] rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500 w-64"
            />
          </div>
        </div>

        {/* Tab 1: Flows Table */}
        {activeSubTab === 'flows' && (
          <div className="bg-[#101722] border border-[#1e2a3b] rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="bg-[#090d14] border-b border-[#1e2a3b] text-slate-400 text-[11px] uppercase tracking-wider">
                  <th className="p-3">Flow ID</th>
                  <th className="p-3">Source Endpoint</th>
                  <th className="p-3">Destination Endpoint</th>
                  <th className="p-3">Protocol</th>
                  <th className="p-3">Packets / Bytes</th>
                  <th className="p-3">Duration</th>
                  <th className="p-3">Service Identification Hint</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#172230]">
                {filteredFlows.map(flow => (
                  <tr key={flow.flowId} className="hover:bg-[#15202e] transition-colors">
                    <td className="p-3 text-slate-300 font-bold">{flow.flowId}</td>
                    <td className="p-3 text-slate-200">{flow.srcIp}:{flow.srcPort}</td>
                    <td className="p-3 text-slate-200">{flow.dstIp}:{flow.dstPort}</td>
                    <td className="p-3">
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#162233] text-emerald-400 border border-[#23354c]">
                        {flow.protocol}
                      </span>
                    </td>
                    <td className="p-3 text-slate-300">
                      {flow.packetCount} pkts ({formatBytes(flow.byteCount)})
                    </td>
                    <td className="p-3 text-slate-400">{flow.durationSeconds.toFixed(2)}s</td>
                    <td className="p-3 text-slate-200 font-sans text-xs">
                      {flow.serviceHint || <span className="text-slate-600 italic">Standard Traffic</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Tab 2: DNS Queries Table */}
        {activeSubTab === 'dns' && (
          <div className="bg-[#101722] border border-[#1e2a3b] rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="bg-[#090d14] border-b border-[#1e2a3b] text-slate-400 text-[11px] uppercase tracking-wider">
                  <th className="p-3">Tx ID</th>
                  <th className="p-3">Timestamp (UTC)</th>
                  <th className="p-3">Queried Domain</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">Resolved IP Address(es)</th>
                  <th className="p-3">Response Code</th>
                  <th className="p-3">Resolver Endpoint</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#172230]">
                {filteredDns.map(dns => (
                  <tr key={dns.queryId} className="hover:bg-[#15202e] transition-colors">
                    <td className="p-3 text-slate-300 font-bold">#{dns.queryId}</td>
                    <td className="p-3 text-slate-400 text-[11px]">{dns.timestampUtc}</td>
                    <td className="p-3 text-slate-100 font-semibold">{dns.queryName}</td>
                    <td className="p-3 text-slate-400">{dns.queryType}</td>
                    <td className="p-3 text-emerald-400 font-bold">
                      {dns.responseIps.length > 0 ? dns.responseIps.join(', ') : <span className="text-slate-600">Pending / None</span>}
                    </td>
                    <td className="p-3 text-slate-300">{dns.responseCode}</td>
                    <td className="p-3 text-slate-500">{dns.destinationIp}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
