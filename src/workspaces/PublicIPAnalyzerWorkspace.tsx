import React, { useState } from 'react';
import {
  Globe,
  Shield,
  Search,
  Filter,
  Download,
  CheckCircle,
  AlertTriangle,
  Info,
  Server,
  Lock
} from 'lucide-react';
import { IPRecord, IPClassification } from '../types/forensics';

interface PublicIPProps {
  ipRecords: IPRecord[];
}

export const PublicIPAnalyzerWorkspace: React.FC<PublicIPProps> = ({ ipRecords }) => {
  const [filterClass, setFilterClass] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIp, setSelectedIp] = useState<IPRecord | null>(ipRecords.length > 0 ? ipRecords[0] : null);

  const filtered = ipRecords.filter(ip => {
    if (filterClass !== 'ALL' && ip.classification !== filterClass) return false;
    if (searchQuery) {
      return (
        ip.ipAddress.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (ip.asnInfo && ip.asnInfo.organization.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (ip.geolocation && ip.geolocation.country.toLowerCase().includes(searchQuery.toLowerCase()))
      );
    }
    return true;
  });

  const getBadge = (c: IPClassification) => {
    switch (c) {
      case 'PUBLIC':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">PUBLIC</span>;
      case 'PRIVATE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">PRIVATE (RFC1918)</span>;
      case 'LOOPBACK':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-950 text-blue-300 border border-blue-800">LOOPBACK</span>;
      case 'LINK_LOCAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">LINK_LOCAL</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-400">{c}</span>;
    }
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(ipRecords, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Public_IP_Analysis_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Main Table View */}
      <div className="flex-1 flex flex-col bg-[#0b0f15] border-r border-[#1e293b] overflow-hidden">
        {/* Workspace Top Header */}
        <div className="p-4 bg-[#0e141d] border-b border-[#1e293b] space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 uppercase tracking-wide">
                <Globe className="w-4 h-4 text-emerald-400" /> Public & Private IP Analysis Engine
              </h2>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Classifies observed IPv4 and IPv6 addresses, Autonomous System (ASN) ownership, and estimated geolocation.
              </p>
            </div>

            <button
              onClick={handleExportJson}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#16202c] hover:bg-[#1f2c3d] text-slate-200 border border-[#253446] rounded transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>Export IP Registry</span>
            </button>
          </div>

          {/* Filters & Search */}
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-1 bg-[#090d14] p-1 rounded border border-[#1b2533] text-xs font-mono">
              {['ALL', 'PUBLIC', 'PRIVATE', 'LOOPBACK'].map(cls => (
                <button
                  key={cls}
                  onClick={() => setFilterClass(cls)}
                  className={`px-2.5 py-1 rounded text-[11px] transition-colors ${
                    filterClass === cls
                      ? 'bg-[#182330] text-emerald-400 font-bold border border-emerald-800/60'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {cls}
                </button>
              ))}
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search by IP, ASN, or country..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="bg-[#121924] border border-[#202e40] rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500 w-64"
              />
            </div>
          </div>
        </div>

        {/* High-Density IP Table */}
        <div className="flex-1 overflow-auto p-4">
          <div className="bg-[#101722] border border-[#1e2a3b] rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="bg-[#090d14] border-b border-[#1e2a3b] text-slate-400 text-[11px] uppercase tracking-wider">
                  <th className="p-3">IP Address</th>
                  <th className="p-3">Family</th>
                  <th className="p-3">Classification</th>
                  <th className="p-3">ASN Ownership</th>
                  <th className="p-3">Estimated Location</th>
                  <th className="p-3">Protocols / Ports</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#172230]">
                {filtered.map(ip => {
                  const isSelected = selectedIp?.ipAddress === ip.ipAddress;
                  return (
                    <tr
                      key={ip.ipAddress}
                      onClick={() => setSelectedIp(ip)}
                      className={`hover:bg-[#15202e] cursor-pointer transition-colors ${
                        isSelected ? 'bg-[#152233] border-l-2 border-emerald-500' : ''
                      }`}
                    >
                      <td className="p-3 text-slate-100 font-bold font-mono">{ip.ipAddress}</td>
                      <td className="p-3 text-slate-400">{ip.addressFamily}</td>
                      <td className="p-3">{getBadge(ip.classification)}</td>
                      <td className="p-3 text-slate-300 font-sans text-xs">
                        {ip.asnInfo ? (
                          <span>
                            AS{ip.asnInfo.asn} {ip.asnInfo.organization}
                            {ip.asnInfo.isMetaInfrastructure && (
                              <span className="ml-1.5 text-[10px] text-emerald-400 font-mono font-bold">[META]</span>
                            )}
                          </span>
                        ) : (
                          <span className="text-slate-600">Non-Routable Private</span>
                        )}
                      </td>
                      <td className="p-3 text-slate-300 font-sans text-xs">
                        {ip.geolocation ? (
                          <span>{ip.geolocation.city ? `${ip.geolocation.city}, ` : ''}{ip.geolocation.country}</span>
                        ) : (
                          <span className="text-slate-600">N/A (Local Network)</span>
                        )}
                      </td>
                      <td className="p-3 text-slate-400">
                        {ip.protocols.join(', ')} {ip.ports.length > 0 ? `(${ip.ports.join(', ')})` : ''}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Right Column: IP Dossier & Evidentiary Disclaimer */}
      <div className="w-96 bg-[#0d1219] flex flex-col shrink-0 p-5 overflow-y-auto space-y-4">
        {selectedIp ? (
          <>
            <div className="border-b border-[#1e293b] pb-3">
              <div className="text-[10px] text-slate-500 font-mono">IP FORENSIC DOSSIER</div>
              <h3 className="text-base font-bold text-slate-100 font-mono mt-0.5">{selectedIp.ipAddress}</h3>
              <div className="mt-2 flex items-center justify-between">
                {getBadge(selectedIp.classification)}
                <span className="text-[11px] text-slate-400 font-mono">{selectedIp.addressFamily}</span>
              </div>
            </div>

            {/* ASN Ownership Card */}
            {selectedIp.asnInfo && (
              <div className="bg-[#101722] p-3.5 rounded border border-[#1d2737] space-y-2 text-xs">
                <div className="text-[10px] uppercase font-bold text-emerald-400 font-mono flex items-center gap-1">
                  <Server className="w-3.5 h-3.5" /> Autonomous System (BGP Routing)
                </div>
                <div className="space-y-1">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Autonomous System:</span>
                    <span className="text-slate-200 font-mono">AS{selectedIp.asnInfo.asn} ({selectedIp.asnInfo.asName})</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Registered Org:</span>
                    <span className="text-slate-200 font-medium">{selectedIp.asnInfo.organization}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">BGP CIDR Prefix:</span>
                    <span className="text-slate-400 font-mono text-[11px]">{selectedIp.asnInfo.cidrPrefix}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Geolocation Estimate Card */}
            {selectedIp.geolocation && (
              <div className="bg-[#101722] p-3.5 rounded border border-[#1d2737] space-y-2 text-xs">
                <div className="text-[10px] uppercase font-bold text-cyan-400 font-mono flex items-center gap-1">
                  <Globe className="w-3.5 h-3.5" /> Estimated Geolocation
                </div>
                <div className="space-y-1">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Country:</span>
                    <span className="text-slate-200">{selectedIp.geolocation.country}</span>
                  </div>
                  {selectedIp.geolocation.city && (
                    <div className="flex justify-between">
                      <span className="text-slate-500">City / Region:</span>
                      <span className="text-slate-200">{selectedIp.geolocation.city}, {selectedIp.geolocation.region}</span>
                    </div>
                  )}
                  {selectedIp.geolocation.latitude && (
                    <div className="flex justify-between">
                      <span className="text-slate-500">Coordinates:</span>
                      <span className="text-slate-400 font-mono text-[11px]">{selectedIp.geolocation.latitude}, {selectedIp.geolocation.longitude}</span>
                    </div>
                  )}
                </div>

                <div className="p-2 bg-[#090d14] rounded border border-[#1a2533] text-[10px] text-amber-300/80 leading-relaxed font-sans">
                  <strong>DISCLAIMER:</strong> {selectedIp.geolocation.disclaimer}
                </div>
              </div>
            )}

            {/* Mandatory Attribution Limitations Notice */}
            <div className="bg-[#131b26] p-3.5 rounded border border-amber-900/50 space-y-1.5 text-xs">
              <div className="text-[10px] uppercase font-bold text-amber-400 font-mono flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> Attribution Limitation Notice
              </div>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                {selectedIp.attributionLimitations}
              </p>
            </div>
          </>
        ) : (
          <div className="text-center py-20 text-xs text-slate-500">
            Select an IP address from the table to view the forensic dossier.
          </div>
        )}
      </div>
    </div>
  );
};
