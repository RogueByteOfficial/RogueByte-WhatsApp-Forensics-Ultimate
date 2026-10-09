import React, { useState } from 'react';
import {
  Clock,
  AlertTriangle,
  Download,
  Filter,
  CheckCircle2,
  Calendar,
  Search,
  ArrowRight
} from 'lucide-react';
import { TimelineEvent } from '../types/forensics';
import { formatUtcToLocal } from '../utils/crypto';

interface TimelineProps {
  timelineEvents: TimelineEvent[];
}

export const TimelineWorkspace: React.FC<TimelineProps> = ({ timelineEvents }) => {
  const [filterAnomalyOnly, setFilterAnomalyOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(
    timelineEvents.length > 0 ? timelineEvents[0] : null
  );

  const filtered = timelineEvents.filter(e => {
    if (filterAnomalyOnly && !e.hasChronologyAnomaly) return false;
    if (searchQuery) {
      return (
        e.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
        e.primaryParticipant.toLowerCase().includes(searchQuery.toLowerCase()) ||
        e.eventId.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }
    return true;
  });

  const handleExportCsv = () => {
    const csvRows = [
      'Event ID,Timestamp UTC,Timestamp Epoch MS,Primary Participant,Summary,Record ID,Confidence,Anomaly,Anomaly Explanation',
      ...timelineEvents.map(e =>
        `"${e.eventId}","${e.timestampUtc}","${e.timestampMs}","${e.primaryParticipant}","${e.summary.replace(/"/g, '""')}","${e.associatedEvidenceId}","${e.confidence}","${e.hasChronologyAnomaly ? 'YES' : 'NO'}","${(e.anomalyExplanation || '').replace(/"/g, '""')}"`
      )
    ].join('\n');

    const blob = new Blob([csvRows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Forensic_Timeline_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Left / Center Main Timeline Stream */}
      <div className="flex-1 flex flex-col bg-[#0b0f15] border-r border-[#1e293b] overflow-hidden">
        {/* Header Bar */}
        <div className="p-4 bg-[#0e141d] border-b border-[#1e293b] flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wide flex items-center gap-2">
              <Clock className="w-4 h-4 text-emerald-400" /> Forensic Chronological Timeline
            </h2>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Correlated cross-artifact timeline with UTC normalization and clock drift anomaly detection.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search timeline..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="bg-[#121924] border border-[#202e40] rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500 w-48"
              />
            </div>

            <button
              onClick={() => setFilterAnomalyOnly(!filterAnomalyOnly)}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border transition-colors ${
                filterAnomalyOnly
                  ? 'bg-rose-950/80 text-rose-300 border-rose-800 font-bold'
                  : 'bg-[#141d2a] text-slate-400 border-[#223146] hover:text-slate-200'
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
              <span>Anomalies Only</span>
            </button>

            <button
              onClick={handleExportCsv}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#16202c] hover:bg-[#1f2c3d] text-slate-200 border border-[#253446] rounded transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* Timeline Events Scroll Area */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          <div className="relative border-l-2 border-[#1c293a] ml-4 pl-6 space-y-6">
            {filtered.map(evt => {
              const isSelected = selectedEvent?.eventId === evt.eventId;
              return (
                <div
                  key={evt.eventId}
                  onClick={() => setSelectedEvent(evt)}
                  className="relative group cursor-pointer"
                >
                  {/* Timeline dot */}
                  <div
                    className={`absolute -left-[31px] top-1.5 w-3.5 h-3.5 rounded-full border-2 transition-all ${
                      evt.hasChronologyAnomaly
                        ? 'bg-rose-500 border-rose-950 ring-4 ring-rose-950/60 animate-ping'
                        : isSelected
                        ? 'bg-emerald-400 border-emerald-950 ring-2 ring-emerald-600'
                        : 'bg-[#1e2a3b] border-[#0e141d] group-hover:bg-emerald-500'
                    }`}
                  />

                  {/* Card Content */}
                  <div
                    className={`p-4 rounded-lg border text-xs transition-colors ${
                      evt.hasChronologyAnomaly
                        ? 'bg-rose-950/20 border-rose-800/80'
                        : isSelected
                        ? 'bg-[#15202e] border-emerald-800/80 shadow-md'
                        : 'bg-[#101622] border-[#1b2535] hover:bg-[#131b28]'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
                      <span className="font-semibold text-emerald-400">{evt.timestampUtc}</span>
                      <span>Local: {formatUtcToLocal(evt.timestampUtc)}</span>
                    </div>

                    <div className="text-sm font-semibold text-slate-100 mt-1">
                      {evt.summary}
                    </div>

                    {evt.hasChronologyAnomaly && (
                      <div className="mt-2.5 p-2 bg-rose-950/60 border border-rose-800 rounded text-rose-300 text-[11px] font-sans flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                        <div>
                          <strong>CHRONOLOGY ANOMALY FLAGGED:</strong> {evt.anomalyExplanation}
                        </div>
                      </div>
                    )}

                    <div className="mt-2.5 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                      <span>{evt.provenanceDetails}</span>
                      <span className="text-slate-400">{evt.eventId}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Right Pane: Selected Event Provenance Inspector */}
      <div className="w-80 bg-[#0d1219] p-5 overflow-y-auto space-y-4 shrink-0">
        {selectedEvent ? (
          <>
            <div className="border-b border-[#1e293b] pb-3">
              <div className="text-[10px] text-slate-500 font-mono">EVENT INSPECTOR</div>
              <h3 className="text-sm font-bold text-slate-100 font-mono mt-0.5">{selectedEvent.eventId}</h3>
              <div className="mt-1 text-xs text-emerald-400 font-mono font-semibold">
                {selectedEvent.timestampUtc}
              </div>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-500 block mb-0.5">Primary Participant:</span>
                <span className="text-slate-200 font-mono break-all">{selectedEvent.primaryParticipant}</span>
              </div>

              <div>
                <span className="text-slate-500 block mb-0.5">Secondary Participant:</span>
                <span className="text-slate-200 font-mono break-all">{selectedEvent.secondaryParticipant}</span>
              </div>

              <div>
                <span className="text-slate-500 block mb-0.5">Associated Evidence ID:</span>
                <span className="text-slate-200 font-mono">{selectedEvent.associatedEvidenceId}</span>
              </div>

              <div>
                <span className="text-slate-500 block mb-0.5">Forensic Provenance:</span>
                <p className="text-slate-300 bg-[#111722] p-2.5 rounded border border-[#1e2a3b] font-mono text-[11px] leading-relaxed">
                  {selectedEvent.provenanceDetails}
                </p>
              </div>

              {selectedEvent.hasChronologyAnomaly && (
                <div className="bg-rose-950/40 border border-rose-800 p-3 rounded space-y-1">
                  <div className="text-[10px] uppercase font-bold text-rose-300 font-mono">
                    Forensic Explanation
                  </div>
                  <p className="text-[11px] text-rose-200 leading-relaxed">
                    {selectedEvent.anomalyExplanation}
                  </p>
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="text-center py-20 text-xs text-slate-500">
            Select an event from the timeline to inspect full provenance.
          </div>
        )}
      </div>
    </div>
  );
};
