import React, { useState } from 'react';
import {
  Briefcase,
  Plus,
  Clock,
  User,
  ShieldAlert,
  ChevronRight,
  Filter,
  CheckCircle,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';
import { Incident, IncidentStatus, SeverityLevel } from '../types';

interface IncidentsTabProps {
  incidents: Incident[];
  onOpenIncidentDetail: (inc: Incident) => void;
  onCreateManualIncident: (title: string, summary: string, severity: SeverityLevel) => void;
}

const SEVERITY_BADGES: Record<SeverityLevel, { bg: string; text: string; border: string }> = {
  LOW: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' },
  MEDIUM: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  HIGH: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
  CRITICAL: { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/30' },
};

const STATUS_ICONS: Record<IncidentStatus, React.ReactNode> = {
  OPEN: <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />,
  INVESTIGATING: <Clock className="w-3.5 h-3.5 text-cyan-400" />,
  RESOLVED: <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />,
  FALSE_POSITIVE: <RotateCcw className="w-3.5 h-3.5 text-slate-400" />,
};

export const IncidentsTab: React.FC<IncidentsTabProps> = ({
  incidents,
  onOpenIncidentDetail,
  onCreateManualIncident,
}) => {
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [isCreating, setIsCreating] = useState<boolean>(false);
  const [title, setTitle] = useState('');
  const [summary, setSummary] = useState('');
  const [severity, setSeverity] = useState<SeverityLevel>('MEDIUM');

  const filtered = incidents.filter(i => {
    if (statusFilter !== 'ALL' && i.status !== statusFilter) return false;
    if (severityFilter !== 'ALL' && i.severity !== severityFilter) return false;
    return true;
  });

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    onCreateManualIncident(title.trim(), summary.trim() || 'Manual incident docket.', severity);
    setTitle('');
    setSummary('');
    setIsCreating(false);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner and Quick Actions */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Briefcase className="w-5 h-5 text-indigo-400" />
            <h2 className="text-base font-bold text-slate-100">Incident Investigation &amp; Case Management</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Track forensic investigations, record timestamped analyst observations, and advance containment statuses.
          </p>
        </div>

        <button
          onClick={() => setIsCreating(true)}
          className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs shadow-md shadow-blue-900/30 transition shrink-0"
        >
          <Plus className="w-4 h-4" />
          <span>Open New Incident</span>
        </button>
      </div>

      {/* Manual Incident Creator Form */}
      {isCreating && (
        <form
          onSubmit={handleCreateSubmit}
          className="p-5 rounded-2xl bg-slate-900 border border-slate-700 space-y-4 shadow-xl"
        >
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <h3 className="text-sm font-bold text-slate-100">Open Manual Incident Case</h3>
            <button
              type="button"
              onClick={() => setIsCreating(false)}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2 space-y-1">
              <label className="text-xs font-semibold text-slate-300">Incident Title</label>
              <input
                type="text"
                placeholder="e.g. Investigation: Abnormal Data Exfiltration from DB Server"
                value={title}
                onChange={e => setTitle(e.target.value)}
                required
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-300">Severity</label>
              <select
                value={severity}
                onChange={e => setSeverity(e.target.value as SeverityLevel)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-xs font-semibold text-slate-300">Incident Summary / Scope</label>
            <textarea
              rows={2}
              placeholder="Describe initial indicators of compromise, affected hostnames, and triage hypotheses..."
              value={summary}
              onChange={e => setSummary(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 resize-none"
            />
          </div>

          <div className="flex justify-end space-x-2 pt-2">
            <button
              type="button"
              onClick={() => setIsCreating(false)}
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium"
            >
              Save Incident
            </button>
          </div>
        </form>
      )}

      {/* Filter Bar */}
      <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center space-x-2 text-slate-400">
          <Filter className="w-3.5 h-3.5 text-indigo-400" />
          <span className="font-semibold text-slate-300">Case Filters:</span>
        </div>

        <div className="flex items-center space-x-3">
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none"
          >
            <option value="ALL">All Statuses ({incidents.length})</option>
            <option value="OPEN">Open Only</option>
            <option value="INVESTIGATING">Under Investigation</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>

          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Incidents List */}
      <div className="space-y-3">
        {filtered.length > 0 ? (
          filtered.map(inc => {
            const sev = SEVERITY_BADGES[inc.severity];
            const icon = STATUS_ICONS[inc.status];

            return (
              <div
                key={inc.incident_id}
                onClick={() => onOpenIncidentDetail(inc)}
                className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 hover:border-indigo-500/50 cursor-pointer transition flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-lg group"
              >
                <div className="space-y-2 min-w-0 flex-1">
                  <div className="flex items-center flex-wrap gap-2">
                    <span className="font-mono text-xs font-semibold text-slate-400">
                      {inc.incident_id}
                    </span>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${sev.bg} ${sev.text} ${sev.border}`}>
                      {inc.severity}
                    </span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-medium uppercase bg-slate-800 border border-slate-700 text-slate-300 flex items-center space-x-1">
                      {icon}
                      <span className="ml-1">{inc.status}</span>
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-slate-100 group-hover:text-cyan-300 transition">
                    {inc.title}
                  </h3>
                  <p className="text-xs text-slate-400 line-clamp-1">{inc.summary}</p>

                  <div className="flex flex-wrap gap-4 text-[11px] text-slate-500 pt-1">
                    <span className="flex items-center space-x-1">
                      <User className="w-3.5 h-3.5 text-slate-500" />
                      <span>{inc.assigned_analyst || 'Unassigned'}</span>
                    </span>
                    <span className="flex items-center space-x-1">
                      <ShieldAlert className="w-3.5 h-3.5 text-slate-500" />
                      <span>{inc.related_event_ids.length} linked events</span>
                    </span>
                    <span className="flex items-center space-x-1">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      <span>Updated: {new Date(inc.updated_at).toLocaleTimeString()}</span>
                    </span>
                    <span>Notes: {inc.notes.length}</span>
                  </div>
                </div>

                <div className="flex items-center space-x-3 shrink-0">
                  <button className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-slate-800 group-hover:bg-indigo-600 text-slate-300 group-hover:text-white text-xs font-medium transition">
                    <span>View Docket</span>
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            );
          })
        ) : (
          <div className="p-8 text-center bg-slate-900/40 rounded-2xl border border-slate-800 text-slate-400 text-xs">
            No incidents found matching the filter.
          </div>
        )}
      </div>
    </div>
  );
};
