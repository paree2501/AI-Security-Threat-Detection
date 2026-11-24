import React, { useMemo, useState } from 'react';
import {
  ShieldAlert,
  Database,
  AlertCircle,
  Briefcase,
  Bot,
  Filter,
  CheckCircle,
  Clock,
  ArrowUpRight,
  TrendingUp,
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  AreaChart,
  Area,
} from 'recharts';
import { SecurityEvent, Detection, Incident } from '../types';
import { TabId } from './Sidebar';

interface OverviewTabProps {
  events: SecurityEvent[];
  detections: Detection[];
  incidents: Incident[];
  onSelectTab: (tab: TabId) => void;
  onSelectDetectionForAI: (detectionId: string) => void;
  onOpenIncidentDetail: (incident: Incident) => void;
  onLoadSample: () => void;
}

const SEVERITY_COLORS = {
  CRITICAL: '#f43f5e',
  HIGH: '#f59e0b',
  MEDIUM: '#eab308',
  LOW: '#10b981',
};

export const OverviewTab: React.FC<OverviewTabProps> = ({
  events,
  detections,
  incidents,
  onSelectTab,
  onSelectDetectionForAI,
  onOpenIncidentDetail,
  onLoadSample,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('ALL');

  // Filtered detections
  const filteredDetections = useMemo(() => {
    return detections.filter(d => {
      if (severityFilter !== 'ALL' && d.severity !== severityFilter) return false;
      return true;
    });
  }, [detections, severityFilter]);

  // Metric aggregates
  const totalEvents = events.length;
  const suspiciousCount = events.filter(e => e.is_suspicious === 1 || e.status === 'FAILURE').length;
  const highSeverityAlerts = detections.filter(d => d.severity === 'HIGH' || d.severity === 'CRITICAL').length;
  const openIncidents = incidents.filter(i => i.status === 'OPEN' || i.status === 'INVESTIGATING').length;

  // Severity Distribution Data
  const severityData = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    detections.forEach(d => {
      if (counts[d.severity] !== undefined) {
        counts[d.severity]++;
      }
    });
    return [
      { name: 'Critical', value: counts.CRITICAL, color: SEVERITY_COLORS.CRITICAL },
      { name: 'High', value: counts.HIGH, color: SEVERITY_COLORS.HIGH },
      { name: 'Medium', value: counts.MEDIUM, color: SEVERITY_COLORS.MEDIUM },
      { name: 'Low', value: counts.LOW, color: SEVERITY_COLORS.LOW },
    ].filter(item => item.value > 0);
  }, [detections]);

  // Category Distribution Data
  const categoryData = useMemo(() => {
    const map: Record<string, number> = {};
    events.forEach(e => {
      map[e.event_type] = (map[e.event_type] || 0) + 1;
    });
    return Object.entries(map)
      .map(([name, count]) => ({ name: name.replace('_', ' '), count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [events]);

  // Events Timeline Data (hourly buckets)
  const timelineData = useMemo(() => {
    if (events.length === 0) return [];
    const buckets: Record<string, { time: string; total: number; suspicious: number }> = {};

    events.forEach(e => {
      try {
        const d = new Date(e.timestamp);
        const hourStr = `${String(d.getUTCHours()).padStart(2, '0')}:${String(Math.floor(d.getUTCMinutes() / 15) * 15).padStart(2, '0')}`;
        if (!buckets[hourStr]) {
          buckets[hourStr] = { time: hourStr, total: 0, suspicious: 0 };
        }
        buckets[hourStr].total++;
        if (e.is_suspicious === 1 || e.status === 'FAILURE') {
          buckets[hourStr].suspicious++;
        }
      } catch {
        // ignore date parsing error
      }
    });

    return Object.values(buckets).sort((a, b) => a.time.localeCompare(b.time));
  }, [events]);

  const uniqueEventTypes = useMemo(() => {
    return Array.from(new Set(events.map(e => e.event_type)));
  }, [events]);

  if (events.length === 0) {
    return (
      <div className="p-8 max-w-5xl mx-auto text-center space-y-6">
        <div className="w-16 h-16 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto text-slate-500 shadow-xl">
          <Database className="w-8 h-8" />
        </div>
        <div className="space-y-2">
          <h2 className="text-xl font-bold text-slate-100">No Security Events Ingested</h2>
          <p className="text-sm text-slate-400 max-w-md mx-auto">
            The detection engine requires security log records to identify threats, compute risk scores, and run
            investigation playbooks.
          </p>
        </div>
        <div className="flex flex-wrap justify-center gap-3 pt-2">
          <button
            onClick={onLoadSample}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-medium text-sm shadow-lg shadow-blue-900/30 transition flex items-center space-x-2"
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Load Demonstration Dataset</span>
          </button>
          <button
            onClick={() => onSelectTab('events')}
            className="px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-sm border border-slate-700 transition"
          >
            Upload Custom Log File
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* 4 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Events */}
        <div className="p-5 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Total Analyzed</span>
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-cyan-400">
              <Database className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-slate-100 font-mono">{totalEvents}</span>
            <span className="text-xs text-slate-500">events in store</span>
          </div>
          <div className="mt-2 flex items-center text-xs text-cyan-400 font-medium">
            <CheckCircle className="w-3.5 h-3.5 mr-1" />
            <span>Telemetry validated</span>
          </div>
        </div>

        {/* Suspicious Events */}
        <div className="p-5 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Suspicious Events</span>
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <AlertCircle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-amber-400 font-mono">{suspiciousCount}</span>
            <span className="text-xs text-slate-500">
              ({totalEvents > 0 ? ((suspiciousCount / totalEvents) * 100).toFixed(1) : 0}%)
            </span>
          </div>
          <div className="mt-2 flex items-center text-xs text-amber-400/90 font-medium">
            <TrendingUp className="w-3.5 h-3.5 mr-1" />
            <span>Anomalies / Failures</span>
          </div>
        </div>

        {/* High & Critical Alerts */}
        <div className="p-5 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">High / Critical Alerts</span>
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-rose-400 font-mono">{highSeverityAlerts}</span>
            <span className="text-xs text-slate-500">of {detections.length} total</span>
          </div>
          <div className="mt-2 flex items-center text-xs text-rose-400/90 font-medium">
            <ArrowUpRight className="w-3.5 h-3.5 mr-1" />
            <span>Immediate review advised</span>
          </div>
        </div>

        {/* Open Incidents */}
        <div className="p-5 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Active Incidents</span>
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
              <Briefcase className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-indigo-400 font-mono">{openIncidents}</span>
            <span className="text-xs text-slate-500">in triage docket</span>
          </div>
          <div className="mt-2 flex items-center text-xs text-indigo-400 font-medium">
            <Clock className="w-3.5 h-3.5 mr-1" />
            <span>Workflow tracked</span>
          </div>
        </div>
      </div>

      {/* Filter toolbar */}
      <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center space-x-2 text-slate-400">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span className="font-semibold text-slate-300">Dashboard Telemetry Filters:</span>
        </div>

        <div className="flex items-center flex-wrap gap-2.5">
          <div className="flex items-center space-x-1.5">
            <span className="text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="px-2.5 py-1 rounded-md bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="flex items-center space-x-1.5">
            <span className="text-slate-400">Event Type:</span>
            <select
              value={eventTypeFilter}
              onChange={e => setEventTypeFilter(e.target.value)}
              className="px-2.5 py-1 rounded-md bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none"
            >
              <option value="ALL">All Categories</option>
              {uniqueEventTypes.map(t => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Donut */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800/80 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100">Alert Severity Breakdown</h3>
              <span className="text-xs text-slate-400 font-mono">{detections.length} total</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Classification based on calculated risk score</p>
          </div>

          <div className="h-56 mt-2 relative flex items-center justify-center">
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-xs text-slate-500">No detections recorded</div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/60 text-xs">
            {severityData.map(item => (
              <div key={item.name} className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-slate-400">{item.name}:</span>
                <span className="font-semibold text-slate-200 font-mono">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Security Events Over Time */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800/80 flex flex-col justify-between lg:col-span-2">
          <div>
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100">Event Telemetry Timeline</h3>
              <span className="text-xs text-slate-400 font-mono">15-minute intervals</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Chronological frequency of all events vs. suspicious activity</p>
          </div>

          <div className="h-56 mt-2">
            {timelineData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <defs>
                    <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorSuspicious" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="total"
                    name="Total Events"
                    stroke="#3b82f6"
                    fillOpacity={1}
                    fill="url(#colorTotal)"
                  />
                  <Area
                    type="monotone"
                    dataKey="suspicious"
                    name="Suspicious Events"
                    stroke="#f43f5e"
                    fillOpacity={1}
                    fill="url(#colorSuspicious)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                Timeline requires event timestamps
              </div>
            )}
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-xs text-slate-400">
            <span className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
              <span>Total Activity</span>
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 ml-2" />
              <span>Suspicious Signals</span>
            </span>
            <span className="text-[11px] text-slate-500">UTC Timeline</span>
          </div>
        </div>
      </div>

      {/* Event Categories Bar Chart */}
      <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800/80 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100">Top Ingested Event Categories</h3>
            <p className="text-xs text-slate-400">Distribution across authentication, network, process, and files</p>
          </div>
          <button
            onClick={() => onSelectTab('events')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
          >
            View All Log Events →
          </button>
        </div>

        <div className="h-44">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={categoryData}>
              <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  borderColor: '#334155',
                  borderRadius: '8px',
                  fontSize: '12px',
                }}
              />
              <Bar dataKey="count" name="Event Count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Split view: Recent Alerts & Recent Investigation Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Alerts */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800/80 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span>Recent Threat Detections</span>
            </h3>
            <button
              onClick={() => onSelectTab('detections')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
            >
              Detection Engine →
            </button>
          </div>

          <div className="space-y-2.5">
            {filteredDetections.slice(0, 4).map(d => {
              const sevBadge = SEVERITY_COLORS[d.severity];
              return (
                <div
                  key={d.detection_id}
                  className="p-3 rounded-xl bg-slate-950 border border-slate-850 hover:border-slate-700 transition flex items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <span
                        className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase font-mono"
                        style={{
                          backgroundColor: `${sevBadge}20`,
                          color: sevBadge,
                          border: `1px solid ${sevBadge}40`,
                        }}
                      >
                        {d.severity}
                      </span>
                      <span className="font-semibold text-slate-200 truncate">{d.rule_name}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 truncate max-w-sm">{d.reason}</p>
                  </div>

                  <div className="flex items-center space-x-2 shrink-0">
                    <div className="text-right">
                      <div className="font-mono font-bold text-slate-200">{d.risk_score}/100</div>
                      <div className="text-[10px] text-slate-500">Risk Score</div>
                    </div>
                    <button
                      onClick={() => onSelectDetectionForAI(d.detection_id)}
                      className="p-1.5 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/50 text-cyan-300 transition"
                      title="Analyze with AI Assistant"
                    >
                      <Bot className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Recent Investigation Activity */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800/80 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <Briefcase className="w-4 h-4 text-indigo-400" />
              <span>Incident Case Docket</span>
            </h3>
            <button
              onClick={() => onSelectTab('incidents')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
            >
              Case Manager →
            </button>
          </div>

          <div className="space-y-2.5">
            {incidents.slice(0, 4).map(inc => (
              <div
                key={inc.incident_id}
                onClick={() => onOpenIncidentDetail(inc)}
                className="p-3 rounded-xl bg-slate-950 border border-slate-850 hover:border-indigo-500/40 cursor-pointer transition space-y-1.5 text-xs"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-[11px] text-slate-400">{inc.incident_id}</span>
                    <span className="font-semibold text-slate-200 truncate">{inc.title}</span>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-medium uppercase">
                    {inc.status}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 line-clamp-1">{inc.summary}</p>
                <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-900">
                  <span>Assigned: {inc.assigned_analyst || 'Unassigned'}</span>
                  <span>{new Date(inc.updated_at).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
