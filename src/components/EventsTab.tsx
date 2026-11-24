import React, { useState, useMemo } from 'react';
import {
  Search,
  UploadCloud,
  Download,
  Trash2,
  RefreshCw,
  Database,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  Info,
} from 'lucide-react';
import { SecurityEvent } from '../types';

interface EventsTabProps {
  events: SecurityEvent[];
  onOpenUpload: () => void;
  onReloadSample: () => void;
  onClearEvents: () => void;
  isReloading: boolean;
}

export const EventsTab: React.FC<EventsTabProps> = ({
  events,
  onOpenUpload,
  onReloadSample,
  onClearEvents,
  isReloading,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [suspiciousFilter, setSuspiciousFilter] = useState('ALL');
  const [page, setPage] = useState(1);
  const pageSize = 20;

  // Filter events
  const filteredEvents = useMemo(() => {
    return events.filter(e => {
      if (searchTerm) {
        const s = searchTerm.toLowerCase();
        const matches =
          e.event_id.toLowerCase().includes(s) ||
          (e.username && e.username.toLowerCase().includes(s)) ||
          (e.source_ip && e.source_ip.toLowerCase().includes(s)) ||
          (e.message && e.message.toLowerCase().includes(s)) ||
          e.action.toLowerCase().includes(s);
        if (!matches) return false;
      }

      if (typeFilter !== 'ALL' && e.event_type !== typeFilter) return false;
      if (statusFilter !== 'ALL' && e.status !== statusFilter) return false;

      if (suspiciousFilter === 'SUSPICIOUS' && e.is_suspicious !== 1 && e.status !== 'FAILURE') return false;
      if (suspiciousFilter === 'BENIGN' && (e.is_suspicious === 1 || e.status === 'FAILURE')) return false;

      return true;
    });
  }, [events, searchTerm, typeFilter, statusFilter, suspiciousFilter]);

  // Pagination slice
  const totalPages = Math.ceil(filteredEvents.length / pageSize) || 1;
  const paginatedEvents = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredEvents.slice(start, start + pageSize);
  }, [filteredEvents, page, pageSize]);

  const uniqueTypes = useMemo(() => {
    return Array.from(new Set(events.map(e => e.event_type)));
  }, [events]);

  const [showClearConfirm, setShowClearConfirm] = useState(false);

  const handleDownloadSample = () => {
    const sample = `event_id,timestamp,source_ip,username,event_type,action,status,destination_ip,destination_port,failed_attempt_count,bytes_transferred,message,is_suspicious,attack_type
EVT-1001,2026-10-22T06:00:15Z,192.168.1.45,alice,AUTH_LOGIN,user_login,SUCCESS,10.0.0.5,443,0,1240,Standard morning login to workstation,0,BENIGN
EVT-1002,2026-10-22T06:10:02Z,198.51.100.42,root,AUTH_LOGIN,user_login,FAILURE,10.0.0.10,22,1,0,SSH authentication failure: invalid password,1,BRUTE_FORCE
EVT-1003,2026-10-22T06:10:24Z,198.51.100.42,root,AUTH_LOGIN,user_login,FAILURE,10.0.0.10,22,2,0,SSH authentication failure: invalid password,1,BRUTE_FORCE
EVT-1004,2026-10-22T06:10:48Z,198.51.100.42,root,AUTH_LOGIN,user_login,FAILURE,10.0.0.10,22,3,0,SSH authentication failure: invalid password,1,BRUTE_FORCE
EVT-1005,2026-10-22T06:35:50Z,10.0.0.15,db_admin,NETWORK_CONN,data_transfer,SUCCESS,198.51.100.88,443,0,145890000,Outbound TLS transmission of 145.89 MB,1,UNUSUAL_NETWORK_ACTIVITY`;

    const blob = new Blob([sample], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sample_security_events.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const formatBytes = (bytes?: number) => {
    if (!bytes || bytes === 0) return '0 B';
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner and Quick Ingestion Actions */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Database className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-slate-100">Security Telemetry Ingestion Hub</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Ingest structured RFC-compliant security logs or synthetic benchmark events for forensic inspection.
          </p>
        </div>

        <div className="flex items-center flex-wrap gap-2.5">
          <button
            onClick={onOpenUpload}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-medium text-xs shadow-md shadow-blue-900/30 border border-cyan-500/30 transition"
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload CSV / JSON</span>
          </button>

          <button
            onClick={onReloadSample}
            disabled={isReloading}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition disabled:opacity-50"
            title="Reload baseline synthetic dataset"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isReloading ? 'animate-spin' : ''}`} />
            <span>Reload Demo Data</span>
          </button>

          <button
            onClick={handleDownloadSample}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
            title="Download CSV format template"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Sample CSV</span>
          </button>

          {showClearConfirm ? (
            <div className="flex items-center space-x-1.5 p-1 rounded-xl bg-rose-950/80 border border-rose-700">
              <span className="text-[11px] text-rose-300 px-1.5 font-medium">Clear all?</span>
              <button
                onClick={() => {
                  onClearEvents();
                  setShowClearConfirm(false);
                }}
                className="px-2 py-1 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-[10px] font-bold"
              >
                Yes
              </button>
              <button
                onClick={() => setShowClearConfirm(false)}
                className="px-2 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px]"
              >
                No
              </button>
            </div>
          ) : (
            <button
              onClick={() => setShowClearConfirm(true)}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 text-xs font-medium border border-rose-800/40 transition"
              title="Clear all stored events"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear</span>
            </button>
          )}
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search events by User, IP, Action, or Message..."
            value={searchTerm}
            onChange={e => {
              setSearchTerm(e.target.value);
              setPage(1);
            }}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Filters */}
        <div className="flex items-center flex-wrap gap-2">
          {/* Event Type Filter */}
          <select
            value={typeFilter}
            onChange={e => {
              setTypeFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none"
          >
            <option value="ALL">All Categories</option>
            {uniqueTypes.map(t => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={e => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none"
          >
            <option value="ALL">All Statuses</option>
            <option value="SUCCESS">SUCCESS</option>
            <option value="FAILURE">FAILURE</option>
            <option value="UNKNOWN">UNKNOWN</option>
          </select>

          {/* Suspicious filter */}
          <select
            value={suspiciousFilter}
            onChange={e => {
              setSuspiciousFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none"
          >
            <option value="ALL">All Signals</option>
            <option value="SUSPICIOUS">Suspicious Only</option>
            <option value="BENIGN">Benign Only</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="border border-slate-800 rounded-2xl overflow-hidden bg-slate-950/80 shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-400 font-semibold tracking-wider font-mono text-[11px]">
                <th className="p-3">Event ID</th>
                <th className="p-3">Timestamp (UTC)</th>
                <th className="p-3">Identity (User / Source IP)</th>
                <th className="p-3">Type &amp; Action</th>
                <th className="p-3">Status</th>
                <th className="p-3">Destination</th>
                <th className="p-3">Bytes / Attempts</th>
                <th className="p-3">Log Message</th>
                <th className="p-3 text-right">Ground Truth</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 text-slate-300 font-mono text-[11px]">
              {paginatedEvents.length > 0 ? (
                paginatedEvents.map(evt => {
                  const isFail = evt.status === 'FAILURE';
                  const isSusp = evt.is_suspicious === 1;

                  return (
                    <tr
                      key={evt.event_id}
                      className={`hover:bg-slate-900/60 transition ${
                        isSusp ? 'bg-rose-950/15' : ''
                      }`}
                    >
                      {/* ID */}
                      <td className="p-3 font-semibold text-slate-200 whitespace-nowrap">
                        {evt.event_id}
                      </td>

                      {/* Timestamp */}
                      <td className="p-3 text-slate-400 whitespace-nowrap">
                        {evt.timestamp}
                      </td>

                      {/* User & Source IP */}
                      <td className="p-3 whitespace-nowrap">
                        <div className="font-semibold text-cyan-300">{evt.username || 'System'}</div>
                        <div className="text-[10px] text-slate-400">{evt.source_ip || 'Internal'}</div>
                      </td>

                      {/* Event Type & Action */}
                      <td className="p-3 whitespace-nowrap">
                        <span className="text-slate-300 font-sans font-medium">{evt.event_type}</span>
                        <div className="text-[10px] text-slate-400 font-mono">{evt.action}</div>
                      </td>

                      {/* Status */}
                      <td className="p-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase font-mono ${
                            evt.status === 'SUCCESS'
                              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                              : isFail
                              ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                              : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                          }`}
                        >
                          {evt.status}
                        </span>
                      </td>

                      {/* Destination */}
                      <td className="p-3 whitespace-nowrap text-slate-400">
                        {evt.destination_ip ? (
                          <span>
                            {evt.destination_ip}
                            {evt.destination_port ? `:${evt.destination_port}` : ''}
                          </span>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>

                      {/* Bytes / Attempts */}
                      <td className="p-3 whitespace-nowrap">
                        <div className="text-slate-300">{formatBytes(evt.bytes_transferred)}</div>
                        {evt.failed_attempt_count !== undefined && evt.failed_attempt_count > 0 && (
                          <div className="text-[10px] text-rose-400 font-semibold">
                            Failures: {evt.failed_attempt_count}
                          </div>
                        )}
                      </td>

                      {/* Message */}
                      <td className="p-3 font-sans text-slate-300 max-w-xs truncate" title={evt.message}>
                        {evt.message || '-'}
                      </td>

                      {/* Ground truth */}
                      <td className="p-3 text-right whitespace-nowrap">
                        {evt.is_suspicious !== undefined ? (
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                              isSusp
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {isSusp ? 'SUSPICIOUS' : 'BENIGN'}
                          </span>
                        ) : (
                          <span className="text-slate-600 text-[10px]">Unlabeled</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={9} className="p-8 text-center text-slate-500">
                    No security events matched the active filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="px-4 py-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 bg-slate-900/60">
          <div>
            Showing{' '}
            <span className="font-semibold text-slate-200">
              {filteredEvents.length > 0 ? (page - 1) * pageSize + 1 : 0}
            </span>{' '}
            to{' '}
            <span className="font-semibold text-slate-200">
              {Math.min(page * pageSize, filteredEvents.length)}
            </span>{' '}
            of <span className="font-semibold text-slate-200">{filteredEvents.length}</span> events
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setPage(p => Math.max(p - 1, 1))}
              disabled={page === 1}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 transition"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="font-mono text-xs text-slate-300">
              Page {page} / {totalPages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(p + 1, totalPages))}
              disabled={page >= totalPages}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 transition"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Educational Note */}
      <div className="p-4 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-start space-x-3 text-xs text-cyan-200">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="font-semibold text-cyan-300">Forensics Guidance:</strong> In real digital forensics
          investigations, timestamp synchronization (NTP) and integrity verification (SHA-256 log hashes) are
          paramount. The detection engine correlates events based on ISO-8601 UTC timestamps, user identity, and network
          sockets to trace malicious kill chains.
        </div>
      </div>
    </div>
  );
};
