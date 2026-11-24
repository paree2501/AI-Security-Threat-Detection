import React, { useState } from 'react';
import {
  X,
  Briefcase,
  Clock,
  ShieldAlert,
  Send,
  User,
  CheckCircle,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';
import { Incident, IncidentStatus, SeverityLevel } from '../types';

interface IncidentDetailModalProps {
  incident: Incident | null;
  isOpen: boolean;
  onClose: () => void;
  onUpdate: (
    id: string,
    updates: { status?: IncidentStatus; severity?: SeverityLevel; newNote?: string; analyst?: string }
  ) => Promise<void>;
}

const SEVERITY_BADGES: Record<SeverityLevel, { bg: string; text: string; border: string }> = {
  LOW: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' },
  MEDIUM: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  HIGH: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
  CRITICAL: { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/30' },
};

const STATUS_BADGES: Record<IncidentStatus, { bg: string; text: string; border: string }> = {
  OPEN: { bg: 'bg-rose-500/15', text: 'text-rose-300', border: 'border-rose-500/30' },
  INVESTIGATING: { bg: 'bg-blue-500/15', text: 'text-cyan-300', border: 'border-cyan-500/30' },
  RESOLVED: { bg: 'bg-emerald-500/15', text: 'text-emerald-300', border: 'border-emerald-500/30' },
  FALSE_POSITIVE: { bg: 'bg-slate-500/15', text: 'text-slate-400', border: 'border-slate-500/30' },
};

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  isOpen,
  onClose,
  onUpdate,
}) => {
  const [newNote, setNewNote] = useState('');
  const [analystName, setAnalystName] = useState('Senior SOC Analyst');
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen || !incident) return null;

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    setIsSubmitting(true);
    try {
      await onUpdate(incident.incident_id, {
        status: newStatus,
        newNote: `Status changed to ${newStatus}`,
        analyst: analystName,
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    setIsSubmitting(true);
    try {
      await onUpdate(incident.incident_id, {
        newNote: newNote.trim(),
        analyst: analystName,
      });
      setNewNote('');
    } finally {
      setIsSubmitting(false);
    }
  };

  const sev = SEVERITY_BADGES[incident.severity];
  const stat = STATUS_BADGES[incident.status];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-[#0f172a] border border-slate-700/80 rounded-2xl w-full max-w-3xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60 shrink-0">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-cyan-400">
              <Briefcase className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono text-xs text-slate-400">{incident.incident_id}</span>
                <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${sev.bg} ${sev.text} ${sev.border}`}>
                  {incident.severity}
                </span>
                <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${stat.bg} ${stat.text} ${stat.border}`}>
                  {incident.status}
                </span>
              </div>
              <h2 className="text-base font-bold text-slate-100 mt-0.5 truncate max-w-xl">
                {incident.title}
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content body */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1">
          {/* Summary */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Incident Overview
            </span>
            <p className="text-sm text-slate-200 leading-relaxed">{incident.summary}</p>
            <div className="flex flex-wrap gap-4 text-xs text-slate-400 pt-2 border-t border-slate-800/80">
              <span className="flex items-center space-x-1">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                <span>Opened: {new Date(incident.created_at).toLocaleString()}</span>
              </span>
              <span className="flex items-center space-x-1">
                <User className="w-3.5 h-3.5 text-slate-500" />
                <span>Assigned: {incident.assigned_analyst || 'Unassigned'}</span>
              </span>
              <span className="flex items-center space-x-1">
                <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
                <span>Linked Events: {incident.related_event_ids.length}</span>
              </span>
            </div>
          </div>

          {/* Workflow Status Controls */}
          <div className="space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Case Workflow State
            </span>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => handleStatusChange('OPEN')}
                disabled={isSubmitting || incident.status === 'OPEN'}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
                  incident.status === 'OPEN'
                    ? 'bg-rose-950/80 border-rose-500 text-rose-300'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Open (New)</span>
              </button>

              <button
                type="button"
                onClick={() => handleStatusChange('INVESTIGATING')}
                disabled={isSubmitting || incident.status === 'INVESTIGATING'}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
                  incident.status === 'INVESTIGATING'
                    ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <Clock className="w-3.5 h-3.5" />
                <span>Under Investigation</span>
              </button>

              <button
                type="button"
                onClick={() => handleStatusChange('RESOLVED')}
                disabled={isSubmitting || incident.status === 'RESOLVED'}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
                  incident.status === 'RESOLVED'
                    ? 'bg-emerald-950/80 border-emerald-500 text-emerald-300'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <CheckCircle className="w-3.5 h-3.5" />
                <span>Resolved &amp; Mitigated</span>
              </button>

              <button
                type="button"
                onClick={() => handleStatusChange('FALSE_POSITIVE')}
                disabled={isSubmitting || incident.status === 'FALSE_POSITIVE'}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
                  incident.status === 'FALSE_POSITIVE'
                    ? 'bg-slate-800 border-slate-600 text-slate-300'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Mark False Positive</span>
              </button>
            </div>
          </div>

          {/* Recommended Next Steps */}
          {incident.recommended_next_steps.length > 0 && (
            <div className="space-y-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Recommended Investigative Actions
              </span>
              <ul className="space-y-1.5">
                {incident.recommended_next_steps.map((step, idx) => (
                  <li
                    key={idx}
                    className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs text-slate-300 flex items-start space-x-2"
                  >
                    <span className="w-4 h-4 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">
                      {idx + 1}
                    </span>
                    <span>{step}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Analyst Notes Log */}
          <div className="space-y-3">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Analyst Investigation Docket &amp; Notes
            </span>

            <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
              {incident.notes.map(note => (
                <div
                  key={note.note_id}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-850 space-y-1 text-xs"
                >
                  <div className="flex items-center justify-between text-slate-400 text-[11px]">
                    <span className="font-semibold text-cyan-400">{note.author}</span>
                    <span className="font-mono">{new Date(note.timestamp).toLocaleString()}</span>
                  </div>
                  <p className="text-slate-200 whitespace-pre-wrap">{note.content}</p>
                </div>
              ))}
            </div>

            {/* Add note input */}
            <form onSubmit={handleAddNote} className="space-y-2 pt-2">
              <div className="flex items-center space-x-2">
                <input
                  type="text"
                  placeholder="Analyst Name / Callout"
                  value={analystName}
                  onChange={e => setAnalystName(e.target.value)}
                  className="w-1/3 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div className="flex items-center space-x-2">
                <textarea
                  rows={2}
                  placeholder="Add forensic finding, packet capture correlation, or triage note..."
                  value={newNote}
                  onChange={e => setNewNote(e.target.value)}
                  className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 resize-none"
                />
                <button
                  type="submit"
                  disabled={isSubmitting || !newNote.trim()}
                  className="h-full px-4 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium flex items-center justify-center transition"
                >
                  <Send className="w-4 h-4" />
                </button>
              </div>
            </form>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 flex justify-end bg-slate-900/60 shrink-0">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
          >
            Close Docket
          </button>
        </div>
      </div>
    </div>
  );
};
