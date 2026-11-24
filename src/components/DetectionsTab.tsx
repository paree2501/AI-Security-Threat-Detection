import React, { useState } from 'react';
import {
  ShieldAlert,
  Bot,
  Briefcase,
  Play,
  CheckCircle,
  HelpCircle,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Cpu,
  Layers,
  Info,
} from 'lucide-react';
import { Detection, SeverityLevel } from '../types';

interface DetectionsTabProps {
  detections: Detection[];
  onRerunDetections: () => void;
  onSelectForAI: (detectionId: string) => void;
  onCreateIncidentFromDetection: (detection: Detection) => void;
  isRerunning: boolean;
}

const SEVERITY_THEMES: Record<
  SeverityLevel,
  { bg: string; text: string; border: string; bar: string; badge: string }
> = {
  CRITICAL: {
    bg: 'bg-rose-950/20',
    text: 'text-rose-400',
    border: 'border-rose-500/40',
    bar: 'bg-rose-500',
    badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
  },
  HIGH: {
    bg: 'bg-amber-950/20',
    text: 'text-amber-400',
    border: 'border-amber-500/40',
    bar: 'bg-amber-500',
    badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
  },
  MEDIUM: {
    bg: 'bg-yellow-950/20',
    text: 'text-yellow-400',
    border: 'border-yellow-500/40',
    bar: 'bg-yellow-500',
    badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
  },
  LOW: {
    bg: 'bg-emerald-950/20',
    text: 'text-emerald-400',
    border: 'border-emerald-500/40',
    bar: 'bg-emerald-500',
    badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
  },
};

export const DetectionsTab: React.FC<DetectionsTabProps> = ({
  detections,
  onRerunDetections,
  onSelectForAI,
  onCreateIncidentFromDetection,
  isRerunning,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [expandedFactors, setExpandedFactors] = useState<Record<string, boolean>>({});

  const toggleFactors = (id: string) => {
    setExpandedFactors(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const filteredDetections = detections.filter(d => {
    if (severityFilter !== 'ALL' && d.severity !== severityFilter) return false;
    return true;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner and Controls */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <h2 className="text-base font-bold text-slate-100">Rule-Based Threat Detection Engine</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Deterministic correlation rules and multi-factor risk scoring evaluated against ingested telemetry.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="px-3 py-2 rounded-xl bg-slate-800 border border-slate-700 text-slate-200 text-xs focus:outline-none"
          >
            <option value="ALL">All Severities ({detections.length})</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
            <option value="MEDIUM">Medium Only</option>
            <option value="LOW">Low Only</option>
          </select>

          <button
            onClick={onRerunDetections}
            disabled={isRerunning}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium shadow-md shadow-blue-900/30 transition"
          >
            <Play className={`w-3.5 h-3.5 ${isRerunning ? 'animate-spin' : ''}`} />
            <span>Re-run Engine</span>
          </button>
        </div>
      </div>

      {/* Detections List */}
      <div className="space-y-4">
        {filteredDetections.length > 0 ? (
          filteredDetections.map(det => {
            const theme = SEVERITY_THEMES[det.severity];
            const isFactorsOpen = Boolean(expandedFactors[det.detection_id]);

            return (
              <div
                key={det.detection_id}
                className={`p-5 rounded-2xl bg-slate-900/90 border ${theme.border} space-y-4 transition shadow-lg`}
              >
                {/* Header line */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                  <div className="flex items-center space-x-2.5">
                    <span className="font-mono text-xs font-semibold text-slate-400">
                      {det.detection_id}
                    </span>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${theme.badge}`}>
                      {det.severity}
                    </span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-slate-400 flex items-center space-x-1">
                      <Cpu className="w-3 h-3 text-cyan-400" />
                      <span>{det.detection_method.toUpperCase()}</span>
                    </span>
                  </div>

                  <div className="text-xs text-slate-400 font-mono">
                    Detected: {new Date(det.detection_timestamp).toLocaleString()}
                  </div>
                </div>

                {/* Main finding & score */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-start">
                  <div className="md:col-span-3 space-y-2">
                    <h3 className="text-base font-bold text-slate-100 flex items-center space-x-2">
                      <span>{det.rule_name}</span>
                    </h3>
                    <p className="text-xs text-slate-300 leading-relaxed">{det.reason}</p>

                    <div className="flex flex-wrap gap-2 text-xs text-slate-400 pt-1">
                      {det.username && (
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                          User: <strong className="text-cyan-300">{det.username}</strong>
                        </span>
                      )}
                      {det.source_ip && (
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                          Source IP: <strong className="text-cyan-300">{det.source_ip}</strong>
                        </span>
                      )}
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                        Rule: {det.rule_id}
                      </span>
                    </div>
                  </div>

                  {/* Risk Score Gauge */}
                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2 text-center">
                    <div className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider">
                      Composite Risk Score
                    </div>
                    <div className="text-3xl font-extrabold font-mono tracking-tight" style={{ color: theme.bar }}>
                      {det.risk_score}
                      <span className="text-xs text-slate-500 font-normal"> / 100</span>
                    </div>

                    {/* Progress Bar */}
                    <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${theme.bar} transition-all`}
                        style={{ width: `${det.risk_score}%` }}
                      />
                    </div>

                    <button
                      onClick={() => toggleFactors(det.detection_id)}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center justify-center space-x-1 mx-auto pt-1"
                    >
                      <span>Formula Factors</span>
                      {isFactorsOpen ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    </button>
                  </div>
                </div>

                {/* Score Factors Breakdown Accordion */}
                {isFactorsOpen && (
                  <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs">
                    <div className="flex items-center space-x-1.5 font-semibold text-slate-300">
                      <Layers className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Documented Score Calculation Formula:</span>
                    </div>
                    <div className="space-y-1.5 pt-1">
                      {det.score_factors.map((factor, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-850"
                        >
                          <div>
                            <span className="font-semibold text-slate-200">{factor.factor}: </span>
                            <span className="text-slate-400">{factor.description}</span>
                          </div>
                          <span className="font-mono font-bold text-cyan-300 ml-3">
                            +{factor.points} pts
                          </span>
                        </div>
                      ))}
                    </div>
                    <div className="text-[10px] text-slate-500 pt-1">
                      * Risk scores evaluate base severity, repetition frequency, target privilege level, and temporal factors.
                    </div>
                  </div>
                )}

                {/* Evidence & Alternative Explanations Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  {/* Evidence List */}
                  <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-850 space-y-2">
                    <div className="flex items-center space-x-1.5 font-semibold text-slate-300">
                      <CheckCircle className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Concrete Observed Evidence:</span>
                    </div>
                    <ul className="space-y-1 list-disc list-inside text-slate-300 pl-1 font-mono text-[11px]">
                      {det.evidence.map((ev, i) => (
                        <li key={i}>{ev}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Alternative Legitimate Explanations */}
                  <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-850 space-y-2">
                    <div className="flex items-center space-x-1.5 font-semibold text-slate-300">
                      <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
                      <span>Alternative Legitimate Explanations:</span>
                    </div>
                    <ul className="space-y-1 list-disc list-inside text-slate-400 pl-1">
                      {det.alternative_explanations.map((alt, i) => (
                        <li key={i}>{alt}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Recommended Defensive Action */}
                <div className="p-3 rounded-xl bg-blue-950/30 border border-blue-800/40 text-xs flex items-start space-x-2.5">
                  <AlertTriangle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-cyan-300">Recommended Defensive Action: </span>
                    <span className="text-slate-300">{det.recommended_action}</span>
                  </div>
                </div>

                {/* Action buttons */}
                <div className="flex flex-wrap items-center justify-end gap-3 pt-2 border-t border-slate-800/60">
                  <button
                    onClick={() => onSelectForAI(det.detection_id)}
                    className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-xs shadow-md shadow-cyan-900/30 transition"
                  >
                    <Bot className="w-3.5 h-3.5" />
                    <span>Deep-Dive with AI Assistant</span>
                  </button>

                  <button
                    onClick={() => onCreateIncidentFromDetection(det)}
                    className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-xs transition"
                  >
                    <Briefcase className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Open Incident Docket</span>
                  </button>
                </div>
              </div>
            );
          })
        ) : (
          <div className="p-8 text-center bg-slate-900/40 rounded-2xl border border-slate-800 text-slate-400 text-xs">
            No threat detections matching the active criteria.
          </div>
        )}
      </div>

      {/* Defensive Ethics Disclaimer */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start space-x-3 text-xs text-slate-400">
        <Info className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="font-semibold text-slate-300">Defense Operations Note:</strong> In modern Security
          Operations Centers (SOCs), rule firings indicate suspicious deviations from baseline activity rather than
          irrefutable breaches. Analysts corroborate detections against host memory artifacts, proxy logs, and
          endpoint telemetry before executing active containment measures.
        </div>
      </div>
    </div>
  );
};
