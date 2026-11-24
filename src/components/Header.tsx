import React from 'react';
import {
  UploadCloud,
  RefreshCw,
  AlertTriangle,
  Database,
  ShieldAlert,
} from 'lucide-react';
import { TabId } from './Sidebar';

interface HeaderProps {
  currentTab: TabId;
  onOpenUpload: () => void;
  onReloadSample: () => void;
  isReloading: boolean;
  totalEvents: number;
  totalDetections: number;
  highAlertsCount: number;
}

const TAB_TITLES: Record<TabId, { title: string; subtitle: string }> = {
  overview: {
    title: 'Security Operations Overview',
    subtitle: 'Real-time telemetry, threat severity distribution, and correlation metrics',
  },
  events: {
    title: 'Security Event Ingestion & Log Explorer',
    subtitle: 'Inspect raw security events, validate telemetry schemas, and import forensic logs',
  },
  detections: {
    title: 'Rule-Based Threat Detection & Risk Scoring',
    subtitle: 'Deterministic detection logic, transparent risk formulas, and evidence correlation',
  },
  assistant: {
    title: 'AI Security Assistant (Gemini 3.8)',
    subtitle: 'Defensive threat intelligence, incident explanation, and human-in-the-loop triage',
  },
  incidents: {
    title: 'Incident Docket & Case Management',
    subtitle: 'Track digital forensics workflows, analyst notes, and status lifecycles',
  },
  reports: {
    title: 'Executive Security & Forensics Reports',
    subtitle: 'Exportable JSON, CSV, and compliance audit summaries with model metrics',
  },
  settings: {
    title: 'System Settings & Rule Configuration',
    subtitle: 'Tune detection thresholds, time windows, and verify automated test suites',
  },
};

export const Header: React.FC<HeaderProps> = ({
  currentTab,
  onOpenUpload,
  onReloadSample,
  isReloading,
  totalEvents,
  totalDetections,
  highAlertsCount,
}) => {
  const info = TAB_TITLES[currentTab] || {
    title: 'AI Security Platform',
    subtitle: 'Cyber threat detection and incident analysis system',
  };

  return (
    <header className="bg-[#0b1326] border-b border-slate-800/80 px-6 py-3.5 flex flex-col md:flex-row md:items-center md:justify-between gap-4 sticky top-0 z-20">
      <div>
        <div className="flex items-center space-x-3">
          <h1 className="text-lg font-bold text-slate-100 tracking-tight">{info.title}</h1>
          <div className="hidden lg:flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[11px] font-medium">
            <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
            <span>PROTOTYPE • ANALYZING UPLOADED &amp; DEMO DATA</span>
          </div>
        </div>
        <p className="text-xs text-slate-400 mt-0.5">{info.subtitle}</p>
      </div>

      <div className="flex items-center flex-wrap gap-2.5">
        {/* Metric pills */}
        <div className="hidden sm:flex items-center space-x-2 text-xs">
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-slate-800/80 border border-slate-700/60 text-slate-300">
            <Database className="w-3.5 h-3.5 text-cyan-400" />
            <span className="font-semibold text-slate-100 font-mono">{totalEvents}</span>
            <span className="text-slate-400">Events</span>
          </div>

          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-slate-800/80 border border-slate-700/60 text-slate-300">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            <span className="font-semibold text-slate-100 font-mono">{totalDetections}</span>
            <span className="text-slate-400">Detections</span>
          </div>

          {highAlertsCount > 0 && (
            <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-rose-950/60 border border-rose-800/50 text-rose-300">
              <span className="font-semibold font-mono">{highAlertsCount}</span>
              <span>High/Crit</span>
            </div>
          )}
        </div>

        {/* Action buttons */}
        <div className="flex items-center space-x-2">
          <button
            onClick={onReloadSample}
            disabled={isReloading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 text-xs font-medium transition disabled:opacity-50"
            title="Reload standard synthetic demonstration dataset"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isReloading ? 'animate-spin' : ''}`} />
            <span className="hidden sm:inline">Reset Demo Data</span>
          </button>

          <button
            onClick={onOpenUpload}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-medium text-xs shadow-md shadow-blue-900/30 border border-cyan-500/30 transition"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>Upload Events</span>
          </button>
        </div>
      </div>
    </header>
  );
};
