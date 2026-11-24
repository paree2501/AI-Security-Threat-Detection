import React from 'react';
import {
  LayoutDashboard,
  ScrollText,
  ShieldAlert,
  Bot,
  Briefcase,
  FileText,
  Settings2,
  ShieldCheck,
  Activity,
  Terminal,
} from 'lucide-react';
import { SystemStatus } from '../types';

export type TabId =
  | 'overview'
  | 'events'
  | 'detections'
  | 'assistant'
  | 'incidents'
  | 'reports'
  | 'settings';

interface SidebarProps {
  currentTab: TabId;
  onSelectTab: (tab: TabId) => void;
  status: SystemStatus | null;
  detectionsCount: number;
  openIncidentsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  status,
  detectionsCount,
  openIncidentsCount,
}) => {
  const navItems: Array<{ id: TabId; label: string; icon: React.ReactNode; badge?: number; badgeColor?: string }> = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <LayoutDashboard className="w-4 h-4" />,
    },
    {
      id: 'events',
      label: 'Security Events',
      icon: <ScrollText className="w-4 h-4" />,
      badge: status?.events_count || 0,
      badgeColor: 'bg-slate-800 text-slate-300',
    },
    {
      id: 'detections',
      label: 'Threat Detection',
      icon: <ShieldAlert className="w-4 h-4" />,
      badge: detectionsCount,
      badgeColor: detectionsCount > 0 ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : undefined,
    },
    {
      id: 'assistant',
      label: 'AI Security Assistant',
      icon: <Bot className="w-4 h-4" />,
    },
    {
      id: 'incidents',
      label: 'Incident Investigation',
      icon: <Briefcase className="w-4 h-4" />,
      badge: openIncidentsCount,
      badgeColor: openIncidentsCount > 0 ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : undefined,
    },
    {
      id: 'reports',
      label: 'Reports',
      icon: <FileText className="w-4 h-4" />,
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: <Settings2 className="w-4 h-4" />,
    },
  ];

  return (
    <aside className="w-64 bg-[#0a1120] border-r border-slate-800/80 flex flex-col justify-between shrink-0 select-none">
      <div>
        {/* Branding */}
        <div className="p-5 border-b border-slate-800/80 flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 border border-cyan-400/30">
            <ShieldCheck className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-1.5">
              <span className="font-bold text-white text-base tracking-wide">AI Security</span>
              <span className="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/50 text-cyan-300">
                SOC
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-medium">Threat Detection &amp; Forensics</p>
          </div>
        </div>

        {/* Navigation list */}
        <nav className="p-3 space-y-1">
          <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            Operations Center
          </div>
          {navItems.map(item => {
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-blue-600/25 to-cyan-600/10 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <span className={isActive ? 'text-cyan-400' : 'text-slate-400'}>
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && item.badge > 0 && (
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full font-mono text-[11px] ${
                      item.badgeColor || 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer / Telemetry status */}
      <div className="p-4 border-t border-slate-800/80 space-y-3 bg-[#080e1a]/60">
        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-400 flex items-center space-x-1.5">
            <Activity className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            <span>Detection Engine</span>
          </span>
          <span className="text-emerald-400 font-medium font-mono text-[11px]">ACTIVE</span>
        </div>

        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-400 flex items-center space-x-1.5">
            <Terminal className="w-3.5 h-3.5 text-blue-400" />
            <span>Gemini AI Engine</span>
          </span>
          <span
            className={`font-mono text-[11px] ${
              status?.gemini_available ? 'text-cyan-400' : 'text-amber-400'
            }`}
          >
            {status?.gemini_available ? 'ONLINE' : 'HEURISTIC'}
          </span>
        </div>

        <div className="pt-2 border-t border-slate-800/60 text-[10px] text-slate-500 leading-tight">
          Undergraduate CS Defense Project. For authorized defensive security research and log triage.
        </div>
      </div>
    </aside>
  );
};
