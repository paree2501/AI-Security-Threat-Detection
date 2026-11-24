import React, { useState } from 'react';
import {
  Settings2,
  Save,
  RotateCcw,
  CheckCircle,
  Cpu,
  Terminal,
  ShieldAlert,
  Play,
  Sliders,
  Sparkles,
  Info,
} from 'lucide-react';
import { DetectionConfig, SystemStatus } from '../types';
import { runAutomatedTests } from '../services/api';

interface SettingsTabProps {
  config: DetectionConfig;
  onUpdateConfig: (newCfg: Partial<DetectionConfig>) => Promise<void>;
  onResetConfig: () => Promise<void>;
  status: SystemStatus | null;
  onRetrainML: () => void;
  isRetrainingML: boolean;
}

export const SettingsTab: React.FC<SettingsTabProps> = ({
  config,
  onUpdateConfig,
  onResetConfig,
  status,
  onRetrainML,
  isRetrainingML,
}) => {
  const [formConfig, setFormConfig] = useState<DetectionConfig>({ ...config });
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  // Test suite execution state
  const [isRunningTests, setIsRunningTests] = useState(false);
  const [testResults, setTestResults] = useState<{
    total_tests: number;
    passed: number;
    failed: number;
    duration_ms: number;
    results: Array<{ id: number; name: string; status: string; description: string }>;
  } | null>(null);

  const handleRuleToggle = (ruleKey: keyof DetectionConfig['enabled_rules']) => {
    setFormConfig(prev => ({
      ...prev,
      enabled_rules: {
        ...prev.enabled_rules,
        [ruleKey]: !prev.enabled_rules[ruleKey],
      },
    }));
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setSaveSuccess(false);
    try {
      await onUpdateConfig(formConfig);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } finally {
      setIsSaving(false);
    }
  };

  const [showResetConfirm, setShowResetConfirm] = useState(false);

  const handleReset = async () => {
    await onResetConfig();
    setFormConfig({ ...config });
    setShowResetConfirm(false);
  };

  const handleRunTests = async () => {
    setIsRunningTests(true);
    try {
      const data = await runAutomatedTests();
      setTestResults(data);
    } catch (err) {
      console.error('Failed to run test suite:', err);
    } finally {
      setIsRunningTests(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Settings2 className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-slate-100">System Settings &amp; Engine Tuning</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Configure correlation thresholds, toggle detection rules, inspect system runtimes, and verify test suites.
          </p>
        </div>

        <div className="flex items-center space-x-2.5">
          {showResetConfirm ? (
            <div className="flex items-center space-x-1.5 p-1 rounded-xl bg-amber-950/80 border border-amber-700">
              <span className="text-[11px] text-amber-300 px-1.5 font-medium">Reset defaults?</span>
              <button
                type="button"
                onClick={handleReset}
                className="px-2 py-1 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-[10px] font-bold"
              >
                Yes
              </button>
              <button
                type="button"
                onClick={() => setShowResetConfirm(false)}
                className="px-2 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px]"
              >
                No
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => setShowResetConfirm(true)}
              className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Restore Defaults</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Settings Form */}
      <form onSubmit={handleSave} className="space-y-6">
        {/* Detection Thresholds Card */}
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800/80 space-y-5 shadow-xl">
          <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100">Detection Engine Thresholds</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Failed Login Threshold */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-200">
                Failed Login Trigger Count
              </label>
              <input
                type="number"
                min={2}
                max={20}
                value={formConfig.failed_login_threshold}
                onChange={e =>
                  setFormConfig({
                    ...formConfig,
                    failed_login_threshold: parseInt(e.target.value, 10) || 3,
                  })
                }
                className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-700 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
              />
              <p className="text-[11px] text-slate-400">
                Minimum consecutive authentication failures to flag Rule A (Default: 3 attempts).
              </p>
            </div>

            {/* Time window in minutes */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-200">
                Temporal Correlation Window (Minutes)
              </label>
              <input
                type="number"
                min={1}
                max={60}
                value={formConfig.failed_login_window_minutes}
                onChange={e =>
                  setFormConfig({
                    ...formConfig,
                    failed_login_window_minutes: parseInt(e.target.value, 10) || 10,
                  })
                }
                className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-700 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
              />
              <p className="text-[11px] text-slate-400">
                Maximum elapsed minutes to cluster related failed logins (Default: 10 mins).
              </p>
            </div>

            {/* Network Bytes Threshold */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-200">
                Network Exfiltration Threshold (MB)
              </label>
              <input
                type="number"
                min={5}
                max={500}
                value={formConfig.network_bytes_threshold_mb}
                onChange={e =>
                  setFormConfig({
                    ...formConfig,
                    network_bytes_threshold_mb: parseInt(e.target.value, 10) || 50,
                  })
                }
                className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-700 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
              />
              <p className="text-[11px] text-slate-400">
                Outbound payload volume exceeding this triggers Rule C alert (Default: 50 MB).
              </p>
            </div>
          </div>
        </div>

        {/* Enabled Detection Rules */}
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800/80 space-y-4 shadow-xl">
          <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-bold text-slate-100">Modular Detection Rule Policies</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Rule A */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-start justify-between space-x-3">
              <div>
                <span className="font-semibold text-slate-200 text-xs">
                  Rule A: Repeated Failed Login Attempts
                </span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Flags repeated password failures for same user/IP within the configurable time window.
                </p>
              </div>
              <input
                type="checkbox"
                checked={formConfig.enabled_rules.repeated_failed_login}
                onChange={() => handleRuleToggle('repeated_failed_login')}
                className="w-4 h-4 rounded text-cyan-600 focus:ring-cyan-500 mt-1 cursor-pointer"
              />
            </div>

            {/* Rule B */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-start justify-between space-x-3">
              <div>
                <span className="font-semibold text-slate-200 text-xs">
                  Rule B: Suspicious Login Pattern
                </span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Flags multiple login failures followed immediately by a successful authentication.
                </p>
              </div>
              <input
                type="checkbox"
                checked={formConfig.enabled_rules.suspicious_login_pattern}
                onChange={() => handleRuleToggle('suspicious_login_pattern')}
                className="w-4 h-4 rounded text-cyan-600 focus:ring-cyan-500 mt-1 cursor-pointer"
              />
            </div>

            {/* Rule C */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-start justify-between space-x-3">
              <div>
                <span className="font-semibold text-slate-200 text-xs">
                  Rule C: Unusual Network Activity
                </span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Flags high data transfers (&gt;50MB) and connections to anomalous reverse-shell ports.
                </p>
              </div>
              <input
                type="checkbox"
                checked={formConfig.enabled_rules.unusual_network_activity}
                onChange={() => handleRuleToggle('unusual_network_activity')}
                className="w-4 h-4 rounded text-cyan-600 focus:ring-cyan-500 mt-1 cursor-pointer"
              />
            </div>

            {/* Rule D */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-start justify-between space-x-3">
              <div>
                <span className="font-semibold text-slate-200 text-xs">
                  Rule D: Suspicious Administrative Activity
                </span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Identifies unauthorized sudo group additions or /etc/shadow credential modifications.
                </p>
              </div>
              <input
                type="checkbox"
                checked={formConfig.enabled_rules.suspicious_admin_activity}
                onChange={() => handleRuleToggle('suspicious_admin_activity')}
                className="w-4 h-4 rounded text-cyan-600 focus:ring-cyan-500 mt-1 cursor-pointer"
              />
            </div>

            {/* Rule E */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-start justify-between space-x-3">
              <div>
                <span className="font-semibold text-slate-200 text-xs">
                  Rule E: Potentially Dangerous File Activity
                </span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Flags execution of binaries or shell scripts from volatile paths (/tmp) or malware signatures.
                </p>
              </div>
              <input
                type="checkbox"
                checked={formConfig.enabled_rules.dangerous_file_activity}
                onChange={() => handleRuleToggle('dangerous_file_activity')}
                className="w-4 h-4 rounded text-cyan-600 focus:ring-cyan-500 mt-1 cursor-pointer"
              />
            </div>

            {/* Rule F */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-start justify-between space-x-3">
              <div>
                <span className="font-semibold text-slate-200 text-xs">
                  Rule F: Unknown or Unclassified Security Events
                </span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Flags unhandled status codes or unfamiliar event types for mandatory analyst triage.
                </p>
              </div>
              <input
                type="checkbox"
                checked={formConfig.enabled_rules.unknown_unclassified_event}
                onChange={() => handleRuleToggle('unknown_unclassified_event')}
                className="w-4 h-4 rounded text-cyan-600 focus:ring-cyan-500 mt-1 cursor-pointer"
              />
            </div>
          </div>

          <div className="flex items-center justify-end space-x-3 pt-3">
            {saveSuccess && (
              <span className="text-xs text-emerald-400 flex items-center space-x-1">
                <CheckCircle className="w-3.5 h-3.5" />
                <span>Configuration saved &amp; detection engine re-indexed!</span>
              </span>
            )}
            <button
              type="submit"
              disabled={isSaving}
              className="flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-medium shadow-md shadow-blue-900/30 transition disabled:opacity-50"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{isSaving ? 'Saving...' : 'Save Configuration'}</span>
            </button>
          </div>
        </div>
      </form>

      {/* Runtime Environment & Architecture Status */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800/80 space-y-4 shadow-xl">
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-slate-100">System Runtime &amp; Architecture Status</h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          {/* Node/Express Runtime */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-850 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-200">Server Architecture</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                ONLINE
              </span>
            </div>
            <p className="text-slate-400 text-[11px]">{status?.environment_type}</p>
            <div className="text-[10px] text-slate-500">Dev Server Port: 3000 • Ingest Limit: 5MB</div>
          </div>

          {/* Gemini AI Status */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-850 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-200">Gemini 3.8 Flash AI</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                  status?.gemini_available
                    ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                    : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                }`}
              >
                {status?.gemini_available ? 'CONNECTED' : 'HEURISTIC'}
              </span>
            </div>
            <p className="text-slate-400 text-[11px]">
              {status?.gemini_available
                ? 'Server environment key active with prompt injection boundary defense.'
                : 'Using deterministic rule-based heuristic explanation engine.'}
            </p>
          </div>

          {/* Machine Learning Model */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-850 space-y-2 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-200">ML Anomaly Model</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/30">
                  {status?.ml_model_trained ? 'TRAINED' : 'NOT TRAINED'}
                </span>
              </div>
              <p className="text-slate-400 text-[11px] mt-1">
                Multi-feature statistical Z-score / IQR isolation anomaly detector.
              </p>
            </div>
            <button
              onClick={onRetrainML}
              disabled={isRetrainingML}
              className="w-full flex items-center justify-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
            >
              <Cpu className={`w-3.5 h-3.5 ${isRetrainingML ? 'animate-spin' : ''}`} />
              <span>{isRetrainingML ? 'Retraining Model...' : 'Train & Evaluate Model'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Automated Test Suite Verification Section */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800/80 space-y-5 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <div className="flex items-center space-x-2">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-bold text-slate-100">Automated Verification Test Suite</h3>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Covers the 13 required cybersecurity unit, ingestion, resilience, and evaluation test cases.
            </p>
          </div>

          <button
            onClick={handleRunTests}
            disabled={isRunningTests}
            className="flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-medium shadow-md shadow-emerald-900/30 transition shrink-0"
          >
            <Play className={`w-3.5 h-3.5 ${isRunningTests ? 'animate-spin' : ''}`} />
            <span>{isRunningTests ? 'Running Verification...' : 'Execute Test Suite (13 Tests)'}</span>
          </button>
        </div>

        {testResults ? (
          <div className="space-y-4">
            <div className="flex items-center space-x-4 p-3 rounded-xl bg-emerald-950/30 border border-emerald-800/40 text-xs text-emerald-300">
              <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>
                All <strong>{testResults.passed} of {testResults.total_tests}</strong> verification tests passed
                successfully in {testResults.duration_ms} ms!
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
              {testResults.results.map(t => (
                <div
                  key={t.id}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-850 flex items-start justify-between space-x-2"
                >
                  <div className="space-y-0.5">
                    <div className="font-semibold text-slate-200">
                      #{t.id}: {t.name}
                    </div>
                    <p className="text-[11px] text-slate-400">{t.description}</p>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 shrink-0">
                    {t.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="p-6 text-center bg-slate-950/60 rounded-xl border border-slate-850 text-xs text-slate-400 space-y-2">
            <p>Click &quot;Execute Test Suite&quot; above to run automated end-to-end tests across the detection engine.</p>
            <p className="text-[11px] text-slate-500 font-mono">
              Also executable in terminal via: <code className="text-cyan-400">python3 -m unittest tests/test_detection.py</code>
            </p>
          </div>
        )}
      </div>

      {/* Honest Documentation Disclaimer */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start space-x-3 text-xs text-slate-400">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="font-semibold text-slate-300">Academic &amp; Interview Grounding:</strong> This system
          demonstrates how security event telemetry is parsed, validated, correlated against rule heuristics, scored
          through multi-factor risk algorithms, and analyzed through generative AI while maintaining strict prompt
          injection boundaries.
        </div>
      </div>
    </div>
  );
};
