import React from 'react';
import {
  FileText,
  Download,
  Printer,
  ShieldCheck,
  CheckCircle,
  Database,
  ShieldAlert,
  Cpu,
  Layers,
  Lock,
} from 'lucide-react';
import { Detection, Incident, SecurityEvent, MLEvaluation } from '../types';

interface ReportsTabProps {
  events: SecurityEvent[];
  detections: Detection[];
  incidents: Incident[];
  mlEvaluation: MLEvaluation | null;
}

export const ReportsTab: React.FC<ReportsTabProps> = ({
  events,
  detections,
  incidents,
  mlEvaluation,
}) => {
  const downloadJSON = () => {
    const a = document.createElement('a');
    a.href = '/api/reports/export?format=json';
    a.download = 'ai-security-report.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const downloadCSV = () => {
    const a = document.createElement('a');
    a.href = '/api/reports/export?format=csv';
    a.download = 'ai-security-detections.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handlePrint = () => {
    window.print();
  };

  const criticalDetections = detections.filter(d => d.severity === 'CRITICAL');
  const highDetections = detections.filter(d => d.severity === 'HIGH');
  const mediumDetections = detections.filter(d => d.severity === 'MEDIUM');
  const lowDetections = detections.filter(d => d.severity === 'LOW');

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner and Export Actions */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-slate-100">Executive Security &amp; Forensic Audit Report</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Comprehensive audit report covering scope, telemetry breakdown, detection rules, and ML baseline metrics.
          </p>
        </div>

        <div className="flex items-center flex-wrap gap-2.5">
          <button
            onClick={downloadJSON}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export JSON Audit</span>
          </button>

          <button
            onClick={downloadCSV}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            <span>Export Detections CSV</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium shadow-md shadow-blue-900/30 transition"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / PDF Document</span>
          </button>
        </div>
      </div>

      {/* Printable Report Paper Layout */}
      <div className="p-8 rounded-2xl bg-slate-950 border border-slate-850 shadow-2xl space-y-8 font-sans">
        {/* Document Header */}
        <div className="border-b border-slate-800 pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs uppercase tracking-widest font-mono text-cyan-400 font-bold">
                CONFIDENTIAL CYBERSECURITY REPORT
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 font-mono">
                REF-SOC-2026
              </span>
            </div>
            <h1 className="text-xl font-extrabold text-slate-100 mt-1">
              AI Security Threat Detection &amp; Digital Forensics Assessment
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Automated Incident Correlation, Rule-Based Threat Telemetry, and Machine Learning Evaluation
            </p>
          </div>

          <div className="text-right text-xs text-slate-400 space-y-0.5 font-mono">
            <div>Generated: {new Date().toUTCString()}</div>
            <div>Classification: Internal Security Assessment</div>
            <div>Platform: AI Security v1.0.0</div>
          </div>
        </div>

        {/* Section 1: Executive Summary & Analysis Scope */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
            <Database className="w-4 h-4 text-cyan-400" />
            <span>1. Executive Summary &amp; Analysis Scope</span>
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <div className="text-2xl font-bold text-slate-100 font-mono">{events.length}</div>
              <div className="text-[11px] text-slate-400 mt-1">Total Events Ingested</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <div className="text-2xl font-bold text-amber-400 font-mono">{detections.length}</div>
              <div className="text-[11px] text-slate-400 mt-1">Threat Detections</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <div className="text-2xl font-bold text-rose-400 font-mono">
                {criticalDetections.length + highDetections.length}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">Critical &amp; High Alerts</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <div className="text-2xl font-bold text-indigo-400 font-mono">{incidents.length}</div>
              <div className="text-[11px] text-slate-400 mt-1">Incidents Docketed</div>
            </div>
          </div>
        </div>

        {/* Section 2: Threat Detection Breakdown */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <span>2. Severity &amp; Risk Scoring Distribution</span>
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-800/40 text-rose-300">
              <div className="font-bold text-base font-mono">{criticalDetections.length}</div>
              <div className="text-[11px]">Critical Risk (80–100)</div>
            </div>
            <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-800/40 text-amber-300">
              <div className="font-bold text-base font-mono">{highDetections.length}</div>
              <div className="text-[11px]">High Risk (60–79)</div>
            </div>
            <div className="p-3 rounded-lg bg-yellow-950/30 border border-yellow-800/40 text-yellow-300">
              <div className="font-bold text-base font-mono">{mediumDetections.length}</div>
              <div className="text-[11px]">Medium Risk (30–59)</div>
            </div>
            <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-800/40 text-emerald-300">
              <div className="font-bold text-base font-mono">{lowDetections.length}</div>
              <div className="text-[11px]">Low Risk (0–29)</div>
            </div>
          </div>
        </div>

        {/* Section 3: Key Incident Findings */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
            <Layers className="w-4 h-4 text-indigo-400" />
            <span>3. Key Incident Case Docket</span>
          </h2>

          <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/60">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <th className="p-3">ID</th>
                  <th className="p-3">Title &amp; Scope</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Analyst</th>
                  <th className="p-3">Notes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850 text-slate-300 font-mono text-[11px]">
                {incidents.map(inc => (
                  <tr key={inc.incident_id}>
                    <td className="p-3 font-bold text-slate-200">{inc.incident_id}</td>
                    <td className="p-3 font-sans text-slate-200 max-w-xs">{inc.title}</td>
                    <td className="p-3">
                      <span className="font-bold text-amber-400">{inc.severity}</span>
                    </td>
                    <td className="p-3">{inc.status}</td>
                    <td className="p-3 font-sans">{inc.assigned_analyst}</td>
                    <td className="p-3">{inc.notes.length} log entries</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section 4: Machine Learning Evaluation & Anomaly Scoring */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>4. Machine Learning &amp; Anomaly Detection Model Evaluation</span>
          </h2>

          {mlEvaluation ? (
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4 text-xs">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2">
                <div>
                  <span className="font-bold text-slate-200 text-sm">{mlEvaluation.model_name}</span>
                  <div className="text-[11px] text-slate-400">Version: {mlEvaluation.model_version}</div>
                </div>
                <div className="text-right text-[11px] font-mono text-cyan-400">
                  Trained: {mlEvaluation.training_timestamp ? new Date(mlEvaluation.training_timestamp).toLocaleDateString() : 'Active'}
                </div>
              </div>

              {/* Metric Badges */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-lg font-bold font-mono text-cyan-400">
                    {(mlEvaluation.accuracy * 100).toFixed(1)}%
                  </div>
                  <div className="text-[10px] text-slate-400">Test Accuracy</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-lg font-bold font-mono text-emerald-400">
                    {(mlEvaluation.precision * 100).toFixed(1)}%
                  </div>
                  <div className="text-[10px] text-slate-400">Precision (PPV)</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-lg font-bold font-mono text-blue-400">
                    {(mlEvaluation.recall * 100).toFixed(1)}%
                  </div>
                  <div className="text-[10px] text-slate-400">Recall (Sensitivity)</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-lg font-bold font-mono text-purple-400">
                    {mlEvaluation.f1_score.toFixed(3)}
                  </div>
                  <div className="text-[10px] text-slate-400">F1 Harmonic Score</div>
                </div>
              </div>

              {/* Confusion Matrix Table */}
              <div className="space-y-1.5 pt-1">
                <span className="font-semibold text-slate-300 text-[11px] uppercase tracking-wider">
                  Test Partition Confusion Matrix (70/30 Split):
                </span>
                <div className="grid grid-cols-2 gap-2 text-center font-mono text-xs max-w-sm">
                  <div className="p-2.5 rounded bg-emerald-950/40 border border-emerald-800/40">
                    <div className="font-bold text-emerald-400">{mlEvaluation.confusion_matrix.tp}</div>
                    <div className="text-[10px] text-slate-400">True Positives (TP)</div>
                  </div>
                  <div className="p-2.5 rounded bg-rose-950/40 border border-rose-800/40">
                    <div className="font-bold text-rose-400">{mlEvaluation.confusion_matrix.fp}</div>
                    <div className="text-[10px] text-slate-400">False Positives (FP)</div>
                  </div>
                  <div className="p-2.5 rounded bg-rose-950/40 border border-rose-800/40">
                    <div className="font-bold text-rose-400">{mlEvaluation.confusion_matrix.fn}</div>
                    <div className="text-[10px] text-slate-400">False Negatives (FN)</div>
                  </div>
                  <div className="p-2.5 rounded bg-emerald-950/40 border border-emerald-800/40">
                    <div className="font-bold text-emerald-400">{mlEvaluation.confusion_matrix.tn}</div>
                    <div className="text-[10px] text-slate-400">True Negatives (TN)</div>
                  </div>
                </div>
              </div>

              {/* Features and honest disclosure */}
              <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400 leading-relaxed">
                <strong>Features extracted:</strong> {mlEvaluation.features_used.join(', ')}.
                <p className="mt-1 italic text-slate-500">{mlEvaluation.notes}</p>
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-500">
              ML anomaly model evaluation metrics will display once events are analyzed and trained.
            </div>
          )}
        </div>

        {/* Section 5: Defense Recommendations & Compliance Disclaimer */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>5. Recommended Mitigations &amp; Audit Seal</span>
          </h2>
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2 text-xs text-slate-300 leading-relaxed">
            <p>
              1. <strong>Authentication Perimeter:</strong> Enforce multi-factor authentication (FIDO2/WebAuthn) on all
              SSH (port 22) and administrative endpoints to eliminate credential brute-forcing vulnerability.
            </p>
            <p>
              2. <strong>Least Privilege:</strong> Audit membership in sudoers and wheel groups. Implement ephemeral
              privileged access tokens with mandatory ticketing justification.
            </p>
            <p>
              3. <strong>Egress Filtering:</strong> Implement data loss prevention (DLP) filters on high-volume outbound
              ports and alert on bulk transfers exceeding 50 MB to non-corporate destinations.
            </p>
          </div>
        </div>

        {/* Footer Security Notice */}
        <div className="pt-6 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500">
          <div className="flex items-center space-x-1.5">
            <Lock className="w-3.5 h-3.5 text-slate-600" />
            <span>API credentials, keys, and raw authentication secrets stripped from report export.</span>
          </div>
          <span>Digital Forensics Docket Reference</span>
        </div>
      </div>
    </div>
  );
};
