import React, { useState, useEffect } from 'react';
import {
  Bot,
  Sparkles,
  Send,
  HelpCircle,
  ShieldCheck,
  CheckCircle2,
  FileQuestion,
  Wrench,
  AlertTriangle,
  Lightbulb,
  Lock,
  Cpu,
} from 'lucide-react';
import { Detection, AIExplanationResponse } from '../types';
import { requestAIExplanation } from '../services/api';

interface AIAssistantTabProps {
  detections: Detection[];
  selectedDetectionId?: string;
  onSelectDetectionId: (id: string) => void;
}

const PRESET_QUESTIONS = [
  'Why was this event flagged?',
  'What evidence supports this finding?',
  'What could explain this activity legitimately?',
  'What should a security analyst investigate next?',
  'How can this risk be reduced?',
  'Explain this alert in beginner-friendly language',
];

export const AIAssistantTab: React.FC<AIAssistantTabProps> = ({
  detections,
  selectedDetectionId,
  onSelectDetectionId,
}) => {
  const [activeAlertId, setActiveAlertId] = useState<string>(
    selectedDetectionId || (detections.length > 0 ? detections[0].detection_id : '')
  );
  const [customQuestion, setCustomQuestion] = useState<string>('');
  const [explanation, setExplanation] = useState<AIExplanationResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Sync prop changes
  useEffect(() => {
    if (selectedDetectionId && selectedDetectionId !== activeAlertId) {
      setActiveAlertId(selectedDetectionId);
    }
  }, [selectedDetectionId]);

  const handleRunAnalysis = async (question?: string) => {
    if (!activeAlertId) return;
    setIsLoading(true);
    setError(null);

    try {
      const res = await requestAIExplanation({
        detection_id: activeAlertId,
        question: question || customQuestion || undefined,
      });
      setExplanation(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  // Run initial analysis when alert is first selected
  useEffect(() => {
    if (activeAlertId && !explanation) {
      handleRunAnalysis();
    }
  }, [activeAlertId]);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="p-4 rounded-2xl bg-gradient-to-r from-slate-900 via-blue-950/40 to-slate-900 border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Bot className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold text-slate-100">AI Security Assistant Workbench</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Powered by Google Gemini 3.8 Flash with defensive boundaries, untrusted log sanitization, and forensic analysis.
          </p>
        </div>

        {/* Prompt Injection Guard Notice */}
        <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-950/80 border border-cyan-500/30 text-xs text-cyan-300">
          <Lock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="font-mono text-[11px]">Prompt Injection Guard: ACTIVE</span>
        </div>
      </div>

      {/* Alert Selector Bar */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3 flex-1">
          <label className="text-xs font-semibold text-slate-400 shrink-0">Select Target Alert:</label>
          <select
            value={activeAlertId}
            onChange={e => {
              setActiveAlertId(e.target.value);
              onSelectDetectionId(e.target.value);
              setExplanation(null);
            }}
            className="flex-1 max-w-xl px-3 py-2 rounded-xl bg-slate-950 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            {detections.map(d => (
              <option key={d.detection_id} value={d.detection_id}>
                [{d.detection_id}] {d.rule_name} — Severity: {d.severity} (Score: {d.risk_score})
              </option>
            ))}
          </select>
        </div>

        <button
          onClick={() => handleRunAnalysis()}
          disabled={isLoading || !activeAlertId}
          className="flex items-center justify-center space-x-2 px-4 py-2 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 disabled:opacity-50 text-white text-xs font-medium shadow-md shadow-cyan-900/30 transition shrink-0"
        >
          <Sparkles className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>{isLoading ? 'Generating Analysis...' : 'Analyze Finding'}</span>
        </button>
      </div>

      {/* Pre-crafted Guided Inquiry Buttons */}
      <div className="space-y-2">
        <div className="flex items-center space-x-2 text-xs text-slate-400 font-semibold uppercase tracking-wider">
          <FileQuestion className="w-3.5 h-3.5 text-cyan-400" />
          <span>Quick Analyst Queries</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {PRESET_QUESTIONS.map(q => (
            <button
              key={q}
              onClick={() => {
                setCustomQuestion(q);
                handleRunAnalysis(q);
              }}
              disabled={isLoading}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-cyan-300 text-xs font-medium transition"
            >
              {q}
            </button>
          ))}
        </div>
      </div>

      {/* Custom Question Input */}
      <form
        onSubmit={e => {
          e.preventDefault();
          if (customQuestion.trim()) handleRunAnalysis(customQuestion);
        }}
        className="flex items-center space-x-2"
      >
        <input
          type="text"
          placeholder="Ask a specific defensive question about this alert (e.g. 'What MITRE ATT&CK technique matches this?')"
          value={customQuestion}
          onChange={e => setCustomQuestion(e.target.value)}
          className="flex-1 px-4 py-2.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 placeholder:text-slate-500"
        />
        <button
          type="submit"
          disabled={isLoading || !customQuestion.trim()}
          className="px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium flex items-center space-x-1.5 transition shadow-md shadow-blue-900/30"
        >
          <Send className="w-3.5 h-3.5" />
          <span>Inquire</span>
        </button>
      </form>

      {/* Error display */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-xs text-rose-300 flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>Analysis Error: {error}</span>
        </div>
      )}

      {/* Analysis Output Container */}
      {explanation && (
        <div className="space-y-6">
          {/* Engine & Verification Banner */}
          <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
              <span className="font-semibold text-slate-200">
                Analysis Engine: <strong className="text-cyan-300 font-mono">{explanation.model_used}</strong>
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${
                  explanation.is_ai_generated
                    ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                    : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                }`}
              >
                {explanation.is_ai_generated ? 'AI-GENERATED' : 'DETERMINISTIC FALLBACK'}
              </span>
            </div>

            <div className="text-[11px] text-slate-400 italic">
              {explanation.verification_notice}
            </div>
          </div>

          {/* Executive Summary */}
          <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-2">
            <div className="flex items-center space-x-2 text-xs font-semibold uppercase tracking-wider text-cyan-400">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span>Executive Briefing</span>
            </div>
            <p className="text-sm font-medium text-slate-100 leading-relaxed">
              {explanation.summary}
            </p>
          </div>

          {/* Technical Analysis */}
          <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-2">
            <div className="flex items-center space-x-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <Cpu className="w-4 h-4 text-slate-400" />
              <span>In-Depth Technical Evaluation</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
              {explanation.detailed_analysis}
            </p>
          </div>

          {/* Split: Evidence Breakdown vs Alternative Hypotheses */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
            {/* Concrete Evidence */}
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center space-x-2 font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
                <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                <span>Verified Telemetry Evidence</span>
              </div>
              <ul className="space-y-2 pl-1 list-disc list-inside text-slate-300 font-mono text-[11px]">
                {explanation.evidence_breakdown.map((ev, i) => (
                  <li key={i}>{ev}</li>
                ))}
              </ul>
            </div>

            {/* Legitimate Explanations */}
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center space-x-2 font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
                <HelpCircle className="w-4 h-4 text-amber-400" />
                <span>Alternative Benign Explanations</span>
              </div>
              <ul className="space-y-2 pl-1 list-disc list-inside text-slate-300">
                {explanation.legitimate_explanations.map((leg, i) => (
                  <li key={i}>{leg}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* Split: SOC Investigation Steps vs Remediation */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
            {/* Investigation Checklist */}
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center space-x-2 font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
                <ShieldCheck className="w-4 h-4 text-indigo-400" />
                <span>SOC Analyst Investigation Checklist</span>
              </div>
              <ul className="space-y-2">
                {explanation.investigation_steps.map((step, i) => (
                  <li
                    key={i}
                    className="p-2.5 rounded-lg bg-slate-950 border border-slate-850 text-slate-300 flex items-start space-x-2"
                  >
                    <span className="w-4 h-4 rounded-full bg-indigo-950 border border-indigo-800 text-indigo-400 flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">
                      {i + 1}
                    </span>
                    <span>{step}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Hardening & Remediation */}
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center space-x-2 font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
                <Wrench className="w-4 h-4 text-emerald-400" />
                <span>Defensive Hardening &amp; Remediation</span>
              </div>
              <ul className="space-y-2">
                {explanation.remediation_steps.map((rem, i) => (
                  <li
                    key={i}
                    className="p-2.5 rounded-lg bg-slate-950 border border-slate-850 text-slate-300 flex items-start space-x-2"
                  >
                    <span className="w-4 h-4 rounded-full bg-emerald-950 border border-emerald-800 text-emerald-400 flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">
                      {i + 1}
                    </span>
                    <span>{rem}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Beginner-Friendly Translation Card */}
          <div className="p-5 rounded-2xl bg-gradient-to-r from-blue-950/40 via-cyan-950/20 to-blue-950/40 border border-cyan-800/40 space-y-2 text-xs">
            <div className="flex items-center space-x-2 font-semibold text-cyan-300 uppercase tracking-wider text-[11px]">
              <Lightbulb className="w-4 h-4 text-cyan-400" />
              <span>Beginner-Friendly Cybersecurity Summary</span>
            </div>
            <p className="text-slate-200 leading-relaxed">
              {explanation.beginner_summary}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
