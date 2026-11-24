import React, { useState } from 'react';
import {
  X,
  UploadCloud,
  FileSpreadsheet,
  AlertCircle,
  CheckCircle2,
  Download,
  ShieldAlert,
  Info,
} from 'lucide-react';
import { SecurityEvent } from '../types';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onUploadSuccess: (res: { added: number; duplicates: number; total_events: number }) => void;
}

export const UploadModal: React.FC<UploadModalProps> = ({
  isOpen,
  onClose,
  onUploadSuccess,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [fileContent, setFileContent] = useState<string>('');
  const [previewRows, setPreviewRows] = useState<Array<Record<string, string>>>([]);
  const [headers, setHeaders] = useState<string[]>([]);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0];
    if (!selected) return;

    setUploadError(null);
    setValidationErrors([]);

    // Check size limit (2MB)
    if (selected.size > 2 * 1024 * 1024) {
      setUploadError('File exceeds 2MB limit. Please upload a smaller log segment.');
      return;
    }

    // Check file extension
    const name = selected.name.toLowerCase();
    if (!name.endsWith('.csv') && !name.endsWith('.json')) {
      setUploadError('Unsupported format. Please upload a .csv or .json security log file.');
      return;
    }

    setFile(selected);

    const reader = new FileReader();
    reader.onload = event => {
      const text = event.target?.result as string;
      setFileContent(text);

      if (name.endsWith('.csv')) {
        parseAndValidateCSV(text);
      } else {
        parseAndValidateJSON(text);
      }
    };
    reader.readAsText(selected);
  };

  const parseAndValidateCSV = (text: string) => {
    const lines = text.trim().split(/\r?\n/);
    const errors: string[] = [];

    if (lines.length < 2) {
      errors.push('File appears empty or missing header row.');
      setValidationErrors(errors);
      return;
    }

    const rawHeaders = lines[0].split(',').map(h => h.trim());
    setHeaders(rawHeaders);

    const required = ['timestamp', 'event_type', 'action'];
    const missing = required.filter(r => !rawHeaders.includes(r));
    if (missing.length > 0) {
      errors.push(`Missing essential columns: ${missing.join(', ')}. Standard schema requires timestamp, event_type, and action.`);
    }

    // Check preview of first 5 rows
    const previews: Array<Record<string, string>> = [];
    for (let i = 1; i < Math.min(lines.length, 6); i++) {
      const cols = lines[i].split(',');
      const row: Record<string, string> = {};
      rawHeaders.forEach((h, idx) => {
        row[h] = cols[idx] ? cols[idx].trim() : '';
      });
      previews.push(row);
    }

    if (lines.length > 5001) {
      errors.push(`File contains ${lines.length - 1} rows. Max limit is 5,000 events.`);
    }

    setPreviewRows(previews);
    setValidationErrors(errors);
  };

  const parseAndValidateJSON = (text: string) => {
    const errors: string[] = [];
    try {
      const parsed = JSON.parse(text);
      const arr: SecurityEvent[] = Array.isArray(parsed) ? parsed : [parsed];
      if (arr.length === 0) {
        errors.push('JSON array is empty.');
      } else {
        const first = arr[0];
        const keys = Object.keys(first);
        setHeaders(keys);
        setPreviewRows(
          arr.slice(0, 5).map(item => {
            const row: Record<string, string> = {};
            keys.forEach(k => {
              row[k] = String((item as unknown as Record<string, unknown>)[k] ?? '');
            });
            return row;
          })
        );
        if (arr.length > 5000) {
          errors.push(`JSON contains ${arr.length} events. Maximum allowed is 5,000.`);
        }
      }
    } catch {
      errors.push('Failed to parse JSON syntax. Please verify valid JSON structure.');
    }
    setValidationErrors(errors);
  };

  const handleImport = async () => {
    if (!fileContent || validationErrors.length > 0) return;
    setIsUploading(true);
    setUploadError(null);

    try {
      let res;
      if (file?.name.endsWith('.json')) {
        const events = JSON.parse(fileContent);
        const arr = Array.isArray(events) ? events : [events];
        const response = await fetch('/api/events/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ events: arr }),
        });
        res = await response.json();
      } else {
        const response = await fetch('/api/events/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ csv_text: fileContent }),
        });
        res = await response.json();
      }

      if (res.error) {
        throw new Error(res.error);
      }

      onUploadSuccess(res);
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setUploadError(msg);
    } finally {
      setIsUploading(false);
    }
  };

  const downloadSampleTemplate = () => {
    const sample = `event_id,timestamp,source_ip,username,event_type,action,status,destination_ip,destination_port,failed_attempt_count,bytes_transferred,message,is_suspicious,attack_type
EVT-DEMO-01,2026-10-22T08:00:00Z,192.168.1.100,alice,AUTH_LOGIN,user_login,SUCCESS,10.0.0.5,443,0,1200,Normal login,0,BENIGN
EVT-DEMO-02,2026-10-22T08:01:00Z,198.51.100.55,admin,AUTH_LOGIN,user_login,FAILURE,10.0.0.10,22,1,0,SSH authentication failure,1,BRUTE_FORCE
EVT-DEMO-03,2026-10-22T08:01:30Z,198.51.100.55,admin,AUTH_LOGIN,user_login,FAILURE,10.0.0.10,22,2,0,SSH authentication failure,1,BRUTE_FORCE
EVT-DEMO-04,2026-10-22T08:02:00Z,198.51.100.55,admin,AUTH_LOGIN,user_login,FAILURE,10.0.0.10,22,3,0,SSH authentication failure,1,BRUTE_FORCE
EVT-DEMO-05,2026-10-22T08:15:00Z,10.0.0.15,db_admin,NETWORK_CONN,data_transfer,SUCCESS,198.51.100.88,443,0,85000000,Data transfer to external IP,1,UNUSUAL_NETWORK_ACTIVITY`;

    const blob = new Blob([sample], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sample_security_events_template.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-[#0f172a] border border-slate-700/80 rounded-2xl w-full max-w-2xl shadow-2xl overflow-hidden flex flex-col my-8">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <UploadCloud className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100">Ingest Security Event Logs</h2>
              <p className="text-xs text-slate-400">Import CSV or JSON format with schema verification</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 overflow-y-auto max-h-[70vh]">
          {/* Privacy & Anonymization warning */}
          <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start space-x-3 text-xs text-amber-200">
            <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="leading-relaxed">
              <strong className="font-semibold text-amber-300">Data Privacy &amp; Sanitization:</strong> Security event
              logs may contain sensitive hostnames, IP addresses, or usernames. Ensure logs are sanitized or
              anonymized before analysis. Logs are analyzed in local sandbox memory and never broadcast.
            </div>
          </div>

          {/* Upload Dropzone */}
          <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-xl p-6 text-center transition cursor-pointer bg-slate-900/40 relative">
            <input
              type="file"
              accept=".csv,.json"
              onChange={handleFileChange}
              className="absolute inset-0 opacity-0 cursor-pointer"
            />
            <div className="flex flex-col items-center space-y-2">
              <FileSpreadsheet className="w-10 h-10 text-cyan-400" />
              <div className="text-sm font-medium text-slate-200">
                {file ? file.name : 'Choose CSV or JSON security log file'}
              </div>
              <p className="text-xs text-slate-400">
                Drag and drop, or browse. Limits: 2MB max file size, up to 5,000 event rows.
              </p>
            </div>
          </div>

          {/* Download sample template button */}
          <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
            <span className="flex items-center space-x-1.5">
              <Info className="w-3.5 h-3.5 text-slate-500" />
              <span>Need a compliant schema template?</span>
            </span>
            <button
              onClick={downloadSampleTemplate}
              className="flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 font-medium hover:underline"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Sample CSV Template</span>
            </button>
          </div>

          {/* Validation Feedback */}
          {validationErrors.length > 0 && (
            <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 space-y-1.5 text-xs text-rose-300">
              <div className="flex items-center space-x-2 font-semibold text-rose-400">
                <AlertCircle className="w-4 h-4" />
                <span>Validation Errors</span>
              </div>
              <ul className="list-disc list-inside space-y-1 text-rose-200/90 pl-1">
                {validationErrors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}

          {uploadError && (
            <div className="p-3 rounded-xl bg-rose-950/60 border border-rose-800 text-xs text-rose-300 flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{uploadError}</span>
            </div>
          )}

          {/* Preview Table */}
          {previewRows.length > 0 && validationErrors.length === 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Schema Preview (First {previewRows.length} Rows)</span>
                </span>
                <span className="text-[11px] text-slate-400">{headers.length} columns detected</span>
              </div>

              <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-48 bg-slate-950/60 text-xs">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                      {headers.slice(0, 6).map(h => (
                        <th key={h} className="p-2 whitespace-nowrap">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-850 text-slate-300 font-mono text-[11px]">
                    {previewRows.map((r, i) => (
                      <tr key={i} className="hover:bg-slate-900/50">
                        {headers.slice(0, 6).map(h => (
                          <td key={h} className="p-2 whitespace-nowrap max-w-[140px] truncate">
                            {r[h] || '-'}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-800 flex items-center justify-end space-x-3 bg-slate-900/60">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            Cancel
          </button>
          <button
            onClick={handleImport}
            disabled={!fileContent || validationErrors.length > 0 || isUploading}
            className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-xs shadow-md shadow-cyan-900/30 transition"
          >
            {isUploading ? (
              <span>Validating &amp; Ingesting...</span>
            ) : (
              <>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Validate &amp; Ingest Events</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
