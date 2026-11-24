import {
  SecurityEvent,
  Detection,
  Incident,
  DetectionConfig,
  MLEvaluation,
  AIExplanationResponse,
  SystemStatus,
  IncidentStatus,
} from '../types';

export async function fetchSystemStatus(): Promise<SystemStatus> {
  const res = await fetch('/api/status');
  if (!res.ok) throw new Error('Failed to fetch system status');
  return res.json();
}

export async function fetchEvents(params?: {
  search?: string;
  type?: string;
  status?: string;
  limit?: number;
  offset?: number;
}): Promise<{ total: number; events: SecurityEvent[] }> {
  const query = new URLSearchParams();
  if (params?.search) query.set('search', params.search);
  if (params?.type && params.type !== 'ALL') query.set('type', params.type);
  if (params?.status && params.status !== 'ALL') query.set('status', params.status);
  if (params?.limit) query.set('limit', params.limit.toString());
  if (params?.offset) query.set('offset', params.offset.toString());

  const res = await fetch(`/api/events?${query.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch security events');
  return res.json();
}

export async function uploadEvents(payload: {
  csv_text?: string;
  events?: SecurityEvent[];
}): Promise<{ success: boolean; added: number; duplicates: number; total_events: number }> {
  const res = await fetch('/api/events/upload', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to upload events');
  return data;
}

export async function loadSampleEvents(): Promise<{ success: boolean; events_count: number; detections_count: number }> {
  const res = await fetch('/api/events/load-sample', { method: 'POST' });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to load sample dataset');
  return data;
}

export async function clearAllEvents(): Promise<void> {
  const res = await fetch('/api/events', { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to clear events');
}

export async function fetchDetections(): Promise<{ detections: Detection[]; count: number }> {
  const res = await fetch('/api/detections');
  if (!res.ok) throw new Error('Failed to fetch detections');
  return res.json();
}

export async function runDetections(): Promise<{ detections: Detection[]; count: number }> {
  const res = await fetch('/api/detections/run', { method: 'POST' });
  if (!res.ok) throw new Error('Failed to run detections');
  return res.json();
}

export async function fetchIncidents(): Promise<{ incidents: Incident[]; count: number }> {
  const res = await fetch('/api/incidents');
  if (!res.ok) throw new Error('Failed to fetch incidents');
  return res.json();
}

export async function createIncident(payload: {
  title: string;
  summary: string;
  related_detection_id?: string;
  severity?: Incident['severity'];
  analyst?: string;
}): Promise<{ success: boolean; incident: Incident }> {
  const res = await fetch('/api/incidents', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to create incident');
  return data;
}

export async function updateIncident(
  id: string,
  payload: {
    status?: IncidentStatus;
    severity?: Incident['severity'];
    newNote?: string;
    analyst?: string;
  }
): Promise<{ success: boolean; incident: Incident }> {
  const res = await fetch(`/api/incidents/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to update incident');
  return data;
}

export async function fetchMLEvaluation(): Promise<{ evaluation: MLEvaluation | null; is_trained: boolean }> {
  const res = await fetch('/api/ml/evaluation');
  if (!res.ok) throw new Error('Failed to fetch ML evaluation');
  return res.json();
}

export async function trainMLModel(): Promise<{ success: boolean; evaluation: MLEvaluation }> {
  const res = await fetch('/api/ml/train', { method: 'POST' });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to train ML model');
  return data;
}

export async function requestAIExplanation(payload: {
  detection_id: string;
  question?: string;
}): Promise<AIExplanationResponse> {
  const res = await fetch('/api/ai/explain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to request AI explanation');
  return data;
}

export async function fetchSettings(): Promise<DetectionConfig> {
  const res = await fetch('/api/settings');
  if (!res.ok) throw new Error('Failed to fetch settings');
  return res.json();
}

export async function updateSettings(cfg: Partial<DetectionConfig>): Promise<DetectionConfig> {
  const res = await fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cfg),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to update settings');
  return data.config;
}

export async function resetSettings(): Promise<DetectionConfig> {
  const res = await fetch('/api/settings/reset', { method: 'POST' });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to reset settings');
  return data.config;
}

export async function runAutomatedTests(): Promise<{
  total_tests: number;
  passed: number;
  failed: number;
  duration_ms: number;
  results: Array<{ id: number; name: string; status: string; description: string }>;
}> {
  const res = await fetch('/api/tests/run');
  if (!res.ok) throw new Error('Failed to execute test suite');
  return res.json();
}
