import fs from 'fs';
import path from 'path';
import {
  SecurityEvent,
  Detection,
  Incident,
  DetectionConfig,
  IncidentStatus,
  IncidentNote,
  SystemStatus,
} from '../src/types';
import { DEFAULT_CONFIG, runDetectionEngine } from './detectionEngine';
import { AnomalyMLModel } from './mlEngine';

export class SecurityDataStore {
  private events: SecurityEvent[] = [];
  private detections: Detection[] = [];
  private incidents: Incident[] = [];
  private config: DetectionConfig = { ...DEFAULT_CONFIG };
  private mlEngine: AnomalyMLModel = new AnomalyMLModel();

  constructor() {
    this.init();
  }

  private init() {
    // Attempt to load sample data on startup
    this.loadSampleEvents();
  }

  public getMLEngine(): AnomalyMLModel {
    return this.mlEngine;
  }

  public loadSampleEvents(): { count: number; detectionsCount: number } {
    try {
      const csvPath = path.resolve(process.cwd(), 'data', 'sample_events.csv');
      if (fs.existsSync(csvPath)) {
        const content = fs.readFileSync(csvPath, 'utf8');
        const parsed = this.parseCSV(content);
        this.events = parsed;
        this.runDetections();

        // Train ML model on sample data
        if (this.events.length > 0) {
          try {
            this.mlEngine.train(this.events);
          } catch (e) {
            console.warn('Initial ML training notice:', e);
          }
        }

        // Initialize sample incident if detections exist
        if (this.detections.length > 0 && this.incidents.length === 0) {
          const det = this.detections[0];
          this.incidents.push({
            incident_id: 'INC-2026-001',
            title: `Investigation: ${det.rule_name}`,
            summary: `Automated incident created from detection ${det.detection_id}. Severity ${det.severity} on target ${det.username || 'System'}.`,
            related_detection_ids: [det.detection_id],
            related_event_ids: det.related_event_ids,
            severity: det.severity,
            status: 'INVESTIGATING',
            created_at: new Date(Date.now() - 3600000).toISOString(),
            updated_at: new Date().toISOString(),
            assigned_analyst: 'SOC Lead Analyst',
            notes: [
              {
                note_id: 'NOTE-1',
                timestamp: new Date(Date.now() - 3000000).toISOString(),
                author: 'SOC Lead Analyst',
                content: 'Triage initiated: correlated failed SSH logins against perimeter firewall logs.',
              },
            ],
            recommended_next_steps: [
              'Verify source IP ASN and reverse DNS.',
              'Check for successful logins from the same subnet.',
              'Implement temporary IP block rule at perimeter if unauthorized.',
            ],
          });
        }

        return { count: this.events.length, detectionsCount: this.detections.length };
      }
    } catch (err) {
      console.error('Failed to load initial sample events:', err);
    }
    return { count: 0, detectionsCount: 0 };
  }

  public parseCSV(csvContent: string): SecurityEvent[] {
    const lines = csvContent.trim().split(/\r?\n/);
    if (lines.length < 2) return [];

    const headers = lines[0].split(',').map(h => h.trim());
    const events: SecurityEvent[] = [];

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      // Simple CSV split taking care of standard comma-separated fields
      const cols = line.split(',');
      if (cols.length < headers.length) continue;

      const obj: Record<string, string> = {};
      headers.forEach((h, idx) => {
        obj[h] = cols[idx] ? cols[idx].trim() : '';
      });

      const event: SecurityEvent = {
        event_id: obj.event_id || `EVT-${Date.now()}-${i}`,
        timestamp: obj.timestamp || new Date().toISOString(),
        source_ip: obj.source_ip || '0.0.0.0',
        username: obj.username || 'anonymous',
        event_type: obj.event_type || 'UNKNOWN',
        action: obj.action || 'unknown_action',
        status: (obj.status as 'SUCCESS' | 'FAILURE' | 'UNKNOWN') || 'UNKNOWN',
        destination_ip: obj.destination_ip || undefined,
        destination_port: obj.destination_port ? parseInt(obj.destination_port, 10) : undefined,
        failed_attempt_count: obj.failed_attempt_count ? parseInt(obj.failed_attempt_count, 10) : 0,
        bytes_transferred: obj.bytes_transferred ? parseInt(obj.bytes_transferred, 10) : 0,
        message: obj.message || undefined,
        is_suspicious: obj.is_suspicious ? parseInt(obj.is_suspicious, 10) : undefined,
        attack_type: obj.attack_type || undefined,
      };

      events.push(event);
    }

    return events;
  }

  public getEvents(): SecurityEvent[] {
    return this.events;
  }

  public addEvents(newEvents: SecurityEvent[]): { added: number; duplicates: number } {
    const existingIds = new Set(this.events.map(e => e.event_id));
    let added = 0;
    let duplicates = 0;

    for (const evt of newEvents) {
      if (existingIds.has(evt.event_id)) {
        duplicates++;
      } else {
        this.events.push(evt);
        existingIds.add(evt.event_id);
        added++;
      }
    }

    if (added > 0) {
      this.runDetections();
    }

    return { added, duplicates };
  }

  public clearEvents(): void {
    this.events = [];
    this.detections = [];
    this.incidents = [];
  }

  public runDetections(): Detection[] {
    this.detections = runDetectionEngine(this.events, this.config);
    return this.detections;
  }

  public getDetections(): Detection[] {
    return this.detections;
  }

  public getDetectionById(id: string): Detection | undefined {
    return this.detections.find(d => d.detection_id === id);
  }

  public getIncidents(): Incident[] {
    return this.incidents;
  }

  public getIncidentById(id: string): Incident | undefined {
    return this.incidents.find(i => i.incident_id === id);
  }

  public createIncident(
    title: string,
    summary: string,
    relatedDetectionId?: string,
    severity: Incident['severity'] = 'MEDIUM',
    analyst = 'Security Analyst'
  ): Incident {
    const detection = relatedDetectionId ? this.getDetectionById(relatedDetectionId) : undefined;
    const incidentId = `INC-${new Date().getFullYear()}-${String(this.incidents.length + 1).padStart(3, '0')}`;

    const incident: Incident = {
      incident_id: incidentId,
      title: title || (detection ? `Investigation: ${detection.rule_name}` : 'Security Incident'),
      summary: summary || (detection ? detection.reason : 'Created manual security incident.'),
      related_detection_ids: detection ? [detection.detection_id] : [],
      related_event_ids: detection ? detection.related_event_ids : [],
      severity: detection ? detection.severity : severity,
      status: 'OPEN',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      assigned_analyst: analyst,
      notes: [
        {
          note_id: `NOTE-${Date.now()}`,
          timestamp: new Date().toISOString(),
          author: analyst,
          content: 'Incident docket opened. Queued for initial review.',
        },
      ],
      recommended_next_steps: detection
        ? [detection.recommended_action, 'Review authentication and perimeter logs.']
        : ['Verify affected assets and isolate compromised credentials.'],
    };

    this.incidents.unshift(incident);
    return incident;
  }

  public updateIncident(
    id: string,
    updates: {
      status?: IncidentStatus;
      severity?: Incident['severity'];
      newNote?: string;
      analyst?: string;
    }
  ): Incident {
    const inc = this.incidents.find(i => i.incident_id === id);
    if (!inc) {
      throw new Error(`Incident ${id} not found`);
    }

    if (updates.status) inc.status = updates.status;
    if (updates.severity) inc.severity = updates.severity;
    if (updates.analyst) inc.assigned_analyst = updates.analyst;
    inc.updated_at = new Date().toISOString();

    if (updates.newNote && updates.newNote.trim().length > 0) {
      const note: IncidentNote = {
        note_id: `NOTE-${Date.now()}`,
        timestamp: new Date().toISOString(),
        author: updates.analyst || 'Investigating Analyst',
        content: updates.newNote.trim(),
      };
      inc.notes.push(note);
    }

    return inc;
  }

  public getConfig(): DetectionConfig {
    return this.config;
  }

  public updateConfig(newConfig: Partial<DetectionConfig>): DetectionConfig {
    this.config = {
      ...this.config,
      ...newConfig,
      enabled_rules: {
        ...this.config.enabled_rules,
        ...(newConfig.enabled_rules || {}),
      },
      risk_thresholds: {
        ...this.config.risk_thresholds,
        ...(newConfig.risk_thresholds || {}),
      },
    };
    // Re-run detection engine with updated configuration
    this.runDetections();
    return this.config;
  }

  public resetConfig(): DetectionConfig {
    this.config = { ...DEFAULT_CONFIG };
    this.runDetections();
    return this.config;
  }

  public getSystemStatus(): SystemStatus {
    const hasKey = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY');
    return {
      status: 'healthy',
      gemini_available: hasKey,
      python_runtime_available: true,
      events_count: this.events.length,
      detections_count: this.detections.length,
      incidents_count: this.incidents.length,
      ml_model_trained: this.mlEngine.isTrained(),
      environment_type: 'Full-Stack Express + Node.js (with Python 3.10 Reference Suite)',
    };
  }

  public exportReportJSON() {
    return {
      generated_at: new Date().toISOString(),
      system_name: 'AI Security Incident Analysis System',
      scope: {
        total_events: this.events.length,
        total_detections: this.detections.length,
        total_incidents: this.incidents.length,
      },
      detections_summary: {
        critical: this.detections.filter(d => d.severity === 'CRITICAL').length,
        high: this.detections.filter(d => d.severity === 'HIGH').length,
        medium: this.detections.filter(d => d.severity === 'MEDIUM').length,
        low: this.detections.filter(d => d.severity === 'LOW').length,
      },
      detections: this.detections,
      incidents: this.incidents,
      ml_evaluation: this.mlEngine.getEvaluation(),
      active_rules: Object.entries(this.config.enabled_rules)
        .filter(([, v]) => v)
        .map(([k]) => k),
    };
  }
}

export const dataStore = new SecurityDataStore();
