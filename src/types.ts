export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
export type DetectionMethod = 'rule_based' | 'ml_based' | 'hybrid';

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  source_ip: string;
  username: string;
  event_type: string;
  action: string;
  status: 'SUCCESS' | 'FAILURE' | 'UNKNOWN' | string;
  destination_ip?: string;
  destination_port?: number;
  failed_attempt_count?: number;
  bytes_transferred?: number;
  message?: string;
  is_suspicious?: number; // 0 or 1 for ML ground-truth evaluation
  attack_type?: string;
}

export interface ScoreFactor {
  factor: string;
  points: number;
  description: string;
}

export interface Detection {
  detection_id: string;
  related_event_ids: string[];
  rule_id: string;
  rule_name: string;
  detection_timestamp: string;
  severity: SeverityLevel;
  risk_score: number; // 0 - 100
  score_factors: ScoreFactor[];
  reason: string;
  evidence: string[];
  recommended_action: string;
  detection_method: DetectionMethod;
  alternative_explanations: string[];
  source_ip?: string;
  username?: string;
}

export interface IncidentNote {
  note_id: string;
  timestamp: string;
  author: string;
  content: string;
}

export interface Incident {
  incident_id: string;
  title: string;
  summary: string;
  related_detection_ids: string[];
  related_event_ids: string[];
  severity: SeverityLevel;
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
  notes: IncidentNote[];
  recommended_next_steps: string[];
  assigned_analyst?: string;
}

export interface DetectionConfig {
  failed_login_threshold: number; // e.g. 3
  failed_login_window_minutes: number; // e.g. 10
  network_bytes_threshold_mb: number; // e.g. 50
  suspicious_ports: number[]; // e.g. [4444, 1337, 31337, 9999]
  enabled_rules: {
    repeated_failed_login: boolean;
    suspicious_login_pattern: boolean;
    unusual_network_activity: boolean;
    suspicious_admin_activity: boolean;
    dangerous_file_activity: boolean;
    unknown_unclassified_event: boolean;
  };
  risk_thresholds: {
    low: [number, number]; // [0, 29]
    medium: [number, number]; // [30, 59]
    high: [number, number]; // [60, 79]
    critical: [number, number]; // [80, 100]
  };
}

export interface ConfusionMatrix {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface MLEvaluation {
  model_name: string;
  model_version: string;
  is_trained: boolean;
  train_samples: number;
  test_samples: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  confusion_matrix: ConfusionMatrix;
  features_used: string[];
  training_timestamp?: string;
  class_balance: {
    benign: number;
    suspicious: number;
  };
  anomaly_score_threshold: number;
  notes: string;
}

export interface AIExplanationRequest {
  detection_id: string;
  user_question?: string;
}

export interface AIExplanationResponse {
  detection_id: string;
  summary: string;
  detailed_analysis: string;
  evidence_breakdown: string[];
  legitimate_explanations: string[];
  investigation_steps: string[];
  remediation_steps: string[];
  beginner_summary: string;
  is_ai_generated: boolean;
  model_used: string;
  generated_at: string;
  verification_notice: string;
}

export interface SystemStatus {
  status: 'healthy' | 'degraded';
  gemini_available: boolean;
  python_runtime_available: boolean;
  events_count: number;
  detections_count: number;
  incidents_count: number;
  ml_model_trained: boolean;
  environment_type: string;
}
