"""
AI Security - Python Reference Engine
Designed for Computer Science undergraduate cybersecurity coursework, research, and technical interviews.
Uses Python 3 standard library (sqlite3, csv, json, datetime, math) without external heavy dependencies.
"""

import sqlite3
import json
import math
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

class SecurityDatabase:
    """Manages SQLite storage for security events, detections, and incident records."""
    
    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    username TEXT,
                    event_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    failed_attempt_count INTEGER DEFAULT 0,
                    bytes_transferred INTEGER DEFAULT 0,
                    message TEXT,
                    is_suspicious INTEGER DEFAULT 0,
                    attack_type TEXT
                );
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    detection_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    detection_timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    detection_method TEXT NOT NULL,
                    related_event_ids_json TEXT NOT NULL
                );
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    analyst TEXT,
                    notes_json TEXT NOT NULL
                );
            """)

    def insert_event(self, event: Dict[str, Any]) -> bool:
        """Safely inserts a security event using parameterized queries."""
        try:
            with self.conn:
                self.conn.execute("""
                    INSERT INTO security_events (
                        event_id, timestamp, source_ip, username, event_type,
                        action, status, destination_ip, destination_port,
                        failed_attempt_count, bytes_transferred, message,
                        is_suspicious, attack_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.get("event_id"),
                    event.get("timestamp"),
                    event.get("source_ip"),
                    event.get("username"),
                    event.get("event_type"),
                    event.get("action"),
                    event.get("status"),
                    event.get("destination_ip"),
                    event.get("destination_port"),
                    event.get("failed_attempt_count", 0),
                    event.get("bytes_transferred", 0),
                    event.get("message"),
                    event.get("is_suspicious", 0),
                    event.get("attack_type")
                ))
            return True
        except sqlite3.IntegrityError:
            return False  # Duplicate event_id handled safely

    def get_events(self) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM security_events ORDER BY timestamp ASC")
        return [dict(row) for row in cursor.fetchall()]

    def insert_detection(self, det: Dict[str, Any]):
        with self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO detections (
                    detection_id, rule_id, rule_name, detection_timestamp,
                    severity, risk_score, reason, evidence_json,
                    recommended_action, detection_method, related_event_ids_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                det["detection_id"],
                det["rule_id"],
                det["rule_name"],
                det["detection_timestamp"],
                det["severity"],
                det["risk_score"],
                det["reason"],
                json.dumps(det.get("evidence", [])),
                det["recommended_action"],
                det["detection_method"],
                json.dumps(det.get("related_event_ids", []))
            ))

    def insert_incident(self, incident: Dict[str, Any]):
        with self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO incidents (
                    incident_id, title, summary, severity, status,
                    created_at, updated_at, analyst, notes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident["incident_id"],
                incident["title"],
                incident["summary"],
                incident["severity"],
                incident["status"],
                incident["created_at"],
                incident["updated_at"],
                incident.get("analyst", "Analyst"),
                json.dumps(incident.get("notes", []))
            ))

    def update_incident_status(self, incident_id: str, new_status: str) -> bool:
        with self.conn:
            cursor = self.conn.execute(
                "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
                (new_status, datetime.utcnow().isoformat() + "Z", incident_id)
            )
            return cursor.rowcount > 0


class PythonDetectionEngine:
    """Core rule-based detection engine and transparent risk scoring."""

    def __init__(self, failed_threshold: int = 3, window_minutes: int = 10, bytes_threshold_mb: int = 50):
        self.failed_threshold = failed_threshold
        self.window_minutes = window_minutes
        self.bytes_threshold = bytes_threshold_mb * 1024 * 1024

    def calculate_severity(self, score: int) -> str:
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 30: return "MEDIUM"
        return "LOW"

    def analyze(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        det_counter = 1

        # Sort chronologically
        events_sorted = sorted(events, key=lambda x: x.get("timestamp", ""))

        # Group by user and source IP
        user_events = {}
        for e in events_sorted:
            u = e.get("username")
            if u:
                user_events.setdefault(u, []).append(e)

        # Rule A: Repeated Failed Login Attempts
        for user, u_list in user_events.items():
            failures = [
                e for e in u_list 
                if e.get("status") == "FAILURE" and ("AUTH" in e.get("event_type", "") or "login" in e.get("action", ""))
            ]
            
            for i in range(len(failures)):
                try:
                    t_anchor = datetime.fromisoformat(failures[i]["timestamp"].replace("Z", "+00:00"))
                except Exception:
                    continue
                
                cluster = []
                for f in failures[i:]:
                    try:
                        t_curr = datetime.fromisoformat(f["timestamp"].replace("Z", "+00:00"))
                        if (t_curr - t_anchor).total_seconds() <= self.window_minutes * 60:
                            cluster.append(f)
                    except Exception:
                        continue
                
                if len(cluster) >= self.failed_threshold:
                    risk_score = min(40 + len(cluster) * 5 + (15 if user in ["root", "admin", "db_admin"] else 0), 100)
                    detections.append({
                        "detection_id": f"DET-PY-{det_counter:04d}",
                        "rule_id": "RULE_REPEATED_FAILED_LOGINS",
                        "rule_name": "Repeated Failed Login Attempts (Brute Force Indicator)",
                        "detection_timestamp": datetime.utcnow().isoformat() + "Z",
                        "severity": self.calculate_severity(risk_score),
                        "risk_score": risk_score,
                        "reason": f"Detected {len(cluster)} failed authentications for user '{user}' within {self.window_minutes} minutes.",
                        "evidence": [f"User: {user}", f"Failures: {len(cluster)}", f"Source: {cluster[0].get('source_ip')}"],
                        "recommended_action": f"Lock account '{user}' temporarily and audit source IP.",
                        "detection_method": "rule_based",
                        "related_event_ids": [c["event_id"] for c in cluster]
                    })
                    det_counter += 1
                    break

        # Rule C: Large Data Exfiltration
        for e in events_sorted:
            b = e.get("bytes_transferred", 0) or 0
            if b >= self.bytes_threshold:
                risk_score = 75
                detections.append({
                    "detection_id": f"DET-PY-{det_counter:04d}",
                    "rule_id": "RULE_UNUSUAL_NETWORK_ACTIVITY",
                    "rule_name": "Unusual Network Activity (Potential Data Exfiltration)",
                    "detection_timestamp": datetime.utcnow().isoformat() + "Z",
                    "severity": self.calculate_severity(risk_score),
                    "risk_score": risk_score,
                    "reason": f"Network transfer of {b / (1024*1024):.2f} MB exceeds threshold of {self.bytes_threshold / (1024*1024)} MB.",
                    "evidence": [f"Event ID: {e.get('event_id')}", f"Bytes: {b}", f"Dest: {e.get('destination_ip')}"],
                    "recommended_action": "Verify if authorized backup occurred, else isolate host.",
                    "detection_method": "rule_based",
                    "related_event_ids": [e.get("event_id")]
                })
                det_counter += 1

        return detections


class PythonMLAnomalyScorer:
    """Supervised and unsupervised anomaly evaluation for student demonstrations."""

    @staticmethod
    def evaluate(labeled_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        tp, fp, tn, fn = 0, 0, 0, 0
        for e in labeled_events:
            actual = int(e.get("is_suspicious", 0) or 0)
            # Simple heuristic baseline: failed attempts >= 3 or bytes > 10MB or admin/tmp keywords
            msg = str(e.get("message", "")).lower()
            bytes_t = e.get("bytes_transferred", 0) or 0
            predicted = 1 if (e.get("failed_attempt_count", 0) >= 3 or bytes_t > 10*1024*1024 or "/tmp" in msg or "shadow" in msg) else 0

            if actual == 1 and predicted == 1: tp += 1
            elif actual == 0 and predicted == 1: fp += 1
            elif actual == 0 and predicted == 0: tn += 1
            elif actual == 1 and predicted == 0: fn += 1

        total = tp + fp + tn + fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / total if total > 0 else 0.0

        return {
            "total_samples": total,
            "accuracy": round(accuracy, 3),
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1_score": round(f1, 3),
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
        }
