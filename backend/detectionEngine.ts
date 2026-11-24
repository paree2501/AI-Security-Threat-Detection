import { SecurityEvent, Detection, DetectionConfig, SeverityLevel, ScoreFactor } from '../src/types';

export const DEFAULT_CONFIG: DetectionConfig = {
  failed_login_threshold: 3,
  failed_login_window_minutes: 10,
  network_bytes_threshold_mb: 50,
  suspicious_ports: [4444, 1337, 31337, 9999, 6667],
  enabled_rules: {
    repeated_failed_login: true,
    suspicious_login_pattern: true,
    unusual_network_activity: true,
    suspicious_admin_activity: true,
    dangerous_file_activity: true,
    unknown_unclassified_event: true,
  },
  risk_thresholds: {
    low: [0, 29],
    medium: [30, 59],
    high: [60, 79],
    critical: [80, 100],
  },
};

export function calculateSeverity(score: number, thresholds = DEFAULT_CONFIG.risk_thresholds): SeverityLevel {
  if (score >= thresholds.critical[0]) return 'CRITICAL';
  if (score >= thresholds.high[0]) return 'HIGH';
  if (score >= thresholds.medium[0]) return 'MEDIUM';
  return 'LOW';
}

function isOffHours(timestampStr: string): boolean {
  try {
    const d = new Date(timestampStr);
    const hour = d.getUTCHours();
    // Off hours: before 07:00 UTC or after 19:00 UTC
    return hour < 7 || hour >= 19;
  } catch {
    return false;
  }
}

function isPrivilegedUser(username: string): boolean {
  const privileged = ['root', 'admin', 'administrator', 'db_admin', 'wheel', 'system'];
  return privileged.includes(username.toLowerCase());
}

export function runDetectionEngine(
  events: SecurityEvent[],
  config: DetectionConfig = DEFAULT_CONFIG
): Detection[] {
  const detections: Detection[] = [];
  let detectionCounter = 1;

  // Sort events chronologically
  const sortedEvents = [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  // Group events by identity (user and IP) for temporal correlation
  const eventsByUser: Record<string, SecurityEvent[]> = {};
  const eventsByIp: Record<string, SecurityEvent[]> = {};

  sortedEvents.forEach(evt => {
    if (evt.username) {
      eventsByUser[evt.username] = eventsByUser[evt.username] || [];
      eventsByUser[evt.username].push(evt);
    }
    if (evt.source_ip) {
      eventsByIp[evt.source_ip] = eventsByIp[evt.source_ip] || [];
      eventsByIp[evt.source_ip].push(evt);
    }
  });

  const windowMs = config.failed_login_window_minutes * 60 * 1000;

  // RULE A: Repeated Failed Login Attempts
  if (config.enabled_rules.repeated_failed_login) {
    const processedPairs = new Set<string>();

    // Analyze per source_ip and username
    for (const [user, userEvents] of Object.entries(eventsByUser)) {
      const authFailures = userEvents.filter(
        e => e.status === 'FAILURE' && (e.event_type.includes('AUTH') || e.action.includes('login'))
      );

      for (let i = 0; i < authFailures.length; i++) {
        const anchor = authFailures[i];
        const anchorTime = new Date(anchor.timestamp).getTime();
        const cluster = authFailures.filter(e => {
          const t = new Date(e.timestamp).getTime();
          return t >= anchorTime && t <= anchorTime + windowMs;
        });

        if (cluster.length >= config.failed_login_threshold) {
          const key = `FAILED_LOGIN_${user}_${cluster[0].event_id}_${cluster[cluster.length - 1].event_id}`;
          if (!processedPairs.has(key)) {
            processedPairs.add(key);

            const scoreFactors: ScoreFactor[] = [
              { factor: 'Base Rule Weight', points: 40, description: 'Repeated authentication failures detected within time window' },
              { factor: 'Failure Frequency', points: Math.min(cluster.length * 5, 25), description: `${cluster.length} failed attempts observed within ${config.failed_login_window_minutes} minutes` },
            ];

            if (isPrivilegedUser(user)) {
              scoreFactors.push({ factor: 'Privileged Target', points: 15, description: `Target username '${user}' possesses administrative privileges` });
            }
            if (isOffHours(anchor.timestamp)) {
              scoreFactors.push({ factor: 'Off-Hours Activity', points: 5, description: 'Attempts initiated outside standard business hours' });
            }

            const rawScore = scoreFactors.reduce((acc, f) => acc + f.points, 0);
            const risk_score = Math.min(Math.max(rawScore, 0), 100);
            const severity = calculateSeverity(risk_score, config.risk_thresholds);

            detections.push({
              detection_id: `DET-${String(detectionCounter++).padStart(4, '0')}`,
              related_event_ids: cluster.map(e => e.event_id),
              rule_id: 'RULE_REPEATED_FAILED_LOGINS',
              rule_name: 'Repeated Failed Login Attempts (Potential Brute-Force)',
              detection_timestamp: new Date().toISOString(),
              severity,
              risk_score,
              score_factors: scoreFactors,
              reason: `Observed ${cluster.length} failed login attempts for account '${user}' within a ${config.failed_login_window_minutes}-minute timeframe.`,
              evidence: [
                `Target Account: ${user}`,
                `Total Failures in Window: ${cluster.length}`,
                `Source IP: ${anchor.source_ip || 'Unknown'}`,
                `Time Span: ${cluster[0].timestamp} to ${cluster[cluster.length - 1].timestamp}`,
                `Destination Port: ${anchor.destination_port || 'N/A'}`
              ],
              recommended_action: `Temporarily lock or enforce MFA for '${user}'. Inspect source IP (${anchor.source_ip}) against threat intelligence or rate-limit SSH/auth endpoints.`,
              detection_method: 'rule_based',
              alternative_explanations: [
                'User recently changed password and forgot to update saved credentials in a script, SSH key, or mobile client.',
                'Expired active directory token causing automated reconnect loops.',
                'IT administrator misconfigured an automated backup or sync service account.'
              ],
              source_ip: anchor.source_ip,
              username: user
            });

            // Advance outer loop index past this cluster to avoid duplicates
            i += cluster.length - 1;
          }
        }
      }
    }
  }

  // RULE B: Suspicious Login Pattern (Multiple Failures followed by Success)
  if (config.enabled_rules.suspicious_login_pattern) {
    for (const [user, userEvents] of Object.entries(eventsByUser)) {
      for (let i = 0; i < userEvents.length; i++) {
        const evt = userEvents[i];
        if (evt.status === 'SUCCESS' && (evt.event_type.includes('AUTH') || evt.action.includes('login'))) {
          const successTime = new Date(evt.timestamp).getTime();
          // Look back within window for failures
          const priorFailures = userEvents.filter(e => {
            const t = new Date(e.timestamp).getTime();
            return (
              e.status === 'FAILURE' &&
              (e.event_type.includes('AUTH') || e.action.includes('login')) &&
              t < successTime &&
              t >= successTime - windowMs
            );
          });

          if (priorFailures.length >= 2) {
            const scoreFactors: ScoreFactor[] = [
              { factor: 'Base Rule Weight', points: 55, description: 'Sequential failures followed immediately by successful authentication' },
              { factor: 'Preceding Failures', points: Math.min(priorFailures.length * 6, 20), description: `${priorFailures.length} unsuccessful attempts preceding authentication` },
            ];

            if (isPrivilegedUser(user)) {
              scoreFactors.push({ factor: 'Privileged Target', points: 15, description: `Account '${user}' has high privileges` });
            }

            const rawScore = scoreFactors.reduce((acc, f) => acc + f.points, 0);
            const risk_score = Math.min(Math.max(rawScore, 0), 100);
            const severity = calculateSeverity(risk_score, config.risk_thresholds);

            detections.push({
              detection_id: `DET-${String(detectionCounter++).padStart(4, '0')}`,
              related_event_ids: [...priorFailures.map(e => e.event_id), evt.event_id],
              rule_id: 'RULE_SUSPICIOUS_LOGIN_PATTERN',
              rule_name: 'Suspicious Login Sequence (Failures Preceding Success)',
              detection_timestamp: new Date().toISOString(),
              severity,
              risk_score,
              score_factors: scoreFactors,
              reason: `Account '${user}' experienced ${priorFailures.length} failed login attempts followed by a successful login at ${evt.timestamp}. This pattern is characteristic of successful credential guessing or password spray attacks.`,
              evidence: [
                `User: ${user}`,
                `Preceding Failures: ${priorFailures.length}`,
                `Successful Event: ${evt.event_id} at ${evt.timestamp}`,
                `Source IP: ${evt.source_ip || 'N/A'}`,
                `Destination: ${evt.destination_ip || 'Internal'} : ${evt.destination_port || 'N/A'}`
              ],
              recommended_action: 'Immediately contact the legitimate account owner via an out-of-band channel (phone/Slack) to confirm whether they executed this login. Review subsequent session commands.',
              detection_method: 'rule_based',
              alternative_explanations: [
                'Legitimate user mistyped their password a couple of times before entering the correct one.',
                'Caps Lock was enabled during initial attempts.',
                'User reset password on another device and attempted old password first.'
              ],
              source_ip: evt.source_ip,
              username: user
            });
          }
        }
      }
    }
  }

  // RULE C: Unusual Network Activity (Large Data Volume or Suspicious Ports)
  if (config.enabled_rules.unusual_network_activity) {
    const bytesThreshold = config.network_bytes_threshold_mb * 1024 * 1024;

    for (const evt of sortedEvents) {
      const bytes = evt.bytes_transferred || 0;
      const port = evt.destination_port || 0;
      const isLargeTransfer = bytes >= bytesThreshold;
      const isSuspiciousPort = config.suspicious_ports.includes(port);

      if (isLargeTransfer || isSuspiciousPort) {
        const scoreFactors: ScoreFactor[] = [];
        if (isLargeTransfer) {
          scoreFactors.push({
            factor: 'Large Volume Outbound',
            points: 50,
            description: `Transferred ${(bytes / (1024 * 1024)).toFixed(2)} MB (exceeds ${config.network_bytes_threshold_mb} MB threshold)`
          });
        }
        if (isSuspiciousPort) {
          scoreFactors.push({
            factor: 'Anomalous Port',
            points: 25,
            description: `Connected to unusual port ${port} commonly associated with shells or non-standard protocols`
          });
        }
        if (isOffHours(evt.timestamp)) {
          scoreFactors.push({ factor: 'Off-Hours Transfer', points: 10, description: 'Network transmission occurred outside business hours' });
        }

        const rawScore = scoreFactors.reduce((acc, f) => acc + f.points, 0);
        const risk_score = Math.min(Math.max(rawScore, 0), 100);
        const severity = calculateSeverity(risk_score, config.risk_thresholds);

        detections.push({
          detection_id: `DET-${String(detectionCounter++).padStart(4, '0')}`,
          related_event_ids: [evt.event_id],
          rule_id: 'RULE_UNUSUAL_NETWORK_ACTIVITY',
          rule_name: 'Unusual Network Activity (Potential Data Exfiltration / C2)',
          detection_timestamp: new Date().toISOString(),
          severity,
          risk_score,
          score_factors: scoreFactors,
          reason: `High network traffic or connection to non-standard port detected: ${(bytes / (1024 * 1024)).toFixed(2)} MB to ${evt.destination_ip || 'destination'}:${port}.`,
          evidence: [
            `Event ID: ${evt.event_id}`,
            `Source: ${evt.source_ip || 'N/A'} (User: ${evt.username || 'System'})`,
            `Destination: ${evt.destination_ip || 'N/A'}:${port}`,
            `Bytes Transferred: ${bytes.toLocaleString()} bytes (${(bytes / (1024 * 1024)).toFixed(2)} MB)`
          ],
          recommended_action: 'Isolate host if destination IP is unrecognized. Capture network flow logs (PCAP) and verify if an authorized database backup or software sync was scheduled.',
          detection_method: 'rule_based',
          alternative_explanations: [
            'Legitimate scheduled cloud database backup or VM snapshot upload.',
            'Operating system updates or heavy developer Docker image pull/push.',
            'Approved large client asset transfer by employee.'
          ],
          source_ip: evt.source_ip,
          username: evt.username
        });
      }
    }
  }

  // RULE D: Suspicious Administrative Activity
  if (config.enabled_rules.suspicious_admin_activity) {
    const adminIndicators = ['privilege_escalation', 'usermod', 'sudo', 'shadow', 'passwd', 'sudoers', 'chmod 777'];

    for (const evt of sortedEvents) {
      const msg = (evt.message || '').toLowerCase();
      const action = (evt.action || '').toLowerCase();
      const isTypeAdmin = evt.event_type.includes('ADMIN') || action.includes('admin');
      const matchesAdminIndicator = adminIndicators.some(ind => msg.includes(ind) || action.includes(ind));

      if (isTypeAdmin || matchesAdminIndicator) {
        const scoreFactors: ScoreFactor[] = [
          { factor: 'Base Admin Escalation', points: 65, description: 'Administrative privilege alteration or security file access' }
        ];

        if (msg.includes('/etc/shadow') || msg.includes('sudoers')) {
          scoreFactors.push({ factor: 'Critical Security File Alteration', points: 25, description: 'Target involves core authentication credential file (/etc/shadow or sudoers)' });
        }
        if (evt.username && !isPrivilegedUser(evt.username)) {
          scoreFactors.push({ factor: 'Unprivileged User Origin', points: 10, description: `Command initiated by non-admin account '${evt.username}'` });
        }

        const rawScore = scoreFactors.reduce((acc, f) => acc + f.points, 0);
        const risk_score = Math.min(Math.max(rawScore, 0), 100);
        const severity = calculateSeverity(risk_score, config.risk_thresholds);

        detections.push({
          detection_id: `DET-${String(detectionCounter++).padStart(4, '0')}`,
          related_event_ids: [evt.event_id],
          rule_id: 'RULE_SUSPICIOUS_ADMIN_ACTIVITY',
          rule_name: 'Suspicious Administrative Activity (Privilege Alteration)',
          detection_timestamp: new Date().toISOString(),
          severity,
          risk_score,
          score_factors: scoreFactors,
          reason: `Potentially unauthorized administrative operation detected: '${evt.action}' on host ${evt.source_ip}. Message: "${evt.message || 'Privilege change'}"`,
          evidence: [
            `Event ID: ${evt.event_id}`,
            `User: ${evt.username}`,
            `Action: ${evt.action}`,
            `Message: ${evt.message || 'N/A'}`,
            `Source Host: ${evt.source_ip}`
          ],
          recommended_action: 'Audit active sudoers file and group membership. Check change management tickets for authorized maintenance window. Revoke unexpected permissions.',
          detection_method: 'rule_based',
          alternative_explanations: [
            'System administrator performing scheduled server provisioning or user onboarding.',
            'Automated configuration management tool (Ansible/Puppet) applying policy updates.',
            'Software installer configuring a background system daemon user.'
          ],
          source_ip: evt.source_ip,
          username: evt.username
        });
      }
    }
  }

  // RULE E: Potentially Dangerous File Activity
  if (config.enabled_rules.dangerous_file_activity) {
    const dangerousPatterns = ['/tmp/', 'mimikatz', 'rev_shell', 'backdoor', '.sh', 'powershell -enc', 'nc -e', 'netcat'];

    for (const evt of sortedEvents) {
      const msg = (evt.message || '').toLowerCase();
      const action = (evt.action || '').toLowerCase();
      const isFileOrProc = evt.event_type.includes('FILE') || evt.event_type.includes('PROCESS');
      const isDangerous = dangerousPatterns.some(pat => msg.includes(pat) || action.includes(pat));

      if (isFileOrProc && isDangerous) {
        const scoreFactors: ScoreFactor[] = [
          { factor: 'Suspicious Execution Context', points: 60, description: 'Execution of binary or script from volatile/temporary directory or known attack signature' }
        ];

        if (msg.includes('backdoor') || msg.includes('shell') || msg.includes('mimikatz')) {
          scoreFactors.push({ factor: 'High-Risk Signature', points: 25, description: 'Explicit signature associated with offensive tooling or reverse shells' });
        }

        const rawScore = scoreFactors.reduce((acc, f) => acc + f.points, 0);
        const risk_score = Math.min(Math.max(rawScore, 0), 100);
        const severity = calculateSeverity(risk_score, config.risk_thresholds);

        detections.push({
          detection_id: `DET-${String(detectionCounter++).padStart(4, '0')}`,
          related_event_ids: [evt.event_id],
          rule_id: 'RULE_DANGEROUS_FILE_ACTIVITY',
          rule_name: 'Dangerous File or Process Activity (Potential Malware/Execution)',
          detection_timestamp: new Date().toISOString(),
          severity,
          risk_score,
          score_factors: scoreFactors,
          reason: `Detected suspicious file creation or execution: '${evt.action}'. Details: ${evt.message || 'N/A'}.`,
          evidence: [
            `Event ID: ${evt.event_id}`,
            `Process/File Action: ${evt.action}`,
            `Message: ${evt.message || 'N/A'}`,
            `Host: ${evt.source_ip}`,
            `User: ${evt.username}`
          ],
          recommended_action: 'Quarantine the file and terminate the associated PID. Collect memory and disk triage artifacts for forensic analysis.',
          detection_method: 'rule_based',
          alternative_explanations: [
            'Developer testing an internal automation script in /tmp during development.',
            'Third-party monitoring tool deploying a temporary collector agent.',
            'Security team authorized penetration test exercise.'
          ],
          source_ip: evt.source_ip,
          username: evt.username
        });
      }
    }
  }

  // RULE F: Unknown or Unclassified Security Events
  if (config.enabled_rules.unknown_unclassified_event) {
    const knownTypes = ['AUTH_LOGIN', 'FILE_ACCESS', 'NETWORK_CONN', 'PROCESS_EXEC', 'SYSTEM_LOG', 'DNS_QUERY'];

    for (const evt of sortedEvents) {
      const isUnknownType = !knownTypes.includes(evt.event_type);
      const isUnknownStatus = evt.status === 'UNKNOWN';

      if (isUnknownType || isUnknownStatus) {
        const scoreFactors: ScoreFactor[] = [
          { factor: 'Unrecognized Event Signature', points: 30, description: 'Event type or execution status does not match standard baseline schema' }
        ];

        if (isUnknownType && isUnknownStatus) {
          scoreFactors.push({ factor: 'Compound Anomaly', points: 15, description: 'Both event category and status code are unclassified' });
        }

        const rawScore = scoreFactors.reduce((acc, f) => acc + f.points, 0);
        const risk_score = Math.min(Math.max(rawScore, 0), 100);
        const severity = calculateSeverity(risk_score, config.risk_thresholds);

        detections.push({
          detection_id: `DET-${String(detectionCounter++).padStart(4, '0')}`,
          related_event_ids: [evt.event_id],
          rule_id: 'RULE_UNCLASSIFIED_SECURITY_EVENT',
          rule_name: 'Unclassified Security Event (Analyst Triage Required)',
          detection_timestamp: new Date().toISOString(),
          severity,
          risk_score,
          score_factors: scoreFactors,
          reason: `Event '${evt.event_id}' has unrecognized type '${evt.event_type}' or status '${evt.status}'. Manual inspection is required to baseline this behavior.`,
          evidence: [
            `Event ID: ${evt.event_id}`,
            `Event Type: ${evt.event_type}`,
            `Action: ${evt.action}`,
            `Status: ${evt.status}`,
            `Message: ${evt.message || 'N/A'}`
          ],
          recommended_action: 'Review host kernel and application logs around the event timestamp. Define a formal parsing rule if this is a newly deployed enterprise service.',
          detection_method: 'rule_based',
          alternative_explanations: [
            'Newly installed security or observability agent (e.g. eBPF, Falco, Wazuh) reporting in a new schema.',
            'Custom internal software deployment logging non-standard status codes.'
          ],
          source_ip: evt.source_ip,
          username: evt.username
        });
      }
    }
  }

  return detections;
}
