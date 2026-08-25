/** J.A.R.V.I.S. Security Core Types */
export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type SecurityIncidentStatus = 'open' | 'investigating' | 'resolved';
export type SecurityEventType = 'authentication' | 'network' | 'process' | 'file' | 'malware' | 'privilege' | 'exfiltration' | 'dns' | 'web' | 'system' | 'detection';
export type SecurityEventSource = 'simulation' | 'suricata' | 'zeek' | 'splunk' | 'endpoint' | 'firewall' | 'identity' | 'manual';

export interface SecurityEvent {
  id: string; timestamp: string; type: SecurityEventType; source: SecurityEventSource; sourceSystem?: string;
  title: string; description: string; severity: SecuritySeverity; sourceIP?: string; destinationIP?: string;
  sourcePort?: number; destinationPort?: number; protocol?: string; hostname?: string; username?: string;
  processName?: string; filePath?: string; mitreTechniques?: string[]; scenarioId?: string; metadata?: Record<string, unknown>;
}
export interface DetectionRule { id: string; name: string; description: string; severity: SecuritySeverity; mitreTechniques: string[]; match: (event: SecurityEvent) => boolean; }
export interface DetectionResult { id: string; ruleId: string; ruleName: string; eventId: string; timestamp: string; severity: SecuritySeverity; title: string; description: string; confidence: number; mitreTechniques: string[]; sourceIP?: string; destinationIP?: string; }
export type SecurityDetection = DetectionResult;
export interface AttackScenarioEventTemplate { offsetMs: number; event: Omit<SecurityEvent, 'id' | 'timestamp' | 'scenarioId'>; }
export interface AttackScenario { id: string; name: string; description: string; category: string; mitreTechniques: string[]; events: AttackScenarioEventTemplate[]; }
export interface ScenarioRun { id: string; scenarioId: string; startedAt: string; completedAt?: string; eventIds: string[]; }

export interface SecurityIncident {
  id: string; title: string; severity: SecuritySeverity; status: SecurityIncidentStatus;
  eventIds: string[]; detectionIds: string[]; assignee?: string; resolvedAt?: string; createdAt: string; updatedAt: string;
}
export interface SecurityIncidentNote { id: string; incidentId: string; author: string; body: string; createdAt: string; }
export interface SecurityIncidentActivity { id: string; incidentId: string; action: string; actor: string; metadata: Record<string, unknown>; createdAt: string; }
export interface SecurityIncidentThread { id: string; rootEventId: string; events: string[]; pattern: string; severity: SecuritySeverity; attackTechniques: string[]; relatedIncidents: string[]; correlationStrength: number; correlationReasons: string[]; firstSeen: string; lastSeen: string; }

export interface SecurityIncidentDetail {
  incident: SecurityIncident; events: SecurityEvent[]; detections: DetectionResult[];
  notes: SecurityIncidentNote[]; activity: SecurityIncidentActivity[]; attackTechniques: string[];
  timeline: Array<{ timestamp: string; kind: 'event' | 'detection'; id: string; title: string; severity: SecuritySeverity; mitreTechniques: string[] }>;
  correlation: { eventCount: number; detectionCount: number; confidence: number; reasons: string[] };
}
export interface SecurityStoreSnapshot { events: SecurityEvent[]; detections: DetectionResult[]; incidentThreads: SecurityIncidentThread[]; incidents: SecurityIncident[]; runs: ScenarioRun[]; isSimulationRunning: boolean; backendOnline: boolean; }
export type SecurityStoreListener = (snapshot: SecurityStoreSnapshot) => void;
