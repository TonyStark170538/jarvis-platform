export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type SecurityEventType =
  | 'authentication'
  | 'network'
  | 'process'
  | 'file'
  | 'malware'
  | 'privilege'
  | 'exfiltration'
  | 'dns'
  | 'web'
  | 'system'
  | 'detection';

export type SecurityEventSource =
  | 'simulation'
  | 'suricata'
  | 'zeek'
  | 'splunk'
  | 'endpoint'
  | 'firewall'
  | 'identity'
  | 'manual';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: SecurityEventType;
  source: SecurityEventSource;
  sourceSystem?: string;
  title: string;
  description: string;
  severity: SecuritySeverity;
  sourceIP?: string;
  destinationIP?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  hostname?: string;
  username?: string;
  processName?: string;
  filePath?: string;
  mitreTechniques?: string[];
  scenarioId?: string;
  metadata?: Record<string, unknown>;
}

export interface SecurityDetection {
  id: string;
  ruleId: string;
  ruleName: string;
  eventId: string;
  timestamp: string;
  severity: SecuritySeverity;
  title: string;
  description: string;
  confidence: number;
  mitreTechniques: string[];
  sourceIP?: string;
  destinationIP?: string;
}

export interface SecurityIncident {
  id: string;
  title: string;
  severity: SecuritySeverity;
  status: 'open' | 'investigating' | 'resolved';
  eventIds: string[];
  detectionIds: string[];
  createdAt: string;
  updatedAt: string;
}

<<<<<<< HEAD
export interface SecurityIncidentDetail {
  incident: SecurityIncident;
  events: SecurityEvent[];
  detections: SecurityDetection[];
  attackTechniques: string[];
  timeline: Array<{
    timestamp: string;
    kind: 'event' | 'detection';
    id: string;
    title: string;
    severity: SecuritySeverity;
    mitreTechniques: string[];
  }>;
  correlation: {
    eventCount: number;
    detectionCount: number;
    confidence: number;
    reasons: string[];
  };
}

=======
>>>>>>> origin/main
export interface SecuritySnapshot {
  events: SecurityEvent[];
  detections: SecurityDetection[];
  incidents: SecurityIncident[];
  devices: string[];
  updatedAt: string;
}

export interface SecurityApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}
