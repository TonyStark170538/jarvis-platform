export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type SecurityIncidentStatus = 'open' | 'investigating' | 'resolved';
export type SecurityEventType = 'authentication' | 'network' | 'process' | 'file' | 'malware' | 'privilege' | 'exfiltration' | 'dns' | 'web' | 'system' | 'detection';
export type SecurityEventSource = 'simulation' | 'suricata' | 'zeek' | 'splunk' | 'endpoint' | 'firewall' | 'identity' | 'manual';
export type SecurityIocType = 'ip' | 'domain' | 'hash' | 'url';

export interface SecurityEvent { id: string; timestamp: string; type: SecurityEventType; source: SecurityEventSource; sourceSystem?: string; title: string; description: string; severity: SecuritySeverity; sourceIP?: string; destinationIP?: string; sourcePort?: number; destinationPort?: number; protocol?: string; hostname?: string; username?: string; processName?: string; filePath?: string; mitreTechniques?: string[]; scenarioId?: string; metadata?: Record<string, unknown>; }
export interface SecurityDetection { id: string; ruleId: string; ruleName: string; eventId: string; timestamp: string; severity: SecuritySeverity; title: string; description: string; confidence: number; mitreTechniques: string[]; sourceIP?: string; destinationIP?: string; }
export interface SecurityIncident { id: string; title: string; severity: SecuritySeverity; status: SecurityIncidentStatus; eventIds: string[]; detectionIds: string[]; assignee?: string; resolvedAt?: string; createdAt: string; updatedAt: string; }
export interface SecurityIncidentNote { id: string; incidentId: string; author: string; body: string; createdAt: string; }
export interface SecurityIncidentActivity { id: string; incidentId: string; action: string; actor: string; metadata: Record<string, unknown>; createdAt: string; }
export interface SecurityIoc { id: string; type: SecurityIocType; value: string; severity: SecuritySeverity; source: string; tags: string[]; confidence: number; createdAt: string; updatedAt: string; }
export interface SecurityIncidentDetail { incident: SecurityIncident; events: SecurityEvent[]; detections: SecurityDetection[]; notes: SecurityIncidentNote[]; activity: SecurityIncidentActivity[]; attackTechniques: string[]; timeline: Array<{ timestamp: string; kind: 'event' | 'detection'; id: string; title: string; severity: SecuritySeverity; mitreTechniques: string[] }>; correlation: { eventCount: number; detectionCount: number; confidence: number; reasons: string[] }; }
export interface SecuritySnapshot { events: SecurityEvent[]; detections: SecurityDetection[]; incidents: SecurityIncident[]; devices: string[]; updatedAt: string; }
export interface SecurityIocContext { ioc: SecurityIoc; events: SecurityEvent[]; detections: SecurityDetection[]; incidents: SecurityIncident[]; attackTechniques: string[]; firstSeen?: string; lastSeen?: string; matchReasons: string[]; }
export interface SecurityApiResponse<T> { success: boolean; data?: T; error?: string; }
