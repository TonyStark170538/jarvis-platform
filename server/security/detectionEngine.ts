import { nanoid } from 'nanoid';
import type { SecurityDetection, SecurityEvent, SecuritySeverity } from './types';

const severityWeight: Record<SecuritySeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function contains(text: string | undefined, ...terms: string[]): boolean {
  const normalized = text?.toLowerCase() ?? '';
  return terms.every((term) => normalized.includes(term.toLowerCase()));
}

function hasTechnique(event: SecurityEvent, technique: string): boolean {
  return event.mitreTechniques?.includes(technique) ?? false;
}

interface DetectionRule {
  id: string;
  name: string;
  description: string;
  severity: SecuritySeverity;
  mitreTechniques: string[];
  match: (event: SecurityEvent) => boolean;
}

export const DETECTION_RULES: DetectionRule[] = [
  {
    id: 'DET-SSH-BRUTE-FORCE',
    name: 'SSH Brute Force',
    description: 'Repeated SSH authentication failures indicate possible brute-force activity.',
    severity: 'critical',
    mitreTechniques: ['T1110'],
    match: (event) => event.type === 'authentication' && event.destinationPort === 22 &&
      (contains(event.title, 'ssh', 'failure') || contains(event.description, 'ssh', 'authentication')),
  },
  {
    id: 'DET-PORT-SCAN',
    name: 'Network Port Scan',
    description: 'Network reconnaissance activity consistent with port scanning was observed.',
    severity: 'high',
    mitreTechniques: ['T1046'],
    match: (event) => event.type === 'network' &&
      (contains(event.title, 'port', 'scan') || hasTechnique(event, 'T1046')),
  },
  {
    id: 'DET-POWERSHELL',
    name: 'Suspicious PowerShell Execution',
    description: 'PowerShell execution contains indicators associated with suspicious or encoded activity.',
    severity: 'high',
    mitreTechniques: ['T1059.001'],
    match: (event) =>
      (event.processName?.toLowerCase() === 'powershell.exe' || contains(event.title, 'powershell')) &&
      (contains(event.title, 'suspicious') || contains(event.title, 'encoded') || contains(event.description, 'encoded')),
  },
  {
    id: 'DET-DATA-EXFILTRATION',
    name: 'Potential Data Exfiltration',
    description: 'Suspicious outbound data transfer may indicate attempted exfiltration.',
    severity: 'critical',
    mitreTechniques: ['T1041', 'T1560'],
    match: (event) => event.type === 'exfiltration' ||
      contains(event.title, 'data', 'loss', 'prevention') ||
      contains(event.title, 'large', 'outbound', 'transfer'),
  },
  {
    id: 'DET-MALWARE',
    name: 'Malware Detection',
    description: 'Malware or suspicious executable activity was detected.',
    severity: 'critical',
    mitreTechniques: ['T1204.002'],
    match: (event) => event.type === 'malware' ||
      contains(event.title, 'malware', 'signature') ||
      contains(event.title, 'suspicious', 'executable'),
  },
  {
    id: 'DET-PRIVILEGE-ESCALATION',
    name: 'Privilege Escalation Indicator',
    description: 'Activity indicates possible privilege elevation.',
    severity: 'high',
    mitreTechniques: ['T1548'],
    match: (event) => event.type === 'privilege' ||
      contains(event.title, 'privilege', 'escalation') ||
      contains(event.description, 'elevated', 'privileges'),
  },
];

export function evaluateEvent(event: SecurityEvent, history: SecurityEvent[] = []): SecurityDetection[] {
  return DETECTION_RULES.filter((rule) => rule.match(event)).map((rule) => {
    const relatedCount = history.filter((candidate) =>
      candidate.id !== event.id &&
      candidate.sourceIP === event.sourceIP &&
      Math.abs(new Date(event.timestamp).getTime() - new Date(candidate.timestamp).getTime()) <= 120_000
    ).length;

    let confidence = event.mitreTechniques?.some((t) => rule.mitreTechniques.includes(t)) ? 72 : 60;
    if (relatedCount > 0) confidence += 12;
    if (event.severity === 'high' || event.severity === 'critical') confidence += 8;

    const severity = severityWeight[event.severity] > severityWeight[rule.severity]
      ? event.severity
      : rule.severity;

    return {
      id: nanoid(),
      ruleId: rule.id,
      ruleName: rule.name,
      eventId: event.id,
      timestamp: event.timestamp,
      severity,
      title: rule.name,
      description: `${rule.description}${relatedCount > 0 ? ` ${relatedCount} related event(s) found in the correlation window.` : ''}`,
      confidence: Math.min(99, confidence),
      mitreTechniques: Array.from(new Set([...(event.mitreTechniques ?? []), ...rule.mitreTechniques])),
      sourceIP: event.sourceIP,
      destinationIP: event.destinationIP,
    };
  });
}
