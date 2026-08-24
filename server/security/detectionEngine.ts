import { nanoid } from 'nanoid';
import type {
  SecurityDetection,
  SecurityEvent,
  SecuritySeverity,
} from './types';

interface DetectionRule {
  id: string;
  name: string;
  description: string;
  severity: SecuritySeverity;
  mitreTechniques: string[];
  match: (event: SecurityEvent) => boolean;
}

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

function relatedEvents(event: SecurityEvent, history: SecurityEvent[], windowMs = 120_000): SecurityEvent[] {
  const eventTime = new Date(event.timestamp).getTime();
  return history.filter((candidate) => {
    if (candidate.id === event.id) return false;
    if (!event.sourceIP || candidate.sourceIP !== event.sourceIP) return false;
    const candidateTime = new Date(candidate.timestamp).getTime();
    return candidateTime <= eventTime && eventTime - candidateTime <= windowMs;
  });
}

function confidenceFor(
  event: SecurityEvent,
  history: SecurityEvent[],
  technique: string,
  minimumRelatedEvents = 0
): number {
  const related = relatedEvents(event, history);
  let confidence = hasTechnique(event, technique) ? 72 : 60;

  if (related.length >= minimumRelatedEvents) confidence += 12;
  if (event.severity === 'high' || event.severity === 'critical') confidence += 8;

  return Math.min(99, confidence);
}

/**
 * Server-side source of truth for deterministic security detections.
 * AI may enrich or explain these results later, but never replaces the rules.
 */
export const DETECTION_RULES: DetectionRule[] = [
  {
    id: 'DET-SSH-BRUTE-FORCE',
    name: 'SSH Brute Force',
    description: 'Detects repeated SSH authentication failures from the same source.',
    severity: 'critical',
    mitreTechniques: ['T1110'],
    match: (event) =>
      event.type === 'authentication' &&
      event.destinationPort === 22 &&
      (contains(event.title, 'ssh', 'failure') ||
        contains(event.description, 'ssh', 'authentication')),
  },
  {
    id: 'DET-PORT-SCAN',
    name: 'Network Port Scan',
    description: 'Detects network reconnaissance consistent with port scanning.',
    severity: 'high',
    mitreTechniques: ['T1046'],
    match: (event) =>
      event.type === 'network' &&
      (contains(event.title, 'port', 'scan') || hasTechnique(event, 'T1046')),
  },
  {
    id: 'DET-POWERSHELL',
    name: 'Suspicious PowerShell Execution',
    description: 'Detects suspicious PowerShell and encoded command activity.',
    severity: 'high',
    mitreTechniques: ['T1059.001'],
    match: (event) =>
      (event.processName?.toLowerCase() === 'powershell.exe' || contains(event.title, 'powershell')) &&
      (contains(event.title, 'suspicious') ||
        contains(event.title, 'encoded') ||
        contains(event.description, 'encoded')),
  },
  {
    id: 'DET-DATA-EXFILTRATION',
    name: 'Potential Data Exfiltration',
    description: 'Detects suspicious outbound transfer associated with sensitive data.',
    severity: 'critical',
    mitreTechniques: ['T1041', 'T1560'],
    match: (event) =>
      event.type === 'exfiltration' ||
      contains(event.title, 'data', 'loss', 'prevention') ||
      contains(event.title, 'large', 'outbound', 'transfer'),
  },
  {
    id: 'DET-MALWARE',
    name: 'Malware Detection',
    description: 'Detects malware signatures or suspicious executable activity.',
    severity: 'critical',
    mitreTechniques: ['T1204.002'],
    match: (event) =>
      event.type === 'malware' ||
      contains(event.title, 'malware', 'signature') ||
      contains(event.title, 'suspicious', 'executable'),
  },
  {
    id: 'DET-PRIVILEGE-ESCALATION',
    name: 'Privilege Escalation Indicator',
    description: 'Detects simulated privilege elevation activity.',
    severity: 'high',
    mitreTechniques: ['T1548'],
    match: (event) =>
      event.type === 'privilege' ||
      contains(event.title, 'privilege', 'escalation') ||
      contains(event.description, 'elevated', 'privileges'),
  },
];

export function evaluateEvent(
  event: SecurityEvent,
  history: SecurityEvent[] = [],
  rules: DetectionRule[] = DETECTION_RULES
): SecurityDetection[] {
  return rules
    .filter((rule) => rule.match(event))
    .map((rule) => {
      const related = relatedEvents(event, history);
      const relatedCount = related.length;
      const confidence = confidenceFor(
        event,
        history,
        rule.mitreTechniques[0],
        rule.id === 'DET-SSH-BRUTE-FORCE' ? 2 : 0
      );

      const severity =
        severityWeight[event.severity] > severityWeight[rule.severity]
          ? event.severity
          : rule.severity;

      return {
        id: `det-${nanoid(12)}`,
        ruleId: rule.id,
        ruleName: rule.name,
        eventId: event.id,
        timestamp: event.timestamp,
        severity,
        title: rule.name,
        description: `${rule.description}${relatedCount > 0 ? ` ${relatedCount} related event(s) found in the correlation window.` : ''}`,
        confidence,
        mitreTechniques: Array.from(
          new Set([...(event.mitreTechniques ?? []), ...rule.mitreTechniques])
        ),
        sourceIP: event.sourceIP,
        destinationIP: event.destinationIP,
      } satisfies SecurityDetection;
    });
}

export function evaluateEvents(
  events: SecurityEvent[],
  rules: DetectionRule[] = DETECTION_RULES
): SecurityDetection[] {
  const results: SecurityDetection[] = [];

  for (const event of [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  )) {
    results.push(...evaluateEvent(event, events, rules));
  }

  const unique = new Map<string, SecurityDetection>();
  for (const result of results) {
    unique.set(`${result.ruleId}:${result.eventId}`, result);
  }

  return Array.from(unique.values()).sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
}
