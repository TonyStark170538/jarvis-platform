import type {
  DetectionResult,
  DetectionRule,
  SecurityEvent,
  SecuritySeverity,
} from './types';

const severityWeight: Record<SecuritySeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function createId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function contains(text: string | undefined, ...terms: string[]): boolean {
  const normalized = text?.toLowerCase() ?? '';
  return terms.every((term) => normalized.includes(term.toLowerCase()));
}

function hasTechnique(event: SecurityEvent, technique: string): boolean {
  return event.mitreTechniques?.includes(technique) ?? false;
}

function confidenceFor(
  event: SecurityEvent,
  history: SecurityEvent[],
  technique: string,
  minimumRelatedEvents = 0
): number {
  const related = history.filter(
    (candidate) =>
      candidate.sourceIP &&
      event.sourceIP &&
      candidate.sourceIP === event.sourceIP &&
      candidate.timestamp <= event.timestamp &&
      Math.abs(new Date(event.timestamp).getTime() - new Date(candidate.timestamp).getTime()) <= 120_000
  );

  let confidence = hasTechnique(event, technique) ? 72 : 60;
  if (related.length >= minimumRelatedEvents) confidence += 12;
  if (event.severity === 'high' || event.severity === 'critical') confidence += 8;

  return Math.min(99, confidence);
}

/**
 * Deterministic rules are deliberately kept separate from the AI layer.
 * AI can later explain or prioritize a detection, but it should not be the
 * source of truth for whether a security rule matched.
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
      (contains(event.title, 'ssh', 'failure') || contains(event.description, 'ssh', 'authentication')),
  },
  {
    id: 'DET-PORT-SCAN',
    name: 'Network Port Scan',
    description: 'Detects a network reconnaissance event consistent with port scanning.',
    severity: 'high',
    mitreTechniques: ['T1046'],
    match: (event) =>
      event.type === 'network' &&
      (contains(event.title, 'port', 'scan') || hasTechnique(event, 'T1046')),
  },
  {
    id: 'DET-POWERSHELL',
    name: 'Suspicious PowerShell Execution',
    description: 'Detects suspicious PowerShell execution and encoded command activity.',
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
    description: 'Detects a suspicious outbound transfer associated with sensitive data.',
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
    description: 'Detects a malware signature or suspicious executable activity.',
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
): DetectionResult[] {
  return rules
    .filter((rule) => rule.match(event))
    .map((rule) => {
      const relatedCount = history.filter(
        (candidate) =>
          candidate.id !== event.id &&
          candidate.sourceIP === event.sourceIP &&
          Math.abs(new Date(event.timestamp).getTime() - new Date(candidate.timestamp).getTime()) <= 120_000
      ).length;

      const confidence = confidenceFor(
        event,
        history,
        rule.mitreTechniques[0],
        rule.id === 'DET-SSH-BRUTE-FORCE' ? 2 : 0
      );

      const effectiveSeverity =
        severityWeight[event.severity] > severityWeight[rule.severity]
          ? event.severity
          : rule.severity;

      return {
        id: createId('det'),
        ruleId: rule.id,
        ruleName: rule.name,
        eventId: event.id,
        timestamp: event.timestamp,
        severity: effectiveSeverity,
        title: rule.name,
        description: `${rule.description}${relatedCount > 0 ? ` ${relatedCount} related event(s) found in the correlation window.` : ''}`,
        confidence,
        mitreTechniques: Array.from(
          new Set([...(event.mitreTechniques ?? []), ...rule.mitreTechniques])
        ),
        sourceIP: event.sourceIP,
        destinationIP: event.destinationIP,
      } satisfies DetectionResult;
    });
}

/**
 * Evaluate a complete event collection. Results are sorted newest first and
 * duplicate rule/event combinations are removed.
 */
export function evaluateEvents(
  events: SecurityEvent[],
  rules: DetectionRule[] = DETECTION_RULES
): DetectionResult[] {
  const results: DetectionResult[] = [];

  for (const event of [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  )) {
    results.push(...evaluateEvent(event, events, rules));
  }

  const unique = new Map<string, DetectionResult>();
  for (const result of results) {
    unique.set(`${result.ruleId}:${result.eventId}`, result);
  }

  return Array.from(unique.values()).sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
}

export function getDetectionSeverityScore(severity: SecuritySeverity): number {
  return severityWeight[severity];
}

export function getHighestDetectionSeverity(
  detections: DetectionResult[]
): SecuritySeverity {
  if (detections.length === 0) return 'info';

  return detections.reduce<SecuritySeverity>(
    (highest, current) =>
      severityWeight[current.severity] > severityWeight[highest]
        ? current.severity
        : highest,
    'info'
  );
}
