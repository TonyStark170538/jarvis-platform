/**
 * Incident Correlation Engine
 * Groups related events into incident threads and identifies attack patterns
 */

export interface CorrelatedEvent {
  id: string;
  parentId?: string;
  childIds: string[];
  correlationScore: number;
  correlationReasons: string[];
  isParent: boolean;
}

export interface IncidentThread {
  id: string;
  rootEventId: string;
  events: string[];
  pattern: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  attackTechniques: string[];
  relatedIncidents: string[];
  correlationStrength: number;
}

/**
 * Analyze events for correlation patterns
 */
export function correlateEvents(
  events: Array<{
    id: string;
    event: string;
    source: string;
    severity: string;
    details: string;
    time: string;
  }>
): CorrelatedEvent[] {
  const correlatedEvents: CorrelatedEvent[] = [];
  const correlationMap = new Map<string, CorrelatedEvent>();

  // Initialize all events
  events.forEach((event) => {
    correlationMap.set(event.id, {
      id: event.id,
      childIds: [],
      correlationScore: 0,
      correlationReasons: [],
      isParent: false,
    });
  });

  // Find correlations between events
  for (let i = 0; i < events.length; i++) {
    for (let j = i + 1; j < events.length; j++) {
      const event1 = events[i];
      const event2 = events[j];

      const score = calculateCorrelationScore(event1, event2);

      if (score > 0.5) {
        // Events are correlated
        const correlatedEvent1 = correlationMap.get(event1.id)!;
        const correlatedEvent2 = correlationMap.get(event2.id)!;

        // Determine parent-child relationship based on time
        const isEvent1Earlier = new Date(event1.time) < new Date(event2.time);
        const parent = isEvent1Earlier ? event1 : event2;
        const child = isEvent1Earlier ? event2 : event1;

        const parentCorrelated = correlationMap.get(parent.id)!;
        const childCorrelated = correlationMap.get(child.id)!;

        parentCorrelated.isParent = true;
        childCorrelated.parentId = parent.id;
        parentCorrelated.childIds.push(child.id);

        parentCorrelated.correlationScore = Math.max(
          parentCorrelated.correlationScore,
          score
        );
        childCorrelated.correlationScore = score;

        // Add correlation reasons
        const reasons = getCorrelationReasons(event1, event2);
        parentCorrelated.correlationReasons.push(...reasons);
        childCorrelated.correlationReasons.push(...reasons);
      }
    }
  }

  correlationMap.forEach((event) => {
    correlatedEvents.push(event);
  });

  return correlatedEvents;
}

/**
 * Calculate correlation score between two events (0-1)
 */
function calculateCorrelationScore(
  event1: any,
  event2: any
): number {
  let score = 0;

  // Same source indicator
  if (event1.source === event2.source) {
    score += 0.2;
  }

  // Same or related severity
  const severityMap = { critical: 4, high: 3, medium: 2, low: 1 };
  const sev1 = severityMap[event1.severity as keyof typeof severityMap] || 0;
  const sev2 = severityMap[event2.severity as keyof typeof severityMap] || 0;
  if (Math.abs(sev1 - sev2) <= 1) {
    score += 0.15;
  }

  // Pattern matching in event names
  const keywords1 = event1.event.toLowerCase().split(/\s+/);
  const keywords2 = event2.event.toLowerCase().split(/\s+/);
  const commonKeywords = keywords1.filter((k: string) =>
    keywords2.includes(k)
  ).length;
  score += (commonKeywords / Math.max(keywords1.length, keywords2.length)) * 0.3;

  // Time proximity (within 2 minutes)
  const time1 = new Date(event1.time).getTime();
  const time2 = new Date(event2.time).getTime();
  const timeDiff = Math.abs(time1 - time2);
  if (timeDiff < 120000) {
    score += 0.35;
  } else if (timeDiff < 300000) {
    score += 0.15;
  }

  // Attack pattern matching
  if (isAttackPatternMatch(event1, event2)) {
    score += 0.25;
  }

  return Math.min(score, 1);
}

/**
 * Get human-readable correlation reasons
 */
function getCorrelationReasons(event1: any, event2: any): string[] {
  const reasons: string[] = [];

  if (event1.source === event2.source) {
    reasons.push(`Same source: ${event1.source}`);
  }

  const time1 = new Date(event1.time).getTime();
  const time2 = new Date(event2.time).getTime();
  const timeDiff = Math.abs(time1 - time2);

  if (timeDiff < 60000) {
    reasons.push('Events occurred within 1 minute');
  } else if (timeDiff < 300000) {
    reasons.push('Events occurred within 5 minutes');
  }

  if (event1.event.toLowerCase().includes('ssh') && event2.event.toLowerCase().includes('auth')) {
    reasons.push('Related to SSH authentication chain');
  }

  if (event1.event.toLowerCase().includes('firewall') && event2.event.toLowerCase().includes('block')) {
    reasons.push('Part of firewall blocking sequence');
  }

  return reasons;
}

/**
 * Detect known attack patterns
 */
function isAttackPatternMatch(event1: any, event2: any): boolean {
  const patterns = [
    { keywords: ['ssh', 'failed', 'authentication'], name: 'SSH Brute Force' },
    { keywords: ['powershell', 'execution', 'suspicious'], name: 'PowerShell Execution' },
    { keywords: ['data', 'exfiltration', 'transfer'], name: 'Data Exfiltration' },
    { keywords: ['privilege', 'escalation', 'elevation'], name: 'Privilege Escalation' },
    { keywords: ['malware', 'detected', 'signature'], name: 'Malware Detection' },
  ];

  const text1 = `${event1.event} ${event1.details}`.toLowerCase();
  const text2 = `${event2.event} ${event2.details}`.toLowerCase();

  for (const pattern of patterns) {
    const match1 = pattern.keywords.every((kw) => text1.includes(kw));
    const match2 = pattern.keywords.every((kw) => text2.includes(kw));

    if (match1 && match2) {
      return true;
    }
  }

  return false;
}

/**
 * Group correlated events into incident threads
 */
export function createIncidentThreads(
  events: Array<any>,
  correlatedEvents: CorrelatedEvent[]
): IncidentThread[] {
  const threads: IncidentThread[] = [];
  const processedEvents = new Set<string>();

  // Find root events (parents with no parent)
  correlatedEvents.forEach((corEvent) => {
    if (corEvent.isParent && !corEvent.parentId && !processedEvents.has(corEvent.id)) {
      const rootEvent = events.find((e) => e.id === corEvent.id);
      if (rootEvent) {
        const threadEvents = [corEvent.id, ...corEvent.childIds];
        threadEvents.forEach((id) => processedEvents.add(id));

        const thread: IncidentThread = {
          id: `thread-${corEvent.id}`,
          rootEventId: corEvent.id,
          events: threadEvents,
          pattern: detectAttackPattern(
            threadEvents.map((id) => events.find((e) => e.id === id))
          ),
          severity: rootEvent.severity,
          attackTechniques: extractTechniques(threadEvents.map((id) => events.find((e) => e.id === id))),
          relatedIncidents: [],
          correlationStrength: corEvent.correlationScore,
        };

        threads.push(thread);
      }
    }
  });

  // Handle uncorrelated events as single-event threads
  correlatedEvents.forEach((corEvent) => {
    if (!processedEvents.has(corEvent.id)) {
      const event = events.find((e) => e.id === corEvent.id);
      if (event) {
        threads.push({
          id: `thread-${corEvent.id}`,
          rootEventId: corEvent.id,
          events: [corEvent.id],
          pattern: 'Isolated Event',
          severity: event.severity,
          attackTechniques: extractTechniques([event]),
          relatedIncidents: [],
          correlationStrength: 0,
        });
        processedEvents.add(corEvent.id);
      }
    }
  });

  return threads;
}

/**
 * Detect the attack pattern from a thread of events
 */
function detectAttackPattern(events: any[]): string {
  const eventTexts = events.map((e) => e?.event?.toLowerCase() || '').join(' ');

  if (eventTexts.includes('ssh') && eventTexts.includes('failed')) {
    return 'SSH Brute Force Attack';
  }
  if (eventTexts.includes('powershell') && eventTexts.includes('execution')) {
    return 'PowerShell-based Lateral Movement';
  }
  if (eventTexts.includes('data') && eventTexts.includes('exfiltration')) {
    return 'Data Exfiltration Campaign';
  }
  if (eventTexts.includes('privilege') && eventTexts.includes('escalation')) {
    return 'Privilege Escalation Chain';
  }
  if (eventTexts.includes('malware')) {
    return 'Malware Infection Chain';
  }

  return 'Multi-Stage Attack';
}

/**
 * Extract MITRE ATT&CK techniques from events
 */
function extractTechniques(events: any[]): string[] {
  const techniques: string[] = [];
  const eventTexts = events.map((e) => e?.event?.toLowerCase() || '').join(' ');

  const techniqueMap: Record<string, string[]> = {
    'T1110': ['brute', 'force', 'ssh', 'failed', 'authentication'],
    'T1059': ['powershell', 'execution', 'command'],
    'T1020': ['data', 'exfiltration', 'transfer', 'external'],
    'T1548': ['privilege', 'escalation', 'elevation', 'admin'],
    'T1566': ['phishing', 'email', 'attachment'],
    'T1566.002': ['malware', 'detected', 'signature'],
  };

  Object.entries(techniqueMap).forEach(([technique, keywords]) => {
    if (keywords.some((kw) => eventTexts.includes(kw))) {
      techniques.push(technique);
    }
  });

  return techniques;
}
