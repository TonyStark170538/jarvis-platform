/**
 * J.A.R.V.I.S. Incident Correlation Engine
 *
 * Converts raw security telemetry into incident threads. The legacy generic
 * correlation helpers are kept below for compatibility, while the typed
 * SecurityEvent adapter is used by the live security store.
 */

import type { SecurityEvent, SecurityIncidentThread, SecuritySeverity } from '@/security/types';

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

const severityWeight: Record<SecuritySeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Typed correlation entry point for the security event core.
 * Events are correlated by scenario, host, source IP, destination IP,
 * MITRE technique, attack family and temporal proximity.
 */
export function correlateSecurityEvents(events: SecurityEvent[]): CorrelatedEvent[] {
  const sorted = [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  const result = new Map<string, CorrelatedEvent>();
  sorted.forEach((event) => {
    result.set(event.id, {
      id: event.id,
      childIds: [],
      correlationScore: 0,
      correlationReasons: [],
      isParent: false,
    });
  });

  for (let i = 0; i < sorted.length; i += 1) {
    for (let j = i + 1; j < sorted.length; j += 1) {
      const first = sorted[i];
      const second = sorted[j];
      const score = securityCorrelationScore(first, second);

      if (score < 0.55) continue;

      const parent = first;
      const child = second;
      const parentResult = result.get(parent.id)!;
      const childResult = result.get(child.id)!;

      if (!parentResult.childIds.includes(child.id)) {
        parentResult.childIds.push(child.id);
      }
      parentResult.isParent = true;
      parentResult.correlationScore = Math.max(parentResult.correlationScore, score);
      childResult.correlationScore = Math.max(childResult.correlationScore, score);

      for (const reason of getSecurityCorrelationReasons(first, second)) {
        if (!parentResult.correlationReasons.includes(reason)) parentResult.correlationReasons.push(reason);
        if (!childResult.correlationReasons.includes(reason)) childResult.correlationReasons.push(reason);
      }
    }
  }

  return Array.from(result.values());
}

/** Build incident threads directly from SecurityEvent telemetry. */
export function createSecurityIncidentThreads(events: SecurityEvent[]): SecurityIncidentThread[] {
  if (events.length === 0) return [];

  const sorted = [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  const correlated = correlateSecurityEvents(sorted);
  const byId = new Map(sorted.map((event) => [event.id, event]));
  const parentByChild = new Map<string, string>();

  for (const item of correlated) {
    for (const childId of item.childIds) {
      parentByChild.set(childId, item.id);
    }
  }

  const visited = new Set<string>();
  const threads: SecurityIncidentThread[] = [];

  for (const item of correlated) {
    if (parentByChild.has(item.id) || visited.has(item.id)) continue;

    const queue = [item.id];
    const eventIds: string[] = [];

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      if (visited.has(currentId)) continue;
      visited.add(currentId);
      eventIds.push(currentId);

      const current = correlated.find((candidate) => candidate.id === currentId);
      if (current) queue.push(...current.childIds);
    }

    const threadEvents = eventIds.map((id) => byId.get(id)).filter(Boolean) as SecurityEvent[];
    if (threadEvents.length === 0) continue;

    const firstSeen = threadEvents[0].timestamp;
    const lastSeen = threadEvents[threadEvents.length - 1].timestamp;
    const reasons = Array.from(
      new Set(threadEvents.flatMap((event) => correlated.find((item) => item.id === event.id)?.correlationReasons ?? []))
    );
    const techniques = Array.from(
      new Set(threadEvents.flatMap((event) => event.mitreTechniques ?? []))
    );
    const severity = threadEvents.reduce<SecuritySeverity>(
      (highest, event) => severityWeight[event.severity] > severityWeight[highest] ? event.severity : highest,
      'info'
    );
    const strength = Math.max(
      ...threadEvents.map((event) => correlated.find((item) => item.id === event.id)?.correlationScore ?? 0)
    );

    threads.push({
      id: `thread-${item.id}`,
      rootEventId: item.id,
      events: eventIds,
      pattern: detectSecurityAttackPattern(threadEvents),
      severity,
      attackTechniques: techniques,
      relatedIncidents: [],
      correlationStrength: Number(strength.toFixed(2)),
      correlationReasons: reasons,
      firstSeen,
      lastSeen,
    });
  }

  // Defensive fallback for graphs where a node was already attached to a
  // parent but was not reached due to malformed external telemetry.
  for (const event of sorted) {
    if (visited.has(event.id)) continue;
    visited.add(event.id);
    threads.push({
      id: `thread-${event.id}`,
      rootEventId: event.id,
      events: [event.id],
      pattern: detectSecurityAttackPattern([event]),
      severity: event.severity,
      attackTechniques: [...(event.mitreTechniques ?? [])],
      relatedIncidents: [],
      correlationStrength: 0,
      correlationReasons: [],
      firstSeen: event.timestamp,
      lastSeen: event.timestamp,
    });
  }

  return threads.sort(
    (a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime()
  );
}

function securityCorrelationScore(first: SecurityEvent, second: SecurityEvent): number {
  let score = 0;
  const firstTime = new Date(first.timestamp).getTime();
  const secondTime = new Date(second.timestamp).getTime();
  const timeDiff = Math.abs(secondTime - firstTime);

  if (first.scenarioId && first.scenarioId === second.scenarioId) score += 0.45;
  if (first.hostname && first.hostname === second.hostname) score += 0.18;
  if (first.sourceIP && first.sourceIP === second.sourceIP) score += 0.18;
  if (first.destinationIP && first.destinationIP === second.destinationIP) score += 0.08;

  const techniques = new Set(first.mitreTechniques ?? []);
  if ((second.mitreTechniques ?? []).some((technique) => techniques.has(technique))) score += 0.22;
  if (first.type === second.type) score += 0.05;

  if (timeDiff <= 30_000) score += 0.20;
  else if (timeDiff <= 120_000) score += 0.12;
  else if (timeDiff <= 300_000) score += 0.05;

  if (Math.abs(severityWeight[first.severity] - severityWeight[second.severity]) <= 1) score += 0.04;

  return Math.min(1, score);
}

function getSecurityCorrelationReasons(first: SecurityEvent, second: SecurityEvent): string[] {
  const reasons: string[] = [];
  const diff = Math.abs(new Date(first.timestamp).getTime() - new Date(second.timestamp).getTime());

  if (first.scenarioId && first.scenarioId === second.scenarioId) reasons.push('Same attack scenario');
  if (first.hostname && first.hostname === second.hostname) reasons.push(`Same host: ${first.hostname}`);
  if (first.sourceIP && first.sourceIP === second.sourceIP) reasons.push(`Same source IP: ${first.sourceIP}`);
  if (first.destinationIP && first.destinationIP === second.destinationIP) reasons.push(`Same destination IP: ${first.destinationIP}`);

  const commonTechniques = (first.mitreTechniques ?? []).filter((technique) =>
    second.mitreTechniques?.includes(technique)
  );
  if (commonTechniques.length) reasons.push(`Shared MITRE technique: ${commonTechniques.join(', ')}`);
  if (diff <= 60_000) reasons.push('Events occurred within 1 minute');
  else if (diff <= 300_000) reasons.push('Events occurred within 5 minutes');

  return reasons;
}

function detectSecurityAttackPattern(events: SecurityEvent[]): string {
  const text = events.map((event) => `${event.title} ${event.description}`).join(' ').toLowerCase();
  const techniques = new Set(events.flatMap((event) => event.mitreTechniques ?? []));

  if (techniques.has('T1110') || (text.includes('ssh') && text.includes('authentication'))) return 'SSH Brute Force Attack';
  if (techniques.has('T1059.001') || text.includes('powershell')) return 'Suspicious PowerShell Execution';
  if (techniques.has('T1041') || text.includes('exfiltration')) return 'Data Exfiltration Campaign';
  if (techniques.has('T1548') || text.includes('privilege escalation')) return 'Privilege Escalation Chain';
  if (techniques.has('T1204.002') || text.includes('malware')) return 'Malware Infection Chain';
  if (techniques.has('T1046') || text.includes('port scan')) return 'Network Reconnaissance';
  return events.length > 1 ? 'Multi-Stage Attack' : 'Isolated Security Event';
}

/** Legacy generic API retained for existing callers. */
export function correlateEvents(
  events: Array<{ id: string; event: string; source: string; severity: string; details: string; time: string }>
): CorrelatedEvent[] {
  return correlateSecurityEvents(
    events.map((event) => ({
      id: event.id,
      timestamp: event.time,
      type: 'detection',
      source: 'manual',
      title: event.event,
      description: event.details,
      severity: (['critical', 'high', 'medium', 'low'].includes(event.severity) ? event.severity : 'info') as SecuritySeverity,
    }))
  );
}

/** Legacy thread builder retained for existing callers. */
export function createIncidentThreads(
  events: Array<any>,
  correlatedEvents: CorrelatedEvent[]
): IncidentThread[] {
  const eventMap = new Map(events.map((event) => [event.id, event]));
  const threads: IncidentThread[] = [];
  const processed = new Set<string>();

  for (const item of correlatedEvents) {
    if (!item.isParent || item.parentId || processed.has(item.id)) continue;
    const ids = [item.id, ...item.childIds];
    ids.forEach((id) => processed.add(id));
    const root = eventMap.get(item.id);
    if (!root) continue;
    threads.push({
      id: `thread-${item.id}`,
      rootEventId: item.id,
      events: ids,
      pattern: 'Multi-Stage Attack',
      severity: root.severity === 'critical' || root.severity === 'high' || root.severity === 'medium' || root.severity === 'low' ? root.severity : 'low',
      attackTechniques: [],
      relatedIncidents: [],
      correlationStrength: item.correlationScore,
    });
  }

  for (const item of correlatedEvents) {
    if (processed.has(item.id)) continue;
    const event = eventMap.get(item.id);
    if (!event) continue;
    threads.push({
      id: `thread-${item.id}`,
      rootEventId: item.id,
      events: [item.id],
      pattern: 'Isolated Event',
      severity: event.severity === 'critical' || event.severity === 'high' || event.severity === 'medium' || event.severity === 'low' ? event.severity : 'low',
      attackTechniques: [],
      relatedIncidents: [],
      correlationStrength: 0,
    });
  }
  return threads;
}
