import { Router } from 'express';
import { z } from 'zod';
import { nanoid } from 'nanoid';
import { evaluateEvent } from './detectionEngine';
import { addDetection, addEvent, addIncident, addIncidentActivity, getDevices, getDetections, getEvents, getIncidentDetail, getIncidents, getSnapshot } from './store';
import type { SecurityEvent, SecurityIncident, SecuritySeverity } from './types';

const router = Router();
const securityEventSchema = z.object({
  id: z.string().min(1), timestamp: z.string().datetime(),
  type: z.enum(['authentication', 'network', 'process', 'file', 'malware', 'privilege', 'exfiltration', 'dns', 'web', 'system', 'detection']),
  source: z.enum(['simulation', 'suricata', 'zeek', 'splunk', 'endpoint', 'firewall', 'identity', 'manual']),
  sourceSystem: z.string().optional(), title: z.string().min(1).max(300), description: z.string().min(1).max(5000),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']), sourceIP: z.string().optional(), destinationIP: z.string().optional(),
  sourcePort: z.number().int().min(0).max(65535).optional(), destinationPort: z.number().int().min(0).max(65535).optional(),
  protocol: z.string().optional(), hostname: z.string().optional(), username: z.string().optional(), processName: z.string().optional(),
  filePath: z.string().optional(), mitreTechniques: z.array(z.string()).optional(), scenarioId: z.string().optional(), metadata: z.record(z.string(), z.unknown()).optional(),
});
const severityRank: Record<SecuritySeverity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function highestSeverity(values: SecuritySeverity[]): SecuritySeverity { return values.reduce<SecuritySeverity>((highest, value) => severityRank[value] > severityRank[highest] ? value : highest, 'info'); }
function correlationKeys(event: SecurityEvent): string[] { return [event.sourceIP ? `ip:${event.sourceIP}` : null, event.hostname ? `host:${event.hostname}` : null, event.username ? `user:${event.username}` : null, event.scenarioId ? `scenario:${event.scenarioId}` : null].filter((value): value is string => Boolean(value)); }
function shareCorrelationKey(a: SecurityEvent, b: SecurityEvent): boolean { const keys = new Set(correlationKeys(a)); return correlationKeys(b).some((key) => keys.has(key)); }

async function createIncidentFromDetection(event: SecurityEvent, detection: Awaited<ReturnType<typeof evaluateEvent>>[number]) {
  const recentEvents = (await getEvents(1000)).filter((candidate) => Math.abs(new Date(event.timestamp).getTime() - new Date(candidate.timestamp).getTime()) <= 10 * 60 * 1000 && shareCorrelationKey(event, candidate));
  if (recentEvents.length < 2) return null;
  const recentEventIds = recentEvents.map((item) => item.id);
  const recentDetections = (await getDetections(500)).filter((item) => recentEventIds.includes(item.eventId));
  if (recentDetections.length === 0) return null;
  const existing = (await getIncidents(500)).find((incident) => incident.status !== 'resolved' && incident.eventIds.some((id) => recentEventIds.includes(id)));
  const now = new Date().toISOString();
  const techniques = Array.from(new Set(recentDetections.flatMap((item) => item.mitreTechniques)));
  const chainLabel = techniques.length > 0 ? ` [${techniques.slice(0, 3).join(' → ')}]` : '';
  const incident: SecurityIncident = {
    id: existing?.id ?? `inc-${nanoid(10)}`, title: existing?.title ?? `${detection.ruleName} activity detected${chainLabel}`,
    severity: highestSeverity([detection.severity, ...recentDetections.map((item) => item.severity)]), status: existing?.status ?? 'investigating',
    eventIds: Array.from(new Set([...(existing?.eventIds ?? []), ...recentEventIds])), detectionIds: Array.from(new Set([...(existing?.detectionIds ?? []), ...recentDetections.map((item) => item.id)])),
    assignee: existing?.assignee, resolvedAt: existing?.resolvedAt, createdAt: existing?.createdAt ?? now, updatedAt: now,
  };
  const persisted = await addIncident(incident);
  if (!existing) await addIncidentActivity(persisted.id, 'incident_created', 'J.A.R.V.I.S.', { severity: persisted.severity, detectionId: detection.id });
  return persisted;
}

router.get('/health', async (_req, res) => res.json({ success: true, data: { service: 'jarvis-security-api', status: 'online' } }));
router.get('/snapshot', async (_req, res, next) => { try { res.json({ success: true, data: await getSnapshot() }); } catch (error) { next(error); } });
router.get('/events', async (req, res, next) => { try { const rawLimit = Number(req.query.limit ?? 100); const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(rawLimit, 1000)) : 100; res.json({ success: true, data: await getEvents(limit) }); } catch (error) { next(error); } });
router.post('/events', async (req, res, next) => {
  try {
    const parsed = securityEventSchema.safeParse(req.body?.event ?? req.body);
    if (!parsed.success) return res.status(400).json({ success: false, error: 'Invalid security event payload', details: parsed.error.flatten() });
    const event = parsed.data as SecurityEvent;
    const history = await getEvents(1000); await addEvent(event);
    const detections = evaluateEvent(event, history); for (const detection of detections) await addDetection(detection);
    const incidents: SecurityIncident[] = []; for (const detection of detections) { const incident = await createIncidentFromDetection(event, detection); if (incident) incidents.push(incident); }
    return res.status(201).json({ success: true, data: { event, detections, incidents, ingestionId: nanoid() } });
  } catch (error) { next(error); }
});
router.get('/detections', async (req, res, next) => { try { const rawLimit = Number(req.query.limit ?? 100); const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(rawLimit, 500)) : 100; res.json({ success: true, data: await getDetections(limit) }); } catch (error) { next(error); } });
router.get('/incidents', async (_req, res, next) => { try { res.json({ success: true, data: await getIncidents() }); } catch (error) { next(error); } });
router.get('/incidents/:id', async (req, res, next) => { try { const detail = await getIncidentDetail(req.params.id); if (!detail) return res.status(404).json({ success: false, error: 'Incident not found' }); return res.json({ success: true, data: detail }); } catch (error) { next(error); } });
router.get('/devices', async (_req, res, next) => { try { res.json({ success: true, data: await getDevices() }); } catch (error) { next(error); } });
export default router;
