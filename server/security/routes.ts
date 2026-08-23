import { Router } from 'express';
import { z } from 'zod';
import { nanoid } from 'nanoid';
import { evaluateEvent } from './detectionEngine';
import {
  addDetection,
  addEvent,
  getDevices,
  getDetections,
  getEvents,
  getIncidents,
  getSnapshot,
} from './store';
import type { SecurityEvent } from './types';

const router = Router();

const securityEventSchema = z.object({
  id: z.string().min(1),
  timestamp: z.string().datetime(),
  type: z.enum(['authentication', 'network', 'process', 'file', 'malware', 'privilege', 'exfiltration', 'dns', 'web', 'system', 'detection']),
  source: z.enum(['simulation', 'suricata', 'zeek', 'splunk', 'endpoint', 'firewall', 'identity', 'manual']),
  sourceSystem: z.string().optional(),
  title: z.string().min(1).max(300),
  description: z.string().min(1).max(5000),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  sourceIP: z.string().optional(),
  destinationIP: z.string().optional(),
  sourcePort: z.number().int().min(0).max(65535).optional(),
  destinationPort: z.number().int().min(0).max(65535).optional(),
  protocol: z.string().optional(),
  hostname: z.string().optional(),
  username: z.string().optional(),
  processName: z.string().optional(),
  filePath: z.string().optional(),
  mitreTechniques: z.array(z.string()).optional(),
  scenarioId: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

router.get('/health', (_req, res) => {
  res.json({
    success: true,
    data: { service: 'jarvis-security-api', status: 'online' },
  });
});

router.get('/snapshot', (_req, res) => {
  res.json({ success: true, data: getSnapshot() });
});

router.get('/events', (req, res) => {
  const rawLimit = Number(req.query.limit ?? 100);
  const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(rawLimit, 1000)) : 100;
  res.json({ success: true, data: getEvents(limit) });
});

router.post('/events', (req, res) => {
  const parsed = securityEventSchema.safeParse(req.body?.event ?? req.body);

  if (!parsed.success) {
    return res.status(400).json({
      success: false,
      error: 'Invalid security event payload',
      details: parsed.error.flatten(),
    });
  }

  const event = parsed.data as SecurityEvent;
  const history = getEvents(1000);
  addEvent(event);

  const detections = evaluateEvent(event, history);
  detections.forEach(addDetection);

  return res.status(201).json({
    success: true,
    data: {
      event,
      detections,
      ingestionId: nanoid(),
    },
  });
});

router.get('/detections', (req, res) => {
  const rawLimit = Number(req.query.limit ?? 100);
  const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(rawLimit, 500)) : 100;
  res.json({ success: true, data: getDetections(limit) });
});

router.get('/incidents', (_req, res) => {
  res.json({ success: true, data: getIncidents() });
});

router.get('/devices', (_req, res) => {
  res.json({ success: true, data: getDevices() });
});

export default router;
