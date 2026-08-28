import { Router } from 'express';
import { timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { nanoid } from 'nanoid';
import { evaluateEvent } from './detectionEngine';
import { addDetection, addEvent, getEvents } from './store';
import type { SecurityEvent } from './types';

const router = Router();

const securityEventSchema = z.object({
  id: z.string().min(1).max(200),
  timestamp: z.string().datetime(),
  type: z.enum(['authentication', 'network', 'process', 'file', 'malware', 'privilege', 'exfiltration', 'dns', 'web', 'system', 'detection']),
  source: z.literal('endpoint'),
  sourceSystem: z.string().max(200).optional(),
  title: z.string().min(1).max(300),
  description: z.string().min(1).max(5000),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  sourceIP: z.string().max(100).optional(),
  destinationIP: z.string().max(100).optional(),
  sourcePort: z.number().int().min(0).max(65535).optional(),
  destinationPort: z.number().int().min(0).max(65535).optional(),
  protocol: z.string().max(50).optional(),
  hostname: z.string().max(255).optional(),
  username: z.string().max(255).optional(),
  processName: z.string().max(500).optional(),
  filePath: z.string().max(2000).optional(),
  mitreTechniques: z.array(z.string().max(100)).max(50).optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

function isValidAgentKey(provided: string | undefined): boolean {
  const expected = process.env.JARVIS_AGENT_API_KEY;
  if (!expected || !provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function requireAgentKey(req: { header(name: string): string | undefined }, res: { status(code: number): { json(body: unknown): unknown } }): boolean {
  if (isValidAgentKey(req.header('X-JARVIS-Agent-Key'))) return true;
  res.status(401).json({ success: false, error: 'Invalid or missing agent API key' });
  return false;
}

router.get('/health', (req, res) => {
  if (!requireAgentKey(req, res)) return;
  res.json({ success: true, data: { service: 'jarvis-agent-ingestion', status: 'ready' } });
});

router.post('/events', async (req, res, next) => {
  if (!requireAgentKey(req, res)) return;

  try {
    const parsed = securityEventSchema.safeParse(req.body?.event ?? req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid endpoint security event payload',
        details: parsed.error.flatten(),
      });
    }

    const event = parsed.data as SecurityEvent;
    const history = await getEvents(1000);
    await addEvent(event);

    const detections = evaluateEvent(event, history);
    for (const detection of detections) await addDetection(detection);

    return res.status(201).json({
      success: true,
      data: {
        event,
        detections,
        ingestionId: nanoid(),
      },
    });
  } catch (error) {
    next(error);
  }
});

export default router;
