import { Router } from "express";
import { z } from "zod";
import { addEvent, getDevices, getEvents, getIncidents, getSnapshot } from "./store";

const router = Router();

const securityEventSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  event: z.string(),
  source: z.string(),
  severity: z.string(),
  details: z.string(),
}).passthrough();

router.get("/health", (_req, res) => {
  res.json({ success: true, service: "jarvis-security-api", status: "online" });
});

router.get("/snapshot", (_req, res) => {
  res.json({ success: true, data: getSnapshot() });
});

router.get("/events", (req, res) => {
  const rawLimit = Number(req.query.limit ?? 100);
  const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(rawLimit, 1000)) : 100;
  res.json({ success: true, data: getEvents(limit) });
});

router.post("/events", (req, res) => {
  const parsed = securityEventSchema.safeParse(req.body?.event ?? req.body);
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: "Invalid security event payload" });
  }

  const event = addEvent(parsed.data as never);
  return res.status(201).json({ success: true, data: event });
});

router.get("/incidents", (_req, res) => {
  res.json({ success: true, data: getIncidents() });
});

router.get("/devices", (_req, res) => {
  res.json({ success: true, data: getDevices() });
});

export default router;
