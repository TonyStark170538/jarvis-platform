// server/index.ts
import cors from "cors";
import express from "express";
import { createServer } from "http";

// server/security/routes.ts
import { Router } from "express";
import { z } from "zod";
import { nanoid } from "nanoid";

// server/security/detectionEngine.ts
var severityWeight = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};
function contains(text, ...terms) {
  const normalized = text?.toLowerCase() ?? "";
  return terms.every((term) => normalized.includes(term.toLowerCase()));
}
function hasTechnique(event, technique) {
  return event.mitreTechniques?.includes(technique) ?? false;
}
function relatedEvents(event, history, windowMs = 12e4) {
  const eventTime = new Date(event.timestamp).getTime();
  return history.filter((candidate) => {
    if (candidate.id === event.id) return false;
    if (!event.sourceIP || candidate.sourceIP !== event.sourceIP) return false;
    const candidateTime = new Date(candidate.timestamp).getTime();
    return candidateTime <= eventTime && eventTime - candidateTime <= windowMs;
  });
}
function confidenceFor(event, history, technique, minimumRelatedEvents = 0) {
  const related = relatedEvents(event, history);
  let confidence = hasTechnique(event, technique) ? 72 : 60;
  if (related.length >= minimumRelatedEvents) confidence += 12;
  if (event.severity === "high" || event.severity === "critical") confidence += 8;
  return Math.min(99, confidence);
}
var DETECTION_RULES = [
  {
    id: "DET-SSH-BRUTE-FORCE",
    name: "SSH Brute Force",
    description: "Detects repeated SSH authentication failures from the same source.",
    severity: "critical",
    mitreTechniques: ["T1110"],
    match: (event) => event.type === "authentication" && event.destinationPort === 22 && (contains(event.title, "ssh", "failure") || contains(event.description, "ssh", "authentication"))
  },
  {
    id: "DET-PORT-SCAN",
    name: "Network Port Scan",
    description: "Detects network reconnaissance consistent with port scanning.",
    severity: "high",
    mitreTechniques: ["T1046"],
    match: (event) => event.type === "network" && (contains(event.title, "port", "scan") || hasTechnique(event, "T1046"))
  },
  {
    id: "DET-POWERSHELL",
    name: "Suspicious PowerShell Execution",
    description: "Detects suspicious PowerShell and encoded command activity.",
    severity: "high",
    mitreTechniques: ["T1059.001"],
    match: (event) => (event.processName?.toLowerCase() === "powershell.exe" || contains(event.title, "powershell")) && (contains(event.title, "suspicious") || contains(event.title, "encoded") || contains(event.description, "encoded"))
  },
  {
    id: "DET-DATA-EXFILTRATION",
    name: "Potential Data Exfiltration",
    description: "Detects suspicious outbound transfer associated with sensitive data.",
    severity: "critical",
    mitreTechniques: ["T1041", "T1560"],
    match: (event) => event.type === "exfiltration" || contains(event.title, "data", "loss", "prevention") || contains(event.title, "large", "outbound", "transfer")
  },
  {
    id: "DET-MALWARE",
    name: "Malware Detection",
    description: "Detects malware signatures or suspicious executable activity.",
    severity: "critical",
    mitreTechniques: ["T1204.002"],
    match: (event) => event.type === "malware" || contains(event.title, "malware", "signature") || contains(event.title, "suspicious", "executable")
  },
  {
    id: "DET-PRIVILEGE-ESCALATION",
    name: "Privilege Escalation Indicator",
    description: "Detects simulated privilege elevation activity.",
    severity: "high",
    mitreTechniques: ["T1548"],
    match: (event) => event.type === "privilege" || contains(event.title, "privilege", "escalation") || contains(event.description, "elevated", "privileges")
  }
];
function evaluateEvent(event, history = [], rules = DETECTION_RULES) {
  return rules.filter((rule) => rule.match(event)).map((rule) => {
    const related = relatedEvents(event, history);
    const relatedCount = related.length;
    const confidence = confidenceFor(
      event,
      history,
      rule.mitreTechniques[0],
      rule.id === "DET-SSH-BRUTE-FORCE" ? 2 : 0
    );
    const severity = severityWeight[event.severity] > severityWeight[rule.severity] ? event.severity : rule.severity;
    return {
      // Deterministic identity makes retries idempotent: the same rule/event
      // pair always maps to the same database record.
      id: `det-${rule.id}-${event.id}`,
      ruleId: rule.id,
      ruleName: rule.name,
      eventId: event.id,
      timestamp: event.timestamp,
      severity,
      title: rule.name,
      description: `${rule.description}${relatedCount > 0 ? ` ${relatedCount} related event(s) found in the correlation window.` : ""}`,
      confidence,
      mitreTechniques: Array.from(
        /* @__PURE__ */ new Set([...event.mitreTechniques ?? [], ...rule.mitreTechniques])
      ),
      sourceIP: event.sourceIP,
      destinationIP: event.destinationIP
    };
  });
}

// server/security/db.ts
import { Pool } from "pg";
var connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.warn("[J.A.R.V.I.S.] DATABASE_URL is not configured. PostgreSQL persistence is unavailable.");
}
var db = connectionString ? new Pool({
  connectionString,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : void 0,
  max: Number(process.env.DB_POOL_SIZE ?? 10),
  idleTimeoutMillis: 3e4
}) : null;
function requireDb() {
  if (!db) {
    throw new Error("DATABASE_URL is required for the J.A.R.V.I.S. security API.");
  }
  return db;
}
async function initializeSecurityDatabase() {
  const pool = requireDb();
  await pool.query(`
    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      timestamp TIMESTAMPTZ NOT NULL,
      type TEXT NOT NULL,
      source TEXT NOT NULL,
      source_system TEXT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      severity TEXT NOT NULL,
      source_ip INET,
      destination_ip INET,
      source_port INTEGER,
      destination_port INTEGER,
      protocol TEXT,
      hostname TEXT,
      username TEXT,
      process_name TEXT,
      file_path TEXT,
      mitre_techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
      scenario_id TEXT,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events (timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events (source_ip);
    CREATE INDEX IF NOT EXISTS idx_security_events_hostname ON security_events (hostname);

    CREATE TABLE IF NOT EXISTS security_detections (
      id TEXT PRIMARY KEY,
      rule_id TEXT NOT NULL,
      rule_name TEXT NOT NULL,
      event_id TEXT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
      timestamp TIMESTAMPTZ NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      confidence INTEGER NOT NULL,
      mitre_techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
      source_ip INET,
      destination_ip INET,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_security_detections_timestamp ON security_detections (timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_security_detections_event_id ON security_detections (event_id);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_security_detections_rule_event ON security_detections (rule_id, event_id);

    CREATE TABLE IF NOT EXISTS security_incidents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      event_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
      detection_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
      assignee TEXT,
      resolved_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS assignee TEXT;
    ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;

    CREATE INDEX IF NOT EXISTS idx_security_incidents_updated_at ON security_incidents (updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_security_incidents_status ON security_incidents (status);

    CREATE TABLE IF NOT EXISTS security_incident_notes (
      id BIGSERIAL PRIMARY KEY,
      incident_id TEXT NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,
      author TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_security_incident_notes_incident
      ON security_incident_notes (incident_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS security_incident_activity (
      id BIGSERIAL PRIMARY KEY,
      incident_id TEXT NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      actor TEXT NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_security_incident_activity_incident
      ON security_incident_activity (incident_id, created_at DESC);
  `);
  console.log("[J.A.R.V.I.S.] Security database initialized.");
}

// server/security/store.ts
function parseJson(value, fallback) {
  return value === null || value === void 0 ? fallback : value;
}
function mapEvent(row) {
  return {
    id: String(row.id),
    timestamp: new Date(String(row.timestamp)).toISOString(),
    type: row.type,
    source: row.source,
    sourceSystem: row.source_system,
    title: String(row.title),
    description: String(row.description),
    severity: row.severity,
    sourceIP: row.source_ip,
    destinationIP: row.destination_ip,
    sourcePort: row.source_port,
    destinationPort: row.destination_port,
    protocol: row.protocol,
    hostname: row.hostname,
    username: row.username,
    processName: row.process_name,
    filePath: row.file_path,
    mitreTechniques: parseJson(row.mitre_techniques, []),
    scenarioId: row.scenario_id,
    metadata: parseJson(row.metadata, {})
  };
}
function mapDetection(row) {
  return {
    id: String(row.id),
    ruleId: String(row.rule_id),
    ruleName: String(row.rule_name),
    eventId: String(row.event_id),
    timestamp: new Date(String(row.timestamp)).toISOString(),
    severity: row.severity,
    title: String(row.title),
    description: String(row.description),
    confidence: Number(row.confidence),
    mitreTechniques: parseJson(row.mitre_techniques, []),
    sourceIP: row.source_ip,
    destinationIP: row.destination_ip
  };
}
function mapIncident(row) {
  return {
    id: String(row.id),
    title: String(row.title),
    severity: row.severity,
    status: row.status,
    eventIds: parseJson(row.event_ids, []),
    detectionIds: parseJson(row.detection_ids, []),
    assignee: row.assignee,
    resolvedAt: row.resolved_at ? new Date(String(row.resolved_at)).toISOString() : void 0,
    createdAt: new Date(String(row.created_at)).toISOString(),
    updatedAt: new Date(String(row.updated_at)).toISOString()
  };
}
function mapNote(row) {
  return {
    id: String(row.id),
    incidentId: String(row.incident_id),
    author: String(row.author),
    body: String(row.body),
    createdAt: new Date(String(row.created_at)).toISOString()
  };
}
function mapActivity(row) {
  return {
    id: String(row.id),
    incidentId: String(row.incident_id),
    action: String(row.action),
    actor: String(row.actor),
    metadata: parseJson(row.metadata, {}),
    createdAt: new Date(String(row.created_at)).toISOString()
  };
}
async function addEvent(event) {
  const db2 = requireDb();
  await db2.query(
    `INSERT INTO security_events (id, timestamp, type, source, source_system, title, description, severity,
      source_ip, destination_ip, source_port, destination_port, protocol, hostname, username, process_name,
      file_path, mitre_techniques, scenario_id, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
     ON CONFLICT (id) DO NOTHING`,
    [
      event.id,
      event.timestamp,
      event.type,
      event.source,
      event.sourceSystem ?? null,
      event.title,
      event.description,
      event.severity,
      event.sourceIP ?? null,
      event.destinationIP ?? null,
      event.sourcePort ?? null,
      event.destinationPort ?? null,
      event.protocol ?? null,
      event.hostname ?? null,
      event.username ?? null,
      event.processName ?? null,
      event.filePath ?? null,
      JSON.stringify(event.mitreTechniques ?? []),
      event.scenarioId ?? null,
      JSON.stringify(event.metadata ?? {})
    ]
  );
  return event;
}
async function addDetection(detection) {
  const db2 = requireDb();
  await db2.query(
    `INSERT INTO security_detections (id, rule_id, rule_name, event_id, timestamp, severity, title,
      description, confidence, mitre_techniques, source_ip, destination_ip)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (id) DO NOTHING`,
    [
      detection.id,
      detection.ruleId,
      detection.ruleName,
      detection.eventId,
      detection.timestamp,
      detection.severity,
      detection.title,
      detection.description,
      detection.confidence,
      JSON.stringify(detection.mitreTechniques),
      detection.sourceIP ?? null,
      detection.destinationIP ?? null
    ]
  );
  return detection;
}
async function addIncident(incident) {
  const db2 = requireDb();
  await db2.query(
    `INSERT INTO security_incidents (id, title, severity, status, event_ids, detection_ids, assignee, resolved_at, created_at, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     ON CONFLICT (id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, status=EXCLUDED.status,
       event_ids=EXCLUDED.event_ids, detection_ids=EXCLUDED.detection_ids, assignee=EXCLUDED.assignee,
       resolved_at=EXCLUDED.resolved_at, updated_at=EXCLUDED.updated_at`,
    [
      incident.id,
      incident.title,
      incident.severity,
      incident.status,
      JSON.stringify(incident.eventIds),
      JSON.stringify(incident.detectionIds),
      incident.assignee ?? null,
      incident.resolvedAt ?? null,
      incident.createdAt,
      incident.updatedAt
    ]
  );
  return incident;
}
async function addIncidentNote(incidentId, author, body) {
  const db2 = requireDb();
  const result = await db2.query(
    `INSERT INTO security_incident_notes (incident_id, author, body) VALUES ($1,$2,$3) RETURNING *`,
    [incidentId, author, body]
  );
  return mapNote(result.rows[0]);
}
async function addIncidentActivity(incidentId, action, actor2, metadata = {}) {
  const db2 = requireDb();
  const result = await db2.query(
    `INSERT INTO security_incident_activity (incident_id, action, actor, metadata) VALUES ($1,$2,$3,$4) RETURNING *`,
    [incidentId, action, actor2, JSON.stringify(metadata)]
  );
  return mapActivity(result.rows[0]);
}
async function getEvents(limit = 100) {
  const db2 = requireDb();
  const safeLimit = Math.min(Math.max(limit, 1), 1e3);
  const result = await db2.query("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT $1", [safeLimit]);
  return result.rows.map(mapEvent);
}
async function getDetections(limit = 100) {
  const db2 = requireDb();
  const safeLimit = Math.min(Math.max(limit, 1), 500);
  const result = await db2.query("SELECT * FROM security_detections ORDER BY timestamp DESC LIMIT $1", [safeLimit]);
  return result.rows.map(mapDetection);
}
async function getIncidents(limit = 100) {
  const db2 = requireDb();
  const safeLimit = Math.min(Math.max(limit, 1), 500);
  const result = await db2.query("SELECT * FROM security_incidents ORDER BY updated_at DESC LIMIT $1", [safeLimit]);
  return result.rows.map(mapIncident);
}
async function getIncidentById(id) {
  const db2 = requireDb();
  const result = await db2.query("SELECT * FROM security_incidents WHERE id = $1 LIMIT 1", [id]);
  return result.rows.length === 0 ? null : mapIncident(result.rows[0]);
}
async function getIncidentNotes(id) {
  const db2 = requireDb();
  const result = await db2.query("SELECT * FROM security_incident_notes WHERE incident_id = $1 ORDER BY created_at DESC", [id]);
  return result.rows.map(mapNote);
}
async function getIncidentActivity(id) {
  const db2 = requireDb();
  const result = await db2.query("SELECT * FROM security_incident_activity WHERE incident_id = $1 ORDER BY created_at DESC", [id]);
  return result.rows.map(mapActivity);
}
async function getIncidentDetail(id) {
  const db2 = requireDb();
  const incidentResult = await db2.query("SELECT * FROM security_incidents WHERE id = $1 LIMIT 1", [id]);
  if (incidentResult.rows.length === 0) return null;
  const incident = mapIncident(incidentResult.rows[0]);
  const [eventsResult, detectionsResult, notesResult, activityResult] = await Promise.all([
    db2.query("SELECT * FROM security_events WHERE id = ANY($1::text[]) ORDER BY timestamp ASC", [incident.eventIds]),
    db2.query("SELECT * FROM security_detections WHERE id = ANY($1::text[]) ORDER BY timestamp ASC", [incident.detectionIds]),
    db2.query("SELECT * FROM security_incident_notes WHERE incident_id = $1 ORDER BY created_at DESC", [id]),
    db2.query("SELECT * FROM security_incident_activity WHERE incident_id = $1 ORDER BY created_at DESC", [id])
  ]);
  const events = eventsResult.rows.map(mapEvent);
  const detections = detectionsResult.rows.map(mapDetection);
  const notes = notesResult.rows.map(mapNote);
  const activity = activityResult.rows.map(mapActivity);
  const techniqueSet = /* @__PURE__ */ new Set();
  const timeline = [];
  for (const event of events) {
    for (const technique of event.mitreTechniques ?? []) techniqueSet.add(technique);
    timeline.push({
      timestamp: event.timestamp,
      kind: "event",
      id: event.id,
      title: event.title,
      severity: event.severity,
      mitreTechniques: event.mitreTechniques ?? []
    });
  }
  for (const detection of detections) {
    for (const technique of detection.mitreTechniques) techniqueSet.add(technique);
    timeline.push({
      timestamp: detection.timestamp,
      kind: "detection",
      id: detection.id,
      title: detection.title,
      severity: detection.severity,
      mitreTechniques: detection.mitreTechniques
    });
  }
  timeline.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  const confidence = detections.length === 0 ? 0 : Math.min(
    1,
    detections.reduce((sum, detection) => sum + detection.confidence, 0) / detections.length
  );
  const reasons = [`${events.length} related telemetry events`, `${detections.length} detection${detections.length === 1 ? "" : "s"} matched`];
  const sourceIPs = new Set(events.map((event) => event.sourceIP).filter(Boolean));
  const hostnames = new Set(events.map((event) => event.hostname).filter(Boolean));
  const usernames = new Set(events.map((event) => event.username).filter(Boolean));
  if (sourceIPs.size === 1) reasons.push("shared source IP across the event chain");
  if (hostnames.size === 1) reasons.push("shared hostname across the event chain");
  if (usernames.size === 1) reasons.push("shared username across the event chain");
  return {
    incident,
    events,
    detections,
    notes,
    activity,
    attackTechniques: [...techniqueSet],
    timeline,
    correlation: { eventCount: events.length, detectionCount: detections.length, confidence, reasons }
  };
}
async function getDevices() {
  const db2 = requireDb();
  const result = await db2.query("SELECT DISTINCT hostname FROM security_events WHERE hostname IS NOT NULL ORDER BY hostname");
  return result.rows.map((row) => String(row.hostname));
}
async function getSnapshot() {
  const [events, detections, incidents, devices] = await Promise.all([getEvents(), getDetections(), getIncidents(), getDevices()]);
  return { events, detections, incidents, devices, updatedAt: (/* @__PURE__ */ new Date()).toISOString() };
}

// server/security/routes.ts
var router = Router();
var securityEventSchema = z.object({
  id: z.string().min(1),
  timestamp: z.string().datetime(),
  type: z.enum(["authentication", "network", "process", "file", "malware", "privilege", "exfiltration", "dns", "web", "system", "detection"]),
  source: z.enum(["simulation", "suricata", "zeek", "splunk", "endpoint", "firewall", "identity", "manual"]),
  sourceSystem: z.string().optional(),
  title: z.string().min(1).max(300),
  description: z.string().min(1).max(5e3),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
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
  metadata: z.record(z.string(), z.unknown()).optional()
});
var severityRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function highestSeverity(values) {
  return values.reduce((highest, value) => severityRank[value] > severityRank[highest] ? value : highest, "info");
}
function correlationKeys(event) {
  return [event.sourceIP ? `ip:${event.sourceIP}` : null, event.hostname ? `host:${event.hostname}` : null, event.username ? `user:${event.username}` : null, event.scenarioId ? `scenario:${event.scenarioId}` : null].filter((value) => Boolean(value));
}
function shareCorrelationKey(a, b) {
  const keys = new Set(correlationKeys(a));
  return correlationKeys(b).some((key) => keys.has(key));
}
async function createIncidentFromDetection(event, detection) {
  const recentEvents = (await getEvents(1e3)).filter((candidate) => Math.abs(new Date(event.timestamp).getTime() - new Date(candidate.timestamp).getTime()) <= 10 * 60 * 1e3 && shareCorrelationKey(event, candidate));
  if (recentEvents.length < 2) return null;
  const recentEventIds = recentEvents.map((item) => item.id);
  const recentDetections = (await getDetections(500)).filter((item) => recentEventIds.includes(item.eventId));
  if (recentDetections.length === 0) return null;
  const existing = (await getIncidents(500)).find((incident2) => incident2.status !== "resolved" && incident2.eventIds.some((id) => recentEventIds.includes(id)));
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const techniques = Array.from(new Set(recentDetections.flatMap((item) => item.mitreTechniques)));
  const chainLabel = techniques.length > 0 ? ` [${techniques.slice(0, 3).join(" \u2192 ")}]` : "";
  const incident = {
    id: existing?.id ?? `inc-${nanoid(10)}`,
    title: existing?.title ?? `${detection.ruleName} activity detected${chainLabel}`,
    severity: highestSeverity([detection.severity, ...recentDetections.map((item) => item.severity)]),
    status: existing?.status ?? "investigating",
    eventIds: Array.from(/* @__PURE__ */ new Set([...existing?.eventIds ?? [], ...recentEventIds])),
    detectionIds: Array.from(/* @__PURE__ */ new Set([...existing?.detectionIds ?? [], ...recentDetections.map((item) => item.id)])),
    assignee: existing?.assignee,
    resolvedAt: existing?.resolvedAt,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now
  };
  const persisted = await addIncident(incident);
  if (!existing) await addIncidentActivity(persisted.id, "incident_created", "J.A.R.V.I.S.", { severity: persisted.severity, detectionId: detection.id });
  return persisted;
}
router.get("/health", async (_req, res) => res.json({ success: true, data: { service: "jarvis-security-api", status: "online" } }));
router.get("/snapshot", async (_req, res, next) => {
  try {
    res.json({ success: true, data: await getSnapshot() });
  } catch (error) {
    next(error);
  }
});
router.get("/events", async (req, res, next) => {
  try {
    const rawLimit = Number(req.query.limit ?? 100);
    const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(rawLimit, 1e3)) : 100;
    res.json({ success: true, data: await getEvents(limit) });
  } catch (error) {
    next(error);
  }
});
router.post("/events", async (req, res, next) => {
  try {
    const parsed = securityEventSchema.safeParse(req.body?.event ?? req.body);
    if (!parsed.success) return res.status(400).json({ success: false, error: "Invalid security event payload", details: parsed.error.flatten() });
    const event = parsed.data;
    const history = await getEvents(1e3);
    await addEvent(event);
    const detections = evaluateEvent(event, history);
    for (const detection of detections) await addDetection(detection);
    const incidents = [];
    for (const detection of detections) {
      const incident = await createIncidentFromDetection(event, detection);
      if (incident) incidents.push(incident);
    }
    return res.status(201).json({ success: true, data: { event, detections, incidents, ingestionId: nanoid() } });
  } catch (error) {
    next(error);
  }
});
router.get("/detections", async (req, res, next) => {
  try {
    const rawLimit = Number(req.query.limit ?? 100);
    const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(rawLimit, 500)) : 100;
    res.json({ success: true, data: await getDetections(limit) });
  } catch (error) {
    next(error);
  }
});
router.get("/incidents", async (_req, res, next) => {
  try {
    res.json({ success: true, data: await getIncidents() });
  } catch (error) {
    next(error);
  }
});
router.get("/incidents/:id", async (req, res, next) => {
  try {
    const detail = await getIncidentDetail(req.params.id);
    if (!detail) return res.status(404).json({ success: false, error: "Incident not found" });
    return res.json({ success: true, data: detail });
  } catch (error) {
    next(error);
  }
});
router.get("/devices", async (_req, res, next) => {
  try {
    res.json({ success: true, data: await getDevices() });
  } catch (error) {
    next(error);
  }
});
var routes_default = router;

// server/security/incidentRoutes.ts
import { Router as Router2 } from "express";
import { z as z2 } from "zod";

// server/security/incidentLifecycle.ts
function mapIncident2(row) {
  return {
    id: String(row.id),
    title: String(row.title),
    severity: row.severity,
    status: row.status,
    eventIds: row.event_ids ?? [],
    detectionIds: row.detection_ids ?? [],
    assignee: row.assignee,
    resolvedAt: row.resolved_at ? new Date(String(row.resolved_at)).toISOString() : void 0,
    createdAt: new Date(String(row.created_at)).toISOString(),
    updatedAt: new Date(String(row.updated_at)).toISOString()
  };
}
async function updateIncidentStatus(id, status, actor2 = "SOC Analyst") {
  const db2 = requireDb();
  const result = await db2.query(
    `UPDATE security_incidents
     SET status = $2,
         resolved_at = CASE WHEN $2 = 'resolved' THEN NOW() ELSE NULL END,
         updated_at = NOW()
     WHERE id = $1
     RETURNING *`,
    [id, status]
  );
  if (result.rows.length === 0) return null;
  const incident = mapIncident2(result.rows[0]);
  await addIncidentActivity(id, `status_changed:${status}`, actor2, { status });
  return incident;
}
async function updateIncidentAssignee(id, assignee, actor2 = "SOC Analyst") {
  const db2 = requireDb();
  const result = await db2.query(
    `UPDATE security_incidents SET assignee = $2, updated_at = NOW() WHERE id = $1 RETURNING *`,
    [id, assignee]
  );
  if (result.rows.length === 0) return null;
  const incident = mapIncident2(result.rows[0]);
  await addIncidentActivity(id, "assignee_changed", actor2, { assignee });
  return incident;
}

// server/security/incidentRoutes.ts
var router2 = Router2();
var statusSchema = z2.object({ status: z2.enum(["open", "investigating", "resolved"]) });
var assigneeSchema = z2.object({ assignee: z2.string().trim().min(1).max(120) });
var noteSchema = z2.object({ body: z2.string().trim().min(1).max(5e3) });
function actor(req) {
  const header = req.header("x-jarvis-actor");
  return header?.trim().slice(0, 120) || "SOC Analyst";
}
async function ensureIncident(id) {
  return Boolean(await getIncidentById(id));
}
router2.patch("/incidents/:id/status", async (req, res, next) => {
  try {
    const parsed = statusSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ success: false, error: "Invalid incident status" });
    if (!await ensureIncident(req.params.id)) return res.status(404).json({ success: false, error: "Incident not found" });
    const incident = await updateIncidentStatus(req.params.id, parsed.data.status, actor(req));
    return res.json({ success: true, data: incident });
  } catch (error) {
    next(error);
  }
});
router2.patch("/incidents/:id/assignee", async (req, res, next) => {
  try {
    const parsed = assigneeSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ success: false, error: "Invalid assignee" });
    if (!await ensureIncident(req.params.id)) return res.status(404).json({ success: false, error: "Incident not found" });
    const incident = await updateIncidentAssignee(req.params.id, parsed.data.assignee, actor(req));
    return res.json({ success: true, data: incident });
  } catch (error) {
    next(error);
  }
});
router2.post("/incidents/:id/notes", async (req, res, next) => {
  try {
    const parsed = noteSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ success: false, error: "Note body is required" });
    if (!await ensureIncident(req.params.id)) return res.status(404).json({ success: false, error: "Incident not found" });
    const note = await addIncidentNote(req.params.id, actor(req), parsed.data.body);
    await addIncidentActivity(req.params.id, "note_added", actor(req), { noteId: note.id });
    return res.status(201).json({ success: true, data: note });
  } catch (error) {
    next(error);
  }
});
router2.get("/incidents/:id/notes", async (req, res, next) => {
  try {
    if (!await ensureIncident(req.params.id)) return res.status(404).json({ success: false, error: "Incident not found" });
    return res.json({ success: true, data: await getIncidentNotes(req.params.id) });
  } catch (error) {
    next(error);
  }
});
router2.get("/incidents/:id/activity", async (req, res, next) => {
  try {
    if (!await ensureIncident(req.params.id)) return res.status(404).json({ success: false, error: "Incident not found" });
    return res.json({ success: true, data: await getIncidentActivity(req.params.id) });
  } catch (error) {
    next(error);
  }
});
var incidentRoutes_default = router2;

// server/index.ts
var app = express();
var server = createServer(app);
app.disable("x-powered-by");
app.use(cors({ origin: process.env.FRONTEND_ORIGIN?.split(",") ?? true }));
app.use(express.json({ limit: "256kb" }));
app.get("/api/health", async (_req, res) => {
  if (!db) {
    return res.status(503).json({
      success: false,
      service: "jarvis-api",
      status: "database_not_configured"
    });
  }
  try {
    await db.query("SELECT 1");
    return res.json({
      success: true,
      service: "jarvis-api",
      status: "online",
      database: "connected"
    });
  } catch {
    return res.status(503).json({
      success: false,
      service: "jarvis-api",
      status: "database_unavailable"
    });
  }
});
app.use("/api/security", routes_default);
app.use("/api/security", incidentRoutes_default);
var port = Number(process.env.PORT ?? 3001);
async function start() {
  await initializeSecurityDatabase();
  server.listen(port, "0.0.0.0", () => {
    console.log(`J.A.R.V.I.S. API running on port ${port}`);
  });
}
start().catch((error) => {
  console.error("[J.A.R.V.I.S.] API startup failed:", error);
  process.exit(1);
});
