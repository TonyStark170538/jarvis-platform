import { Pool } from 'pg';

const connectionString = process.env.DATABASE_URL;

if (!connectionString) console.warn('[J.A.R.V.I.S.] DATABASE_URL is not configured. PostgreSQL persistence is unavailable.');

export const db = connectionString ? new Pool({ connectionString, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined, max: Number(process.env.DB_POOL_SIZE ?? 10), idleTimeoutMillis: 30_000 }) : null;

export function requireDb(): Pool {
  if (!db) throw new Error('DATABASE_URL is required for the J.A.R.V.I.S. security API.');
  return db;
}

export async function initializeSecurityDatabase(): Promise<void> {
  const pool = requireDb();
  await pool.query(`
    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY, timestamp TIMESTAMPTZ NOT NULL, type TEXT NOT NULL, source TEXT NOT NULL,
      source_system TEXT, title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL,
      source_ip INET, destination_ip INET, source_port INTEGER, destination_port INTEGER, protocol TEXT,
      hostname TEXT, username TEXT, process_name TEXT, file_path TEXT, mitre_techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
      scenario_id TEXT, metadata JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events (timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events (source_ip);
    CREATE INDEX IF NOT EXISTS idx_security_events_hostname ON security_events (hostname);

    CREATE TABLE IF NOT EXISTS security_detections (
      id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, rule_name TEXT NOT NULL, event_id TEXT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
      timestamp TIMESTAMPTZ NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, confidence INTEGER NOT NULL,
      mitre_techniques JSONB NOT NULL DEFAULT '[]'::jsonb, source_ip INET, destination_ip INET, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_security_detections_timestamp ON security_detections (timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_security_detections_event_id ON security_detections (event_id);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_security_detections_rule_event ON security_detections (rule_id, event_id);

    CREATE TABLE IF NOT EXISTS security_incidents (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
      event_ids JSONB NOT NULL DEFAULT '[]'::jsonb, detection_ids JSONB NOT NULL DEFAULT '[]'::jsonb, assignee TEXT,
      resolved_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS assignee TEXT;
    ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;
    CREATE INDEX IF NOT EXISTS idx_security_incidents_updated_at ON security_incidents (updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_security_incidents_status ON security_incidents (status);

    CREATE TABLE IF NOT EXISTS security_incident_notes (
      id BIGSERIAL PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,
      author TEXT NOT NULL, body TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_security_incident_notes_incident ON security_incident_notes (incident_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS security_incident_activity (
      id BIGSERIAL PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,
      action TEXT NOT NULL, actor TEXT NOT NULL, metadata JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_security_incident_activity_incident ON security_incident_activity (incident_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS security_iocs (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL CHECK (type IN ('ip','domain','hash','url')),
      value TEXT NOT NULL,
      severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
      source TEXT NOT NULL DEFAULT 'SOC Analyst',
      tags JSONB NOT NULL DEFAULT '[]'::jsonb,
      confidence INTEGER NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(type, value)
    );
    CREATE INDEX IF NOT EXISTS idx_security_iocs_type ON security_iocs(type);
    CREATE INDEX IF NOT EXISTS idx_security_iocs_severity ON security_iocs(severity);
    CREATE INDEX IF NOT EXISTS idx_security_iocs_updated_at ON security_iocs(updated_at DESC);
  `);
  console.log('[J.A.R.V.I.S.] Security database initialized.');
}
