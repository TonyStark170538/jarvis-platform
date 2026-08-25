import { requireDb } from './db';
import { addIncidentActivity, getIncidentById } from './store';
import type { SecurityIncident, SecurityIncidentStatus } from './types';

function mapIncident(row: Record<string, unknown>): SecurityIncident {
  return {
    id: String(row.id),
    title: String(row.title),
    severity: row.severity as SecurityIncident['severity'],
    status: row.status as SecurityIncident['status'],
    eventIds: (row.event_ids ?? []) as string[],
    detectionIds: (row.detection_ids ?? []) as string[],
    assignee: row.assignee as string | undefined,
    resolvedAt: row.resolved_at ? new Date(String(row.resolved_at)).toISOString() : undefined,
    createdAt: new Date(String(row.created_at)).toISOString(),
    updatedAt: new Date(String(row.updated_at)).toISOString(),
  };
}

export async function updateIncidentStatus(
  id: string,
  status: SecurityIncidentStatus,
  actor = 'SOC Analyst'
): Promise<SecurityIncident | null> {
  const db = requireDb();
  const result = await db.query(
    `UPDATE security_incidents
     SET status = $2,
         resolved_at = CASE WHEN $2 = 'resolved' THEN NOW() ELSE NULL END,
         updated_at = NOW()
     WHERE id = $1
     RETURNING *`,
    [id, status]
  );

  if (result.rows.length === 0) return null;
  const incident = mapIncident(result.rows[0]);
  await addIncidentActivity(id, `status_changed:${status}`, actor, { status });
  return incident;
}

export async function updateIncidentAssignee(
  id: string,
  assignee: string,
  actor = 'SOC Analyst'
): Promise<SecurityIncident | null> {
  const db = requireDb();
  const result = await db.query(
    `UPDATE security_incidents SET assignee = $2, updated_at = NOW() WHERE id = $1 RETURNING *`,
    [id, assignee]
  );

  if (result.rows.length === 0) return null;
  const incident = mapIncident(result.rows[0]);
  await addIncidentActivity(id, 'assignee_changed', actor, { assignee });
  return incident;
}

export async function touchIncident(id: string): Promise<void> {
  const incident = await getIncidentById(id);
  if (!incident) return;
  await requireDb().query('UPDATE security_incidents SET updated_at = NOW() WHERE id = $1', [id]);
}
