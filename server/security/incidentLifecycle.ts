import { requireDb } from './db';
import type { SecurityIncident } from './types';

function mapIncident(row: Record<string, unknown>): SecurityIncident {
  return {
    id: String(row.id),
    title: String(row.title),
    severity: row.severity as SecurityIncident['severity'],
    status: row.status as SecurityIncident['status'],
    eventIds: (row.event_ids ?? []) as string[],
    detectionIds: (row.detection_ids ?? []) as string[],
    createdAt: new Date(String(row.created_at)).toISOString(),
    updatedAt: new Date(String(row.updated_at)).toISOString(),
  };
}

export async function updateIncidentStatus(
  id: string,
  status: SecurityIncident['status']
): Promise<SecurityIncident | null> {
  const db = requireDb();
  const result = await db.query(
    `UPDATE security_incidents
     SET status = $2, updated_at = NOW()
     WHERE id = $1
     RETURNING *`,
    [id, status]
  );

  return result.rows.length === 0 ? null : mapIncident(result.rows[0]);
}
