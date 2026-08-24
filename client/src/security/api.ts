import type {
  DetectionResult,
  SecurityEvent,
  SecurityIncident,
} from './types';

const API_BASE_URL = (import.meta.env.VITE_API_URL ?? '').replace(/\/$/, '');

export type SecurityIncidentStatus = 'open' | 'investigating' | 'resolved';

export interface SecurityApiHealth {
  success: boolean;
  service: string;
  status: string;
  database?: string;
}

export interface SecurityIncidentDetail {
  incident: SecurityIncident;
  events: SecurityEvent[];
  detections: DetectionResult[];
  attackTechniques: string[];
  timeline: Array<{
    timestamp: string;
    kind: 'event' | 'detection';
    id: string;
    title: string;
    severity: SecurityIncident['severity'];
    mitreTechniques: string[];
  }>;
  correlation: {
    eventCount: number;
    detectionCount: number;
    confidence: number;
    reasons: string[];
  };
}

export interface SecuritySnapshot {
  events: SecurityEvent[];
  detections: DetectionResult[];
  incidents: SecurityIncident[];
  devices: string[];
  updatedAt: string;
}

interface ApiEnvelope<T> {
  success: boolean;
  data: T;
  error?: string;
}

interface IngestResponse {
  event: SecurityEvent;
  detections: DetectionResult[];
  incidents: SecurityIncident[];
  ingestionId: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });

  const payload = (await response.json().catch(() => null)) as
    | ApiEnvelope<T>
    | { error?: string }
    | null;

  if (!response.ok) {
    throw new Error(payload?.error || `J.A.R.V.I.S. API request failed (${response.status})`);
  }

  if (!payload || !('success' in payload) || !payload.success || !('data' in payload)) {
    throw new Error('J.A.R.V.I.S. API returned an invalid response');
  }

  return payload.data;
}

export const securityApi = {
  health: () => request<SecurityApiHealth>('/api/security/health'),
  snapshot: () => request<SecuritySnapshot>('/api/security/snapshot'),
  events: () => request<SecurityEvent[]>('/api/security/events'),
  detections: () => request<DetectionResult[]>('/api/security/detections'),
  incidents: () => request<SecurityIncident[]>('/api/security/incidents'),
  incidentDetail: (id: string) =>
    request<SecurityIncidentDetail>(`/api/security/incidents/${encodeURIComponent(id)}`),
  updateIncidentStatus: (id: string, status: SecurityIncidentStatus) =>
    request<SecurityIncident>(`/api/security/incidents/${encodeURIComponent(id)}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
  ingestEvent: (event: SecurityEvent) =>
    request<IngestResponse>('/api/security/events', {
      method: 'POST',
      body: JSON.stringify(event),
    }),
};

export function isApiConfigured(): boolean {
  return Boolean(API_BASE_URL);
}
