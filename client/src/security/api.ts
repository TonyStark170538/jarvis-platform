import type { SecurityEvent } from './types';

const API_BASE_URL = (import.meta.env.VITE_API_URL ?? '').replace(/\/$/, '');

export interface SecurityApiHealth {
  success: boolean;
  service: string;
  status: string;
}

export interface SecuritySnapshot {
  events: SecurityEvent[];
  incidents: unknown[];
  devices: unknown[];
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    const message = await response.text().catch(() => '');
    throw new Error(message || `J.A.R.V.I.S. API request failed (${response.status})`);
  }

  return response.json() as Promise<T>;
}

export const securityApi = {
  health: () => request<SecurityApiHealth>('/api/security/health'),

  snapshot: () => request<SecuritySnapshot>('/api/security/snapshot'),

  events: () => request<SecurityEvent[]>('/api/security/events'),

  ingestEvent: (event: SecurityEvent) =>
    request<{ success: boolean; event: SecurityEvent; detections: unknown[] }>(
      '/api/security/events',
      {
        method: 'POST',
        body: JSON.stringify(event),
      }
    ),
};

export function isApiConfigured(): boolean {
  return Boolean(API_BASE_URL);
}
