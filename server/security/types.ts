import type { SecurityEvent, SecurityIncident } from "../../client/src/security/types";

export interface IngestSecurityEventRequest {
  event: SecurityEvent;
}

export interface SecurityApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface SecuritySnapshot {
  events: SecurityEvent[];
  incidents: SecurityIncident[];
  devices: string[];
  updatedAt: string;
}
