import type { SecurityEvent, SecurityIncident } from "../../client/src/security/types";

const events: SecurityEvent[] = [];
const incidents: SecurityIncident[] = [];

export function addEvent(event: SecurityEvent): SecurityEvent {
  events.unshift(event);
  if (events.length > 1000) events.length = 1000;
  return event;
}

export function getEvents(limit = 100): SecurityEvent[] {
  return events.slice(0, Math.min(limit, 1000));
}

export function addIncident(incident: SecurityIncident): SecurityIncident {
  incidents.unshift(incident);
  if (incidents.length > 500) incidents.length = 500;
  return incident;
}

export function getIncidents(limit = 100): SecurityIncident[] {
  return incidents.slice(0, Math.min(limit, 500));
}

export function getDevices(): string[] {
  return [...new Set(events.map((event) => event.hostname).filter(Boolean) as string[])];
}

export function getSnapshot() {
  return {
    events: getEvents(),
    incidents: getIncidents(),
    devices: getDevices(),
    updatedAt: new Date().toISOString(),
  };
}
