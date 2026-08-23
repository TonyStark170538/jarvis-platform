import type {
  SecurityDetection,
  SecurityEvent,
  SecurityIncident,
  SecuritySnapshot,
} from './types';

const MAX_EVENTS = 1000;
const MAX_DETECTIONS = 500;
const MAX_INCIDENTS = 500;

const events: SecurityEvent[] = [];
const detections: SecurityDetection[] = [];
const incidents: SecurityIncident[] = [];

export function addEvent(event: SecurityEvent): SecurityEvent {
  events.unshift(event);
  if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
  return event;
}

export function addDetection(detection: SecurityDetection): SecurityDetection {
  detections.unshift(detection);
  if (detections.length > MAX_DETECTIONS) detections.length = MAX_DETECTIONS;
  return detection;
}

export function addIncident(incident: SecurityIncident): SecurityIncident {
  incidents.unshift(incident);
  if (incidents.length > MAX_INCIDENTS) incidents.length = MAX_INCIDENTS;
  return incident;
}

export function getEvents(limit = 100): SecurityEvent[] {
  return events.slice(0, Math.min(Math.max(limit, 1), MAX_EVENTS));
}

export function getDetections(limit = 100): SecurityDetection[] {
  return detections.slice(0, Math.min(Math.max(limit, 1), MAX_DETECTIONS));
}

export function getIncidents(limit = 100): SecurityIncident[] {
  return incidents.slice(0, Math.min(Math.max(limit, 1), MAX_INCIDENTS));
}

export function getDevices(): string[] {
  return [...new Set(events.map((event) => event.hostname).filter(Boolean) as string[])];
}

export function getSnapshot(): SecuritySnapshot {
  return {
    events: getEvents(),
    detections: getDetections(),
    incidents: getIncidents(),
    devices: getDevices(),
    updatedAt: new Date().toISOString(),
  };
}
