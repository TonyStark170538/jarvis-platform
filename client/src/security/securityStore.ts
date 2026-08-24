import { createSecurityIncidentThreads } from '@/lib/incidentCorrelation';
import { generateScenario, getAttackScenario } from './eventGenerator';
import { evaluateEvent } from './detectionEngine';
import { securityApi } from './api';
import type {
  DetectionResult,
  ScenarioRun,
  SecurityEvent,
  SecurityIncidentThread,
  SecurityStoreListener,
  SecurityStoreSnapshot,
} from './types';

const MAX_EVENTS = 500;
const MAX_DETECTIONS = 250;
const MAX_RUNS = 50;
const MAX_INCIDENT_THREADS = 100;
const BACKEND_POLL_INTERVAL_MS = 10_000;

function createId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

/**
 * Browser-side security event bus.
 *
 * The Attack Lab can still run local simulations, but persisted security data
 * is hydrated from and periodically synchronized with the Render API.
 */
export class SecurityStore {
  private events: SecurityEvent[] = [];
  private detections: DetectionResult[] = [];
  private incidentThreads: SecurityIncidentThread[] = [];
  private runs: ScenarioRun[] = [];
  private listeners = new Set<SecurityStoreListener>();
  private activeController: AbortController | null = null;
  private pollingTimer: ReturnType<typeof setInterval> | null = null;
  private simulationRunning = false;
  private backendOnline = false;

  getSnapshot(): SecurityStoreSnapshot {
    return {
      events: [...this.events],
      detections: [...this.detections],
      incidentThreads: [...this.incidentThreads],
      runs: [...this.runs],
      isSimulationRunning: this.simulationRunning,
      backendOnline: this.backendOnline,
    };
  }

  subscribe(listener: SecurityStoreListener): () => void {
    this.listeners.add(listener);
    listener(this.getSnapshot());
    return () => this.listeners.delete(listener);
  }

  async connectBackend(): Promise<boolean> {
    try {
      await securityApi.health();
      await this.hydrateFromBackend();
      this.backendOnline = true;
      this.emit();
      return true;
    } catch {
      this.backendOnline = false;
      this.emit();
      return false;
    }
  }

  startBackendPolling(): void {
    if (this.pollingTimer) return;

    void this.connectBackend();
    this.pollingTimer = setInterval(() => {
      void this.hydrateFromBackend();
    }, BACKEND_POLL_INTERVAL_MS);
  }

  stopBackendPolling(): void {
    if (!this.pollingTimer) return;
    clearInterval(this.pollingTimer);
    this.pollingTimer = null;
  }

  async hydrateFromBackend(): Promise<void> {
    try {
      const snapshot = await securityApi.snapshot();

      this.events = snapshot.events.slice(0, MAX_EVENTS);
      this.detections = snapshot.detections.slice(0, MAX_DETECTIONS);
      this.incidentThreads = snapshot.incidents.slice(0, MAX_INCIDENT_THREADS);
      this.backendOnline = true;
      this.emit();
    } catch {
      this.backendOnline = false;
      this.emit();
    }
  }

  ingestEvent(event: SecurityEvent): DetectionResult[] {
    this.events = [event, ...this.events.filter((existing) => existing.id !== event.id)].slice(
      0,
      MAX_EVENTS
    );

    const newDetections = evaluateEvent(event, this.events);
    const existingKeys = new Set(
      this.detections.map((detection) => `${detection.ruleId}:${detection.eventId}`)
    );

    for (const detection of newDetections) {
      const key = `${detection.ruleId}:${detection.eventId}`;
      if (!existingKeys.has(key)) this.detections.unshift(detection);
    }

    this.detections = this.detections.slice(0, MAX_DETECTIONS);
    this.rebuildIncidentThreads();
    this.emit();

    void securityApi
      .ingestEvent(event)
      .then(() => {
        this.backendOnline = true;
        void this.hydrateFromBackend();
      })
      .catch(() => {
        this.backendOnline = false;
        this.emit();
      });

    return newDetections;
  }

  ingestEvents(events: SecurityEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];
    for (const event of events) detections.push(...this.ingestEvent(event));
    return detections;
  }

  async runScenario(scenarioId: string): Promise<ScenarioRun> {
    if (this.simulationRunning) {
      throw new Error('A security simulation is already running. Stop it before starting another.');
    }

    if (!getAttackScenario(scenarioId)) {
      throw new Error(`Unknown attack scenario: ${scenarioId}`);
    }

    const controller = new AbortController();
    this.activeController = controller;
    this.simulationRunning = true;

    const run: ScenarioRun = {
      id: createId('run'),
      scenarioId,
      startedAt: new Date().toISOString(),
      eventIds: [],
    };

    this.runs = [run, ...this.runs].slice(0, MAX_RUNS);
    this.emit();

    try {
      await generateScenario({
        scenarioId,
        signal: controller.signal,
        onEvent: (event) => {
          run.eventIds.push(event.id);
          this.ingestEvent(event);
        },
      });

      run.completedAt = new Date().toISOString();
      this.replaceRun(run);
      return { ...run, eventIds: [...run.eventIds] };
    } catch (error) {
      if (!isAbortError(error)) throw error;

      run.completedAt = new Date().toISOString();
      this.replaceRun(run);
      return { ...run, eventIds: [...run.eventIds] };
    } finally {
      if (this.activeController === controller) {
        this.activeController = null;
        this.simulationRunning = false;
        this.emit();
      }
    }
  }

  stopSimulation(): void {
    this.activeController?.abort();
  }

  clearEvents(): void {
    this.events = [];
    this.detections = [];
    this.incidentThreads = [];
    this.emit();
  }

  clearRuns(): void {
    this.runs = [];
    this.emit();
  }

  reset(): void {
    this.stopSimulation();
    this.events = [];
    this.detections = [];
    this.incidentThreads = [];
    this.runs = [];
    this.emit();
  }

  private rebuildLocalAnalysis(): void {
    this.detections = [];
    for (const event of [...this.events].reverse()) {
      const detections = evaluateEvent(event, this.events);
      const existingKeys = new Set(
        this.detections.map((detection) => `${detection.ruleId}:${detection.eventId}`)
      );
      for (const detection of detections) {
        const key = `${detection.ruleId}:${detection.eventId}`;
        if (!existingKeys.has(key)) this.detections.push(detection);
      }
    }
    this.detections = this.detections.slice(0, MAX_DETECTIONS);
    this.rebuildIncidentThreads();
  }

  private rebuildIncidentThreads(): void {
    this.incidentThreads = createSecurityIncidentThreads(this.events).slice(
      0,
      MAX_INCIDENT_THREADS
    );
  }

  private replaceRun(run: ScenarioRun): void {
    this.runs = this.runs.map((existing) =>
      existing.id === run.id ? { ...run, eventIds: [...run.eventIds] } : existing
    );
    this.emit();
  }

  private emit(): void {
    const snapshot = this.getSnapshot();
    this.listeners.forEach((listener) => listener(snapshot));
  }
}

/** Shared browser-side security event store. */
export const securityStore = new SecurityStore();
