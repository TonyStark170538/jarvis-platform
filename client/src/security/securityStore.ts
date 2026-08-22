import { generateScenario, getAttackScenario } from './eventGenerator';
import { evaluateEvent } from './detectionEngine';
import type {
  DetectionResult,
  ScenarioRun,
  SecurityEvent,
  SecurityStoreListener,
  SecurityStoreSnapshot,
} from './types';

const MAX_EVENTS = 500;
const MAX_DETECTIONS = 250;
const MAX_RUNS = 50;

function createId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

/**
 * In-memory event bus for the J.A.R.V.I.S. security simulation.
 *
 * React components can subscribe to this store without introducing another
 * state-management dependency. A backend/WebSocket adapter can later feed
 * the same ingestEvent() API without changing the UI contract.
 */
export class SecurityStore {
  private events: SecurityEvent[] = [];
  private detections: DetectionResult[] = [];
  private runs: ScenarioRun[] = [];
  private listeners = new Set<SecurityStoreListener>();
  private activeController: AbortController | null = null;
  private simulationRunning = false;

  getSnapshot(): SecurityStoreSnapshot {
    return {
      events: [...this.events],
      detections: [...this.detections],
      runs: [...this.runs],
      isSimulationRunning: this.simulationRunning,
    };
  }

  subscribe(listener: SecurityStoreListener): () => void {
    this.listeners.add(listener);
    listener(this.getSnapshot());
    return () => this.listeners.delete(listener);
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
      if (!existingKeys.has(key)) {
        this.detections.unshift(detection);
      }
    }

    this.detections = this.detections.slice(0, MAX_DETECTIONS);
    this.emit();

    return newDetections;
  }

  ingestEvents(events: SecurityEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];
    for (const event of events) {
      detections.push(...this.ingestEvent(event));
    }
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
      if (!isAbortError(error)) {
        throw error;
      }

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
    this.runs = [];
    this.emit();
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
