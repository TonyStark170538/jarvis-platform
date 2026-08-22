import type {
  AttackScenario,
  SecurityEvent,
  SecurityEventType,
  SecuritySeverity,
} from './types';

const DEFAULT_SOURCE_IP = '203.0.113.45';
const DEFAULT_TARGET_IP = '10.0.0.10';
const DEFAULT_HOSTNAME = 'prod-server-01';

function createId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function event(
  type: SecurityEventType,
  title: string,
  description: string,
  severity: SecuritySeverity,
  extra: Omit<SecurityEvent, 'id' | 'timestamp' | 'type' | 'title' | 'description' | 'severity' | 'source'> = {}
) {
  return {
    type,
    title,
    description,
    severity,
    source: 'simulation' as const,
    ...extra,
  };
}

/**
 * Built-in scenarios are intentionally simulations. They generate telemetry
 * only; they never open sockets, execute commands, scan networks, or modify
 * the host running the application.
 */
export const ATTACK_SCENARIOS: AttackScenario[] = [
  {
    id: 'ssh-brute-force',
    name: 'SSH Brute Force',
    description: 'Simulates repeated SSH authentication failures followed by a port scan.',
    category: 'Initial Access',
    mitreTechniques: ['T1110', 'T1046'],
    events: [
      { offsetMs: 0, event: event('authentication', 'SSH connection attempt', 'Inbound SSH connection from an external source.', 'low', { sourceIP: DEFAULT_SOURCE_IP, destinationIP: DEFAULT_TARGET_IP, destinationPort: 22, protocol: 'TCP', hostname: DEFAULT_HOSTNAME }) },
      { offsetMs: 900, event: event('authentication', 'SSH authentication failure', 'Invalid credentials supplied for the administrator account.', 'medium', { sourceIP: DEFAULT_SOURCE_IP, destinationIP: DEFAULT_TARGET_IP, destinationPort: 22, protocol: 'TCP', hostname: DEFAULT_HOSTNAME, username: 'admin', mitreTechniques: ['T1110'] }) },
      { offsetMs: 1800, event: event('authentication', 'SSH authentication failure', 'Second failed SSH authentication attempt from the same source.', 'medium', { sourceIP: DEFAULT_SOURCE_IP, destinationIP: DEFAULT_TARGET_IP, destinationPort: 22, protocol: 'TCP', hostname: DEFAULT_HOSTNAME, username: 'admin', mitreTechniques: ['T1110'] }) },
      { offsetMs: 2700, event: event('authentication', 'SSH authentication failure', 'Third failed SSH authentication attempt from the same source.', 'high', { sourceIP: DEFAULT_SOURCE_IP, destinationIP: DEFAULT_TARGET_IP, destinationPort: 22, protocol: 'TCP', hostname: DEFAULT_HOSTNAME, username: 'admin', mitreTechniques: ['T1110'] }) },
      { offsetMs: 4200, event: event('network', 'Port scan detected', 'Multiple TCP ports were probed on the target host after authentication failures.', 'high', { sourceIP: DEFAULT_SOURCE_IP, destinationIP: DEFAULT_TARGET_IP, protocol: 'TCP', hostname: DEFAULT_HOSTNAME, mitreTechniques: ['T1046'] }) },
      { offsetMs: 5600, event: event('authentication', 'Account protection triggered', 'The simulated account protection policy temporarily locked the targeted account.', 'high', { sourceIP: DEFAULT_SOURCE_IP, destinationIP: DEFAULT_TARGET_IP, destinationPort: 22, hostname: DEFAULT_HOSTNAME, username: 'admin', mitreTechniques: ['T1110'] }) },
    ],
  },
  {
    id: 'powershell-execution',
    name: 'Suspicious PowerShell Execution',
    description: 'Simulates an encoded PowerShell process followed by a persistence indicator.',
    category: 'Execution',
    mitreTechniques: ['T1059.001', 'T1053.005'],
    events: [
      { offsetMs: 0, event: event('process', 'PowerShell process created', 'PowerShell started with a suspicious command-line pattern.', 'medium', { hostname: 'workstation-07', username: 'analyst', processName: 'powershell.exe', mitreTechniques: ['T1059.001'] }) },
      { offsetMs: 1100, event: event('process', 'Encoded PowerShell command detected', 'The simulated command line contains an encoded payload indicator.', 'high', { hostname: 'workstation-07', username: 'analyst', processName: 'powershell.exe', mitreTechniques: ['T1059.001'] }) },
      { offsetMs: 2300, event: event('network', 'PowerShell outbound connection', 'PowerShell initiated an outbound HTTPS connection to an untrusted test endpoint.', 'high', { hostname: 'workstation-07', username: 'analyst', processName: 'powershell.exe', destinationIP: '198.51.100.25', destinationPort: 443, protocol: 'TCP', mitreTechniques: ['T1059.001'] }) },
      { offsetMs: 3900, event: event('system', 'Scheduled task persistence indicator', 'A simulated scheduled-task creation event was observed.', 'high', { hostname: 'workstation-07', username: 'analyst', processName: 'schtasks.exe', mitreTechniques: ['T1053.005'] }) },
    ],
  },
  {
    id: 'data-exfiltration',
    name: 'Data Exfiltration',
    description: 'Simulates unusual archive creation and a large outbound transfer.',
    category: 'Exfiltration',
    mitreTechniques: ['T1560', 'T1041'],
    events: [
      { offsetMs: 0, event: event('file', 'Sensitive archive created', 'A large archive containing simulated sensitive files was created.', 'medium', { hostname: 'db-server-01', username: 'svc-backup', filePath: '/tmp/customer-data.tar.gz', mitreTechniques: ['T1560'] }) },
      { offsetMs: 1400, event: event('network', 'Large outbound transfer', 'An unusually large outbound transfer was detected from the database host.', 'high', { hostname: 'db-server-01', sourceIP: '10.0.0.20', destinationIP: '198.51.100.50', destinationPort: 443, protocol: 'TCP', mitreTechniques: ['T1041'] }) },
      { offsetMs: 3000, event: event('exfiltration', 'External destination anomaly', 'The destination is not present in the simulated approved transfer list.', 'high', { hostname: 'db-server-01', sourceIP: '10.0.0.20', destinationIP: '198.51.100.50', destinationPort: 443, protocol: 'TCP', mitreTechniques: ['T1041'] }) },
      { offsetMs: 4600, event: event('detection', 'Data loss prevention alert', 'A simulated DLP rule flagged the transfer for investigation.', 'critical', { hostname: 'db-server-01', sourceIP: '10.0.0.20', destinationIP: '198.51.100.50', mitreTechniques: ['T1041'] }) },
    ],
  },
  {
    id: 'malware-detection',
    name: 'Malware Detection',
    description: 'Simulates a file detection, process execution, and endpoint isolation signal.',
    category: 'Malware',
    mitreTechniques: ['T1204.002', 'T1059'],
    events: [
      { offsetMs: 0, event: event('file', 'Suspicious executable detected', 'A simulated endpoint scanner identified a known test malware signature.', 'high', { hostname: 'workstation-12', filePath: 'C:\\Users\\Public\\invoice-update.exe', mitreTechniques: ['T1204.002'] }) },
      { offsetMs: 1000, event: event('malware', 'Malware signature confirmed', 'The simulated file matched a known malicious signature.', 'critical', { hostname: 'workstation-12', processName: 'invoice-update.exe', mitreTechniques: ['T1204.002'] }) },
      { offsetMs: 2200, event: event('process', 'Suspicious process execution', 'The detected executable attempted to start a child process.', 'critical', { hostname: 'workstation-12', processName: 'invoice-update.exe', mitreTechniques: ['T1059'] }) },
      { offsetMs: 3800, event: event('system', 'Endpoint isolation triggered', 'The simulated EDR policy isolated the endpoint from the lab network.', 'critical', { hostname: 'workstation-12', mitreTechniques: ['T1204.002'] }) },
    ],
  },
];

export function getAttackScenario(scenarioId: string): AttackScenario | undefined {
  return ATTACK_SCENARIOS.find((scenario) => scenario.id === scenarioId);
}

export function createSimulatedEvent(
  template: AttackScenario['events'][number]['event'],
  scenarioId: string,
  timestamp = new Date().toISOString()
): SecurityEvent {
  return {
    ...template,
    id: createId('evt'),
    timestamp,
    scenarioId,
  };
}

export interface ScenarioGenerationOptions {
  scenarioId: string;
  /** Delay between generated events. Defaults to the scenario's offsets. */
  onEvent?: (event: SecurityEvent) => void;
  signal?: AbortSignal;
}

/**
 * Generate one scenario as a stream of telemetry events.
 * This is the bridge Attack Lab will use later.
 */
export async function generateScenario({
  scenarioId,
  onEvent,
  signal,
}: ScenarioGenerationOptions): Promise<SecurityEvent[]> {
  const scenario = getAttackScenario(scenarioId);
  if (!scenario) throw new Error(`Unknown attack scenario: ${scenarioId}`);

  const generated: SecurityEvent[] = [];
  const startedAt = Date.now();
  let previousOffset = 0;

  for (const template of scenario.events) {
    if (signal?.aborted) break;

    const waitMs = Math.max(0, template.offsetMs - previousOffset);
    if (waitMs > 0) await delay(waitMs, signal);
    previousOffset = template.offsetMs;

    const simulatedTimestamp = new Date(startedAt + template.offsetMs).toISOString();
    const generatedEvent = createSimulatedEvent(template.event, scenario.id, simulatedTimestamp);
    generated.push(generatedEvent);
    onEvent?.(generatedEvent);
  }

  return generated;
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('Simulation aborted', 'AbortError'));
      return;
    }

    const timer = window.setTimeout(resolve, ms);
    const abortHandler = () => {
      window.clearTimeout(timer);
      reject(new DOMException('Simulation aborted', 'AbortError'));
    };

    signal?.addEventListener('abort', abortHandler, { once: true });
  });
}
