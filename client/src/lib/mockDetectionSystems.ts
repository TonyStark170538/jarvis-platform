/**
 * Mock Detection Systems Simulator
 * Generates realistic detection events for testing and demonstration
 */

import {
  DetectionEvent,
  EventSeverity,
  EvidenceArtifact,
  ThreatIndicator,
} from './detectionSystems';

const ATTACK_SIGNATURES = [
  'Unauthorized SSH Access Attempt',
  'SQL Injection Attack Detected',
  'Cross-Site Scripting (XSS) Payload',
  'Brute Force Login Attack',
  'Data Exfiltration Detected',
  'Malware Signature Match',
  'Privilege Escalation Attempt',
  'DDoS Attack Pattern',
  'Suspicious PowerShell Execution',
  'Lateral Movement Detected',
  'Credential Harvesting Activity',
  'Ransomware Behavior Detected',
];

const SOURCE_IPS = [
  '203.0.113.45',
  '198.51.100.78',
  '192.0.2.156',
  '203.0.113.89',
  '198.51.100.234',
];

const DEST_IPS = [
  '10.0.1.50',
  '10.0.2.100',
  '10.0.3.25',
  '10.0.1.150',
  '10.0.2.200',
];

const PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'SSH', 'FTP'];

const EVENT_TYPES = [
  'IDS Alert',
  'Network Anomaly',
  'Process Execution',
  'File Access',
  'Registry Modification',
  'DNS Query',
  'HTTP Request',
  'Authentication Failure',
];

const CATEGORIES = [
  'Reconnaissance',
  'Weaponization',
  'Delivery',
  'Exploitation',
  'Installation',
  'Command & Control',
  'Actions on Objectives',
  'Lateral Movement',
];

/**
 * Generate a random mock detection event
 */
export function generateMockEvent(
  sourceSystem: 'suricata' | 'zeek' | 'splunk' = 'suricata'
): DetectionEvent {
  const severity: EventSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const randomSeverity = severity[Math.floor(Math.random() * severity.length)];

  const sourceIP = SOURCE_IPS[Math.floor(Math.random() * SOURCE_IPS.length)];
  const destIP = DEST_IPS[Math.floor(Math.random() * DEST_IPS.length)];
  const protocol = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
  const signature =
    ATTACK_SIGNATURES[Math.floor(Math.random() * ATTACK_SIGNATURES.length)];
  const category = CATEGORIES[Math.floor(Math.random() * CATEGORIES.length)];
  const eventType = EVENT_TYPES[Math.floor(Math.random() * EVENT_TYPES.length)];

  // Generate timestamp within last hour
  const now = new Date();
  const minutesAgo = Math.floor(Math.random() * 60);
  const timestamp = new Date(now.getTime() - minutesAgo * 60000).toISOString();

  return {
    id: `mock-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp,
    source:
      sourceSystem === 'suricata'
        ? 'Suricata IDS'
        : sourceSystem === 'zeek'
        ? 'Zeek NSM'
        : 'Splunk SIEM',
    sourceSystem,
    eventType,
    severity: randomSeverity,
    title: signature,
    description: `${signature} from ${sourceIP} to ${destIP} via ${protocol}`,
    sourceIP,
    destIP,
    sourcePort: Math.floor(Math.random() * 65535) + 1024,
    destPort: Math.floor(Math.random() * 65535) + 1,
    protocol,
    signature,
    signatureId: `SID-${Math.floor(Math.random() * 9999999)}`,
    category,
    rawData: {
      event_id: Math.floor(Math.random() * 999999),
      timestamp: timestamp,
      src_ip: sourceIP,
      dest_ip: destIP,
      protocol: protocol,
      action: 'alert',
      metadata: {
        policy: 'default',
        engine: sourceSystem,
      },
    },
  };
}

/**
 * Generate multiple mock events
 */
export function generateMockEvents(
  count: number = 10,
  sourceSystem?: 'suricata' | 'zeek' | 'splunk'
): DetectionEvent[] {
  const events: DetectionEvent[] = [];
  const systems: ('suricata' | 'zeek' | 'splunk')[] = sourceSystem
    ? [sourceSystem]
    : ['suricata', 'zeek', 'splunk'];

  for (let i = 0; i < count; i++) {
    const randomSystem = systems[Math.floor(Math.random() * systems.length)];
    events.push(generateMockEvent(randomSystem));
  }

  return events.sort(
    (a, b) =>
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
}

/**
 * Generate mock evidence artifacts
 */
export function generateMockEvidenceArtifacts(
  eventId: string,
  count: number = 5
): EvidenceArtifact[] {
  const types: Array<EvidenceArtifact['type']> = [
    'log',
    'pcap',
    'file',
    'process',
    'network',
    'dns',
  ];

  const artifacts: EvidenceArtifact[] = [];

  for (let i = 0; i < count; i++) {
    const type = types[Math.floor(Math.random() * types.length)];
    const timestamp = new Date(
      Date.now() - Math.random() * 3600000
    ).toISOString();

    artifacts.push({
      id: `artifact-${Date.now()}-${i}`,
      eventId,
      type,
      name: `${type}_capture_${i + 1}.${type === 'pcap' ? 'pcap' : 'log'}`,
      timestamp,
      hash: `sha256_${Math.random().toString(36).substr(2, 64)}`,
      size: `${Math.floor(Math.random() * 10000) + 100} KB`,
      path: `/var/log/detection/${type}/${i + 1}`,
      metadata: {
        captured_at: timestamp,
        packets: Math.floor(Math.random() * 10000),
        duration: `${Math.floor(Math.random() * 300)}s`,
      },
    });
  }

  return artifacts;
}

/**
 * Generate mock threat indicators
 */
export function generateMockThreatIndicators(count: number = 20): ThreatIndicator[] {
  const types: Array<ThreatIndicator['type']> = [
    'ip',
    'domain',
    'hash',
    'url',
    'email',
  ];
  const sources = [
    'OSINT Feed',
    'Internal Detection',
    'Threat Intelligence',
    'MISP',
    'AlienVault OTX',
  ];

  const indicators: ThreatIndicator[] = [];

  for (let i = 0; i < count; i++) {
    const type = types[Math.floor(Math.random() * types.length)];
    const severity: EventSeverity[] = [
      'critical',
      'high',
      'medium',
      'low',
      'info',
    ];

    let value = '';
    switch (type) {
      case 'ip':
        value = `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
        break;
      case 'domain':
        value = `malicious-domain-${i}.com`;
        break;
      case 'hash':
        value = Math.random().toString(36).substr(2, 64);
        break;
      case 'url':
        value = `http://malicious-site-${i}.com/payload`;
        break;
      case 'email':
        value = `attacker${i}@malicious.com`;
        break;
    }

    indicators.push({
      id: `indicator-${i}`,
      type,
      value,
      severity: severity[Math.floor(Math.random() * severity.length)],
      source: sources[Math.floor(Math.random() * sources.length)],
      description: `Detected malicious ${type} in threat intelligence feed`,
      lastSeen: new Date(
        Date.now() - Math.random() * 86400000
      ).toISOString(),
      confidence: Math.floor(Math.random() * 100),
      tags: ['malware', 'c2', 'exfiltration', 'reconnaissance'].slice(
        0,
        Math.floor(Math.random() * 3) + 1
      ),
    });
  }

  return indicators;
}

/**
 * Stream mock events at intervals
 */
export function streamMockEvents(
  callback: (event: DetectionEvent) => void,
  intervalMs: number = 5000
): () => void {
  const interval = setInterval(() => {
    const event = generateMockEvent();
    callback(event);
  }, intervalMs);

  // Return cleanup function
  return () => clearInterval(interval);
}

/**
 * Simulate realistic incident progression
 */
export function generateMockIncidentTimeline(
  incidentType: string = 'ssh-brute-force'
): DetectionEvent[] {
  const timeline: DetectionEvent[] = [];
  const baseTime = Date.now();

  const timelineEvents = {
    'ssh-brute-force': [
      {
        offset: 0,
        severity: 'low' as EventSeverity,
        title: 'SSH Connection Attempt',
        description: 'Initial SSH connection from external IP',
      },
      {
        offset: 5000,
        severity: 'low' as EventSeverity,
        title: 'SSH Authentication Failed',
        description: 'Failed login attempt for user admin',
      },
      {
        offset: 10000,
        severity: 'medium' as EventSeverity,
        title: 'Multiple SSH Failures Detected',
        description: 'Multiple failed login attempts detected',
      },
      {
        offset: 15000,
        severity: 'high' as EventSeverity,
        title: 'Brute Force Attack Pattern',
        description: '50+ failed login attempts in 10 seconds',
      },
      {
        offset: 20000,
        severity: 'critical' as EventSeverity,
        title: 'Successful SSH Authentication',
        description: 'Attacker successfully authenticated',
      },
    ],
    'data-exfiltration': [
      {
        offset: 0,
        severity: 'medium' as EventSeverity,
        title: 'Unusual Network Traffic',
        description: 'Large data transfer to external IP detected',
      },
      {
        offset: 5000,
        severity: 'high' as EventSeverity,
        title: 'Data Exfiltration Detected',
        description: 'Sensitive data being transferred externally',
      },
      {
        offset: 10000,
        severity: 'critical' as EventSeverity,
        title: 'Large Scale Data Theft',
        description: '5GB+ of data transferred in 5 minutes',
      },
    ],
  };

  const events = timelineEvents[incidentType as keyof typeof timelineEvents] || timelineEvents['ssh-brute-force'];

  events.forEach((event, index) => {
    timeline.push({
      id: `incident-${index}`,
      timestamp: new Date(baseTime + event.offset).toISOString(),
      source: 'Suricata IDS',
      sourceSystem: 'suricata',
      eventType: 'IDS Alert',
      severity: event.severity,
      title: event.title,
      description: event.description,
      sourceIP: SOURCE_IPS[0],
      destIP: DEST_IPS[0],
      sourcePort: 54321,
      destPort: 22,
      protocol: 'TCP',
      signature: event.title,
      signatureId: `SID-${index}`,
      category: 'Exploitation',
      rawData: {
        event_id: index,
        timestamp: new Date(baseTime + event.offset).toISOString(),
      },
    });
  });

  return timeline;
}
