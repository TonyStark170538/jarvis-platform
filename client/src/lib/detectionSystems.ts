/**
 * Detection System Integration Library
 * Supports Suricata, Zeek, and Splunk with unified API interfaces
 */

export type DetectionSystemType = 'suricata' | 'zeek' | 'splunk';
export type EventSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Detection System Configuration
 */
export interface DetectionSystemConfig {
  id: string;
  type: DetectionSystemType;
  name: string;
  enabled: boolean;
  endpoint: string;
  apiKey?: string;
  username?: string;
  password?: string;
  port?: number;
  ssl?: boolean;
  verifySSL?: boolean;
  timeout?: number;
  lastConnected?: string;
  status: 'connected' | 'disconnected' | 'error';
  errorMessage?: string;
}

/**
 * Unified Detection Event Format
 */
export interface DetectionEvent {
  id: string;
  timestamp: string;
  source: string;
  sourceSystem: DetectionSystemType;
  eventType: string;
  severity: EventSeverity;
  title: string;
  description: string;
  sourceIP?: string;
  destIP?: string;
  sourcePort?: number;
  destPort?: number;
  protocol?: string;
  signature?: string;
  signatureId?: string;
  category?: string;
  rawData?: Record<string, any>;
}

/**
 * Evidence Artifact from Detection System
 */
export interface EvidenceArtifact {
  id: string;
  eventId: string;
  type: 'log' | 'pcap' | 'file' | 'memory' | 'process' | 'network' | 'dns' | 'http';
  name: string;
  timestamp: string;
  hash?: string;
  size?: string;
  path?: string;
  content?: string;
  metadata?: Record<string, any>;
}

/**
 * Threat Intelligence Indicator
 */
export interface ThreatIndicator {
  id: string;
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
  value: string;
  severity: EventSeverity;
  source: string;
  description: string;
  lastSeen?: string;
  confidence: number; // 0-100
  tags?: string[];
}

/**
 * Suricata API Client
 */
export class SuricataClient {
  private config: DetectionSystemConfig;

  constructor(config: DetectionSystemConfig) {
    this.config = config;
  }

  /**
   * Test connection to Suricata instance
   */
  async testConnection(): Promise<boolean> {
    try {
      const response = await fetch(
        `${this.config.endpoint}/api/v1/stats`,
        {
          headers: {
            'Authorization': `Bearer ${this.config.apiKey}`,
          },
          signal: AbortSignal.timeout(this.config.timeout || 10000),
        }
      );
      return response.ok;
    } catch (error) {
      console.error('Suricata connection failed:', error);
      return false;
    }
  }

  /**
   * Fetch alerts from Suricata
   */
  async getAlerts(limit: number = 100): Promise<DetectionEvent[]> {
    try {
      const response = await fetch(
        `${this.config.endpoint}/api/v1/events?limit=${limit}`,
        {
          headers: {
            'Authorization': `Bearer ${this.config.apiKey}`,
          },
        }
      );

      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const data = await response.json();
      return this.parseAlerts(data);
    } catch (error) {
      console.error('Failed to fetch Suricata alerts:', error);
      return [];
    }
  }

  /**
   * Parse Suricata alerts into unified format
   */
  private parseAlerts(data: any): DetectionEvent[] {
    const events: DetectionEvent[] = [];

    if (Array.isArray(data.events)) {
      data.events.forEach((alert: any) => {
        events.push({
          id: `suricata-${alert.event_id}`,
          timestamp: alert.timestamp,
          source: 'Suricata IDS',
          sourceSystem: 'suricata',
          eventType: 'IDS Alert',
          severity: this.mapSeverity(alert.alert?.severity),
          title: alert.alert?.signature || 'Unknown Alert',
          description: alert.alert?.category || '',
          sourceIP: alert.src_ip,
          destIP: alert.dest_ip,
          sourcePort: alert.src_port,
          destPort: alert.dest_port,
          protocol: alert.proto,
          signature: alert.alert?.signature,
          signatureId: alert.alert?.signature_id,
          category: alert.alert?.category,
          rawData: alert,
        });
      });
    }

    return events;
  }

  private mapSeverity(severity: number | string): EventSeverity {
    if (typeof severity === 'number') {
      if (severity === 1) return 'critical';
      if (severity === 2) return 'high';
      if (severity === 3) return 'medium';
      return 'low';
    }
    return 'medium';
  }

  /**
   * Get pcap files for an alert
   */
  async getPcapFiles(alertId: string): Promise<EvidenceArtifact[]> {
    try {
      const response = await fetch(
        `${this.config.endpoint}/api/v1/alerts/${alertId}/pcap`,
        {
          headers: {
            'Authorization': `Bearer ${this.config.apiKey}`,
          },
        }
      );

      if (!response.ok) return [];

      const data = await response.json();
      return data.pcaps?.map((pcap: any) => ({
        id: pcap.id,
        eventId: alertId,
        type: 'pcap' as const,
        name: pcap.filename,
        timestamp: new Date().toISOString(),
        hash: pcap.sha256,
        size: pcap.size,
      })) || [];
    } catch (error) {
      console.error('Failed to fetch pcap files:', error);
      return [];
    }
  }
}

/**
 * Zeek API Client
 */
export class ZeekClient {
  private config: DetectionSystemConfig;

  constructor(config: DetectionSystemConfig) {
    this.config = config;
  }

  /**
   * Test connection to Zeek instance
   */
  async testConnection(): Promise<boolean> {
    try {
      const response = await fetch(
        `${this.config.endpoint}/api/logs`,
        {
          headers: {
            'Authorization': `Bearer ${this.config.apiKey}`,
          },
          signal: AbortSignal.timeout(this.config.timeout || 10000),
        }
      );
      return response.ok;
    } catch (error) {
      console.error('Zeek connection failed:', error);
      return false;
    }
  }

  /**
   * Fetch logs from Zeek
   */
  async getLogs(limit: number = 100): Promise<DetectionEvent[]> {
    try {
      const response = await fetch(
        `${this.config.endpoint}/api/logs?limit=${limit}&sort=-ts`,
        {
          headers: {
            'Authorization': `Bearer ${this.config.apiKey}`,
          },
        }
      );

      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const data = await response.json();
      return this.parseLogs(data);
    } catch (error) {
      console.error('Failed to fetch Zeek logs:', error);
      return [];
    }
  }

  /**
   * Parse Zeek logs into unified format
   */
  private parseLogs(data: any): DetectionEvent[] {
    const events: DetectionEvent[] = [];

    if (Array.isArray(data.logs)) {
      data.logs.forEach((log: any) => {
        const severity = this.determineSeverity(log);
        events.push({
          id: `zeek-${log.uid}`,
          timestamp: new Date(log.ts * 1000).toISOString(),
          source: 'Zeek NSM',
          sourceSystem: 'zeek',
          eventType: log._path || 'Network Event',
          severity,
          title: `${log._path}: ${log.proto || 'Unknown'}`,
          description: this.buildDescription(log),
          sourceIP: log.id?.orig_h,
          destIP: log.id?.resp_h,
          sourcePort: log.id?.orig_p,
          destPort: log.id?.resp_p,
          protocol: log.proto,
          category: log._path,
          rawData: log,
        });
      });
    }

    return events;
  }

  private determineSeverity(log: any): EventSeverity {
    if (log._path === 'notice') return 'high';
    if (log._path === 'weird') return 'medium';
    if (log._path === 'ssl' && log.validation_status === 'self signed') return 'medium';
    if (log._path === 'dns' && log.rcode_name === 'NXDOMAIN') return 'low';
    return 'info';
  }

  private buildDescription(log: any): string {
    if (log._path === 'http') {
      return `HTTP ${log.method} ${log.uri} from ${log.id?.orig_h}`;
    }
    if (log._path === 'dns') {
      return `DNS query: ${log.query} (${log.rcode_name})`;
    }
    if (log._path === 'ssl') {
      return `SSL/TLS connection to ${log.server_name}`;
    }
    return `${log._path} event`;
  }

  /**
   * Get connection logs
   */
  async getConnections(limit: number = 50): Promise<DetectionEvent[]> {
    try {
      const response = await fetch(
        `${this.config.endpoint}/api/logs?_path=conn&limit=${limit}&sort=-ts`,
        {
          headers: {
            'Authorization': `Bearer ${this.config.apiKey}`,
          },
        }
      );

      if (!response.ok) return [];

      const data = await response.json();
      return this.parseLogs(data);
    } catch (error) {
      console.error('Failed to fetch Zeek connections:', error);
      return [];
    }
  }
}

/**
 * Splunk API Client
 */
export class SplunkClient {
  private config: DetectionSystemConfig;

  constructor(config: DetectionSystemConfig) {
    this.config = config;
  }

  /**
   * Test connection to Splunk instance
   */
  async testConnection(): Promise<boolean> {
    try {
      const auth = Buffer.from(
        `${this.config.username}:${this.config.password}`
      ).toString('base64');

      const response = await fetch(
        `${this.config.endpoint}:${this.config.port || 8089}/services/server/info`,
        {
          headers: {
            'Authorization': `Basic ${auth}`,
          },
          signal: AbortSignal.timeout(this.config.timeout || 10000),
        }
      );
      return response.ok;
    } catch (error) {
      console.error('Splunk connection failed:', error);
      return false;
    }
  }

  /**
   * Execute Splunk search query
   */
  async search(query: string, limit: number = 100): Promise<DetectionEvent[]> {
    try {
      const auth = Buffer.from(
        `${this.config.username}:${this.config.password}`
      ).toString('base64');

      const searchQuery = `search ${query} | head ${limit}`;

      const response = await fetch(
        `${this.config.endpoint}:${this.config.port || 8089}/services/search/jobs`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: `search=${encodeURIComponent(searchQuery)}&output_mode=json`,
        }
      );

      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const data = await response.json();
      return this.parseSearchResults(data);
    } catch (error) {
      console.error('Failed to execute Splunk search:', error);
      return [];
    }
  }

  /**
   * Get security events (IDS/IPS alerts)
   */
  async getSecurityEvents(limit: number = 100): Promise<DetectionEvent[]> {
    return this.search(
      'sourcetype=ids OR sourcetype=ips OR sourcetype=waf | stats count by src_ip, dest_ip, signature',
      limit
    );
  }

  /**
   * Parse Splunk search results into unified format
   */
  private parseSearchResults(data: any): DetectionEvent[] {
    const events: DetectionEvent[] = [];

    if (data.results && Array.isArray(data.results)) {
      data.results.forEach((result: any, index: number) => {
        events.push({
          id: `splunk-${data.sid}-${index}`,
          timestamp: new Date().toISOString(),
          source: 'Splunk SIEM',
          sourceSystem: 'splunk',
          eventType: result.sourcetype || 'Security Event',
          severity: this.mapSeverity(result.severity),
          title: result.signature || result.event_type || 'Splunk Event',
          description: result.description || result._raw || '',
          sourceIP: result.src_ip,
          destIP: result.dest_ip,
          sourcePort: result.src_port,
          destPort: result.dest_port,
          protocol: result.protocol,
          signature: result.signature,
          category: result.category,
          rawData: result,
        });
      });
    }

    return events;
  }

  private mapSeverity(severity: string | number): EventSeverity {
    if (typeof severity === 'string') {
      const lower = severity.toLowerCase();
      if (lower.includes('critical')) return 'critical';
      if (lower.includes('high')) return 'high';
      if (lower.includes('medium')) return 'medium';
      if (lower.includes('low')) return 'low';
    }
    return 'info';
  }
}

/**
 * Detection System Manager
 * Manages multiple detection system connections
 */
export class DetectionSystemManager {
  private systems: Map<string, SuricataClient | ZeekClient | SplunkClient> = new Map();
  private configs: Map<string, DetectionSystemConfig> = new Map();

  /**
   * Register a detection system
   */
  registerSystem(config: DetectionSystemConfig): void {
    this.configs.set(config.id, config);

    if (config.type === 'suricata') {
      this.systems.set(config.id, new SuricataClient(config));
    } else if (config.type === 'zeek') {
      this.systems.set(config.id, new ZeekClient(config));
    } else if (config.type === 'splunk') {
      this.systems.set(config.id, new SplunkClient(config));
    }
  }

  /**
   * Get all registered systems
   */
  getSystems(): DetectionSystemConfig[] {
    return Array.from(this.configs.values());
  }

  /**
   * Get a specific system
   */
  getSystem(id: string): DetectionSystemConfig | undefined {
    return this.configs.get(id);
  }

  /**
   * Test connection to a system
   */
  async testConnection(id: string): Promise<boolean> {
    const client = this.systems.get(id);
    if (!client) return false;

    if (client instanceof SuricataClient) {
      return await client.testConnection();
    } else if (client instanceof ZeekClient) {
      return await client.testConnection();
    } else if (client instanceof SplunkClient) {
      return await client.testConnection();
    }

    return false;
  }

  /**
   * Fetch events from all enabled systems
   */
  async getAllEvents(): Promise<DetectionEvent[]> {
    const allEvents: DetectionEvent[] = [];
    const configArray = Array.from(this.configs.entries());

    for (const [id, config] of configArray) {
      if (!config.enabled) continue;

      const client = this.systems.get(id);
      if (!client) continue;

      try {
        let events: DetectionEvent[] = [];

        if (client instanceof SuricataClient) {
          events = await client.getAlerts();
        } else if (client instanceof ZeekClient) {
          events = await client.getLogs();
        } else if (client instanceof SplunkClient) {
          events = await client.getSecurityEvents();
        }

        allEvents.push(...events);
      } catch (error) {
        console.error(`Failed to fetch events from ${id}:`, error);
      }
    }

    return allEvents.sort(
      (a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  /**
   * Remove a system
   */
  removeSystem(id: string): void {
    this.systems.delete(id);
    this.configs.delete(id);
  }
}

/**
 * Global detection system manager instance
 */
export const detectionManager = new DetectionSystemManager();
