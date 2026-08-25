import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Clock3,
  Laptop,
  Network,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  Smartphone,
  X,
} from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { securityApi } from '@/security/api';
import type {
  SecurityDetection,
  SecurityEvent,
  SecurityIncident,
  SecuritySeverity,
} from '@/security/types';

interface Asset {
  id: string;
  name: string;
  type: 'server' | 'endpoint' | 'mobile' | 'network';
  status: 'active' | 'warning' | 'critical' | 'stale';
  ips: string[];
  users: string[];
  eventCount: number;
  detectionCount: number;
  incidentCount: number;
  highestSeverity: SecuritySeverity;
  lastSeen: string;
  techniques: string[];
  processes: string[];
  sources: string[];
}

interface AssetData {
  events: SecurityEvent[];
  detections: SecurityDetection[];
  incidents: SecurityIncident[];
  updatedAt: string;
}

const severityRank: Record<SecuritySeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function severityFromEvents(events: SecurityEvent[]): SecuritySeverity {
  return events.reduce<SecuritySeverity>(
    (highest, event) => (severityRank[event.severity] > severityRank[highest] ? event.severity : highest),
    'info'
  );
}

function assetIdentity(event: SecurityEvent): { id: string; name: string; type: Asset['type'] }[] {
  const identities: { id: string; name: string; type: Asset['type'] }[] = [];
  const hostname = event.hostname?.trim();

  if (hostname) {
    const lower = hostname.toLowerCase();
    const type: Asset['type'] = lower.includes('server') || lower.includes('db-') || lower.includes('api-')
      ? 'server'
      : lower.includes('mobile') || lower.includes('phone') || lower.includes('android') || lower.includes('ios')
        ? 'mobile'
        : 'endpoint';
    identities.push({ id: `host:${lower}`, name: hostname, type });
  }

  if (event.sourceIP) identities.push({ id: `ip:${event.sourceIP}`, name: event.sourceIP, type: 'network' });
  if (!hostname && event.destinationIP) {
    identities.push({ id: `ip:${event.destinationIP}`, name: event.destinationIP, type: 'network' });
  }

  return identities;
}

function buildAssets(data: AssetData): Asset[] {
  const buckets = new Map<string, {
    name: string;
    type: Asset['type'];
    events: SecurityEvent[];
    ips: Set<string>;
    users: Set<string>;
    techniques: Set<string>;
    processes: Set<string>;
    sources: Set<string>;
  }>();

  for (const event of data.events) {
    for (const identity of assetIdentity(event)) {
      const current = buckets.get(identity.id) ?? {
        name: identity.name,
        type: identity.type,
        events: [],
        ips: new Set<string>(),
        users: new Set<string>(),
        techniques: new Set<string>(),
        processes: new Set<string>(),
        sources: new Set<string>(),
      };
      current.events.push(event);
      if (event.sourceIP) current.ips.add(event.sourceIP);
      if (event.destinationIP) current.ips.add(event.destinationIP);
      if (event.username) current.users.add(event.username);
      for (const technique of event.mitreTechniques ?? []) current.techniques.add(technique);
      if (event.processName) current.processes.add(event.processName);
      current.sources.add(event.source);
      buckets.set(identity.id, current);
    }
  }

  return [...buckets.entries()]
    .map(([id, bucket]) => {
      const eventIds = new Set(bucket.events.map((event) => event.id));
      const detectionCount = data.detections.filter((detection) => eventIds.has(detection.eventId)).length;
      const incidentCount = data.incidents.filter((incident) => incident.eventIds.some((eventId) => eventIds.has(eventId))).length;
      const highestSeverity = severityFromEvents(bucket.events);
      const lastSeen = bucket.events.reduce((latest, event) =>
        event.timestamp > latest ? event.timestamp : latest,
        bucket.events[0]?.timestamp ?? new Date(0).toISOString()
      );
      const ageMinutes = Math.max(0, (Date.now() - new Date(lastSeen).getTime()) / 60000);
      const status: Asset['status'] = highestSeverity === 'critical'
        ? 'critical'
        : highestSeverity === 'high' || incidentCount > 0
          ? 'warning'
          : ageMinutes <= 15
            ? 'active'
            : 'stale';

      return {
        id,
        name: bucket.name,
        type: bucket.type,
        status,
        ips: [...bucket.ips],
        users: [...bucket.users],
        eventCount: eventIds.size,
        detectionCount,
        incidentCount,
        highestSeverity,
        lastSeen,
        techniques: [...bucket.techniques],
        processes: [...bucket.processes],
        sources: [...bucket.sources],
      };
    })
    .sort((a, b) => {
      if (severityRank[b.highestSeverity] !== severityRank[a.highestSeverity]) {
        return severityRank[b.highestSeverity] - severityRank[a.highestSeverity];
      }
      return new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime();
    });
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
}

function relativeTime(value: string): string {
  const age = Math.max(0, Date.now() - new Date(value).getTime());
  const minutes = Math.floor(age / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function statusClass(status: Asset['status']): string {
  switch (status) {
    case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/30';
    case 'warning': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
    case 'active': return 'bg-green-500/20 text-green-300 border-green-500/30';
    default: return 'bg-slate-500/20 text-slate-300 border-slate-500/30';
  }
}

function severityClass(severity: SecuritySeverity): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/30';
    case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
    case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
    case 'low': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
    default: return 'bg-slate-500/20 text-slate-300 border-slate-500/30';
  }
}

function AssetIcon({ type }: { type: Asset['type'] }) {
  if (type === 'server') return <Server className="w-5 h-5" />;
  if (type === 'mobile') return <Smartphone className="w-5 h-5" />;
  if (type === 'network') return <Network className="w-5 h-5" />;
  return <Laptop className="w-5 h-5" />;
}

export default function Assets() {
  const [data, setData] = useState<AssetData>({ events: [], detections: [], incidents: [], updatedAt: '' });
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const loadAssets = async () => {
    setLoading(true);
    setError(null);
    try {
      const snapshot = await securityApi.snapshot();
      setData({
        events: snapshot.events,
        detections: snapshot.detections,
        incidents: snapshot.incidents,
        updatedAt: snapshot.updatedAt,
      });
      setLastRefresh(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load asset telemetry');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadAssets();
  }, []);

  const assets = useMemo(() => buildAssets(data), [data]);
  const filteredAssets = useMemo(() => {
    const query = searchTerm.trim().toLowerCase();
    if (!query) return assets;
    return assets.filter((asset) =>
      asset.name.toLowerCase().includes(query) ||
      asset.ips.some((ip) => ip.toLowerCase().includes(query)) ||
      asset.users.some((user) => user.toLowerCase().includes(query))
    );
  }, [assets, searchTerm]);

  const stats = useMemo(() => ({
    total: assets.length,
    active: assets.filter((asset) => asset.status === 'active').length,
    warning: assets.filter((asset) => asset.status === 'warning').length,
    critical: assets.filter((asset) => asset.status === 'critical').length,
    stale: assets.filter((asset) => asset.status === 'stale').length,
  }), [assets]);

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <div className="glass border-b sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h1 className="text-3xl font-bold font-mono">ASSETS</h1>
                <p className="text-sm text-muted-foreground">Endpoint inventory derived from persisted security telemetry</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge className="bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 gap-2">
                  <Activity className="w-3 h-3" />
                  {loading ? 'SYNCING' : 'LIVE DATA'}
                </Badge>
                <Button variant="outline" size="sm" onClick={() => void loadAssets()} disabled={loading} className="gap-2">
                  <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                  Refresh
                </Button>
              </div>
            </div>
            {lastRefresh && (
              <p className="text-[11px] text-muted-foreground mt-2 font-mono">Last sync: {lastRefresh.toLocaleTimeString()}</p>
            )}
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          {error && (
            <Card className="mb-6 border-red-500/30 bg-red-500/5 p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5" />
                <div>
                  <p className="font-mono text-sm text-red-300">Asset telemetry unavailable</p>
                  <p className="text-xs text-muted-foreground mt-1">{error}</p>
                </div>
              </div>
            </Card>
          )}

          <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
            <StatCard label="Observed Assets" value={stats.total} />
            <StatCard label="Active" value={stats.active} color="green" />
            <StatCard label="Warnings" value={stats.warning} color="yellow" />
            <StatCard label="Critical" value={stats.critical} color="red" />
            <StatCard label="Stale" value={stats.stale} color="slate" />
          </div>

          <Card className="glass glow-border mb-6">
            <div className="p-5">
              <div className="flex items-center justify-between gap-4 mb-4">
                <div>
                  <h2 className="font-mono font-bold text-accent">ENDPOINT INTELLIGENCE</h2>
                  <p className="text-xs text-muted-foreground mt-1">Risk is calculated from observed events, detections, and persisted incidents.</p>
                </div>
                <Badge className="bg-card/50 border border-border/20 text-muted-foreground">{data.events.length} events · {data.detections.length} detections</Badge>
              </div>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search hostname, IP address, or username..."
                  value={searchTerm}
                  onChange={(event) => setSearchTerm(event.target.value)}
                  className="pl-10 bg-card/30 border-border/20"
                />
              </div>
            </div>
          </Card>

          {loading && assets.length === 0 ? (
            <Card className="glass glow-border p-12 text-center">
              <RefreshCw className="w-7 h-7 mx-auto mb-3 animate-spin text-accent" />
              <p className="font-mono text-sm">Synchronizing endpoint telemetry...</p>
            </Card>
          ) : filteredAssets.length === 0 ? (
            <Card className="glass glow-border p-12 text-center">
              <Server className="w-8 h-8 mx-auto mb-3 text-muted-foreground" />
              <p className="font-mono text-sm">No observed assets found.</p>
              <p className="text-xs text-muted-foreground mt-2">
                Run a scenario in Attack Lab to generate telemetry with host or IP information.
              </p>
            </Card>
          ) : (
            <div className="space-y-4">
              {filteredAssets.map((asset) => (
                <Card key={asset.id} className="glass glow-border p-5 hover:border-accent/40 transition-all">
                  <div className="flex flex-col xl:flex-row xl:items-center gap-5">
                    <div className="flex items-start gap-4 min-w-0 xl:w-[32%]">
                      <div className="p-3 rounded border border-accent/20 bg-accent/5 text-accent shrink-0">
                        <AssetIcon type={asset.type} />
                      </div>
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2 mb-1">
                          <h3 className="font-mono font-bold truncate">{asset.name}</h3>
                          <Badge variant="outline" className="text-[10px] uppercase">{asset.type}</Badge>
                        </div>
                        <p className="text-xs text-muted-foreground truncate">
                          {asset.ips.length > 0 ? asset.ips.slice(0, 2).join(' · ') : 'No IP observed'}
                        </p>
                        <div className="flex items-center gap-2 mt-2">
                          <Badge className={`${statusClass(asset.status)} border text-[10px]`}>{asset.status.toUpperCase()}</Badge>
                          <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                            <Clock3 className="w-3 h-3" /> {relativeTime(asset.lastSeen)}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 flex-1">
                      <Metric label="Events" value={asset.eventCount} />
                      <Metric label="Detections" value={asset.detectionCount} emphasis={asset.detectionCount > 0} />
                      <Metric label="Incidents" value={asset.incidentCount} emphasis={asset.incidentCount > 0} />
                      <div>
                        <p className="text-[10px] text-muted-foreground uppercase font-mono">Severity</p>
                        <Badge className={`${severityClass(asset.highestSeverity)} border mt-1 text-[10px]`}>
                          {asset.highestSeverity.toUpperCase()}
                        </Badge>
                      </div>
                    </div>

                    <Button variant="outline" size="sm" onClick={() => setSelectedAsset(asset)} className="shrink-0">
                      View Intelligence
                    </Button>
                  </div>
                </Card>
              ))}
            </div>
          )}

          {data.updatedAt && (
            <p className="text-[11px] text-muted-foreground font-mono mt-6 text-right">
              Backend snapshot: {formatTime(data.updatedAt)}
            </p>
          )}
        </div>
      </main>

      {selectedAsset && (
        <div className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onMouseDown={() => setSelectedAsset(null)}>
          <div className="w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-xl border border-accent/30 bg-background shadow-2xl" onMouseDown={(event) => event.stopPropagation()}>
            <div className="sticky top-0 z-10 bg-background/95 backdrop-blur border-b border-border/20 p-5 flex items-start justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded border border-accent/20 bg-accent/5 text-accent">
                  <AssetIcon type={selectedAsset.type} />
                </div>
                <div>
                  <h2 className="text-xl font-mono font-bold">{selectedAsset.name}</h2>
                  <div className="flex items-center gap-2 mt-1">
                    <Badge className={`${statusClass(selectedAsset.status)} border text-[10px]`}>{selectedAsset.status.toUpperCase()}</Badge>
                    <span className="text-xs text-muted-foreground">Last seen {formatTime(selectedAsset.lastSeen)}</span>
                  </div>
                </div>
              </div>
              <Button variant="ghost" size="icon" onClick={() => setSelectedAsset(null)} aria-label="Close asset details">
                <X className="w-5 h-5" />
              </Button>
            </div>

            <div className="p-5 space-y-5">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <DetailStat label="Events" value={selectedAsset.eventCount} />
                <DetailStat label="Detections" value={selectedAsset.detectionCount} />
                <DetailStat label="Incidents" value={selectedAsset.incidentCount} />
                <DetailStat label="Highest Severity" value={selectedAsset.highestSeverity.toUpperCase()} />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <InfoBlock title="NETWORK IDENTIFIERS" values={selectedAsset.ips} empty="No IP addresses observed" />
                <InfoBlock title="IDENTITIES" values={selectedAsset.users} empty="No usernames observed" />
                <InfoBlock title="PROCESSES" values={selectedAsset.processes} empty="No process telemetry observed" />
                <InfoBlock title="TELEMETRY SOURCES" values={selectedAsset.sources} empty="No source information" />
              </div>

              <Card className="bg-card/20 border-border/20 p-4">
                <div className="flex items-center gap-2 mb-3">
                  <ShieldAlert className="w-4 h-4 text-accent" />
                  <h3 className="font-mono text-sm font-bold">MITRE ATT&CK ACTIVITY</h3>
                </div>
                {selectedAsset.techniques.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No ATT&CK techniques associated with this asset.</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {selectedAsset.techniques.map((technique) => (
                      <Badge key={technique} variant="outline" className="font-mono text-[10px]">
                        {technique}
                      </Badge>
                    ))}
                  </div>
                )}
              </Card>

              <Card className="bg-card/20 border-border/20 p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Network className="w-4 h-4 text-accent" />
                  <h3 className="font-mono text-sm font-bold">SECURITY INTERPRETATION</h3>
                </div>
                <p className="text-sm text-muted-foreground leading-6">
                  {selectedAsset.incidentCount > 0
                    ? `This asset is linked to ${selectedAsset.incidentCount} persisted incident${selectedAsset.incidentCount === 1 ? '' : 's'}. Review the incident timeline before treating the endpoint as contained.`
                    : selectedAsset.detectionCount > 0
                      ? `This asset generated ${selectedAsset.detectionCount} detection${selectedAsset.detectionCount === 1 ? '' : 's'}. Review the associated telemetry and ATT&CK techniques for investigation.`
                      : 'No persisted detections or incidents are currently linked to this asset.'}
                </p>
              </Card>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, color = 'cyan' }: { label: string; value: number; color?: 'cyan' | 'green' | 'yellow' | 'red' | 'slate' }) {
  const classes = {
    cyan: 'text-cyan-400',
    green: 'text-green-400',
    yellow: 'text-yellow-400',
    red: 'text-red-400',
    slate: 'text-slate-300',
  };
  return (
    <Card className="glass border border-border/20 p-4">
      <p className="text-xs text-muted-foreground font-mono uppercase">{label}</p>
      <p className={`text-2xl font-mono font-bold mt-2 ${classes[color]}`}>{value}</p>
    </Card>
  );
}

function Metric({ label, value, emphasis = false }: { label: string; value: number; emphasis?: boolean }) {
  return (
    <div>
      <p className="text-[10px] text-muted-foreground uppercase font-mono">{label}</p>
      <p className={`text-lg font-mono font-bold mt-1 ${emphasis ? 'text-orange-300' : 'text-foreground'}`}>{value}</p>
    </div>
  );
}

function DetailStat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded border border-border/20 bg-card/20 p-3">
      <p className="text-[10px] text-muted-foreground uppercase font-mono">{label}</p>
      <p className="text-lg font-mono font-bold mt-1 text-cyan-300">{value}</p>
    </div>
  );
}

function InfoBlock({ title, values, empty }: { title: string; values: string[]; empty: string }) {
  return (
    <Card className="bg-card/20 border-border/20 p-4">
      <h3 className="font-mono text-xs font-bold text-muted-foreground mb-3">{title}</h3>
      {values.length === 0 ? (
        <p className="text-xs text-muted-foreground">{empty}</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {values.map((value) => (
            <Badge key={value} variant="outline" className="font-mono text-[10px]">{value}</Badge>
          ))}
        </div>
      )}
    </Card>
  );
}
