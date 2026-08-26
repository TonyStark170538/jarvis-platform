import { useCallback, useEffect, useMemo, useState } from 'react';
import { Copy, Globe, Plus, RefreshCw, Search, ShieldAlert, Trash2, X } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { securityApi } from '@/security/api';
import type { SecurityEvent, SecuritySeverity } from '@/security/types';

type IOCType = 'ip' | 'domain' | 'hash' | 'url';

type IOC = {
  id: string;
  type: IOCType;
  value: string;
  severity: SecuritySeverity;
  source: string;
  lastSeen: string;
  detections: number;
  eventCount: number;
  confidence: number;
  tags: string[];
  observed: boolean;
};

const severityRank: Record<SecuritySeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function normalizeSeverity(events: SecurityEvent[]): SecuritySeverity {
  return events.reduce<SecuritySeverity>(
    (highest, event) => severityRank[event.severity] > severityRank[highest] ? event.severity : highest,
    'info',
  );
}

function classifyValue(value: string): IOCType | null {
  const trimmed = value.trim();
  if (/^https?:\/\//i.test(trimmed)) return 'url';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return 'ip';
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(trimmed)) return 'hash';
  if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(trimmed)) return 'domain';
  return null;
}

function extractIndicators(events: SecurityEvent[]): IOC[] {
  const groups = new Map<string, { type: IOCType; events: SecurityEvent[]; sources: Set<string> }>();

  const add = (value: string | undefined, type: IOCType, event: SecurityEvent) => {
    if (!value) return;
    const normalized = value.trim();
    if (!normalized) return;
    const key = `${type}:${normalized.toLowerCase()}`;
    const existing = groups.get(key);
    if (existing) {
      existing.events.push(event);
      existing.sources.add(event.source);
    } else {
      groups.set(key, { type, events: [event], sources: new Set([event.source]) });
    }
  };

  for (const event of events) {
    add(event.sourceIP, 'ip', event);
    add(event.destinationIP, 'ip', event);

    const metadata = event.metadata ?? {};
    const metadataValues = [
      metadata.domain,
      metadata.url,
      metadata.destinationDomain,
      metadata.sha256,
      metadata.sha1,
      metadata.md5,
      metadata.hash,
    ];
    for (const candidate of metadataValues) {
      if (typeof candidate !== 'string') continue;
      const type = classifyValue(candidate);
      if (type) add(candidate, type, event);
    }
  }

  return Array.from(groups.entries())
    .map(([id, group]) => {
      const severity = normalizeSeverity(group.events);
      const detections = group.events.filter((event) => event.severity !== 'info').length;
      const confidence = Math.min(99, 60 + detections * 8 + (severity === 'critical' ? 20 : severity === 'high' ? 12 : 0));
      const tags = new Set<string>();
      group.events.forEach((event) => {
        event.mitreTechniques?.forEach((technique) => tags.add(technique));
        tags.add(event.type);
      });

      return {
        id,
        type: group.type,
        value: id.slice(id.indexOf(':') + 1),
        severity,
        source: Array.from(group.sources).join(', '),
        lastSeen: group.events.reduce((latest, event) => event.timestamp > latest ? event.timestamp : latest, group.events[0].timestamp),
        detections,
        eventCount: group.events.length,
        confidence,
        tags: Array.from(tags).slice(0, 6),
        observed: true,
      } satisfies IOC;
    })
    .sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || b.lastSeen.localeCompare(a.lastSeen));
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

function typeClass(type: IOCType): string {
  switch (type) {
    case 'ip': return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
    case 'domain': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
    case 'hash': return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
    case 'url': return 'bg-green-500/20 text-green-300 border-green-500/30';
  }
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export default function Intelligence() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [manualIocs, setManualIocs] = useState<IOC[]>([]);
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<'all' | IOCType>('all');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [newValue, setNewValue] = useState('');
  const [newSeverity, setNewSeverity] = useState<SecuritySeverity>('medium');
  const [copied, setCopied] = useState<string | null>(null);

  const loadIntelligence = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const snapshot = await securityApi.snapshot();
      setEvents(snapshot.events);
      setLastUpdated(new Date().toISOString());
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load security telemetry');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadIntelligence();
  }, [loadIntelligence]);

  const observedIocs = useMemo(() => extractIndicators(events), [events]);
  const allIocs = useMemo(() => [...manualIocs, ...observedIocs], [manualIocs, observedIocs]);

  const filteredIocs = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return allIocs.filter((ioc) => {
      const matchesType = typeFilter === 'all' || ioc.type === typeFilter;
      const matchesQuery = !normalizedQuery || [ioc.value, ioc.source, ...ioc.tags].some((value) => value.toLowerCase().includes(normalizedQuery));
      return matchesType && matchesQuery;
    });
  }, [allIocs, query, typeFilter]);

  const stats = useMemo(() => ({
    total: allIocs.length,
    critical: allIocs.filter((ioc) => ioc.severity === 'critical').length,
    high: allIocs.filter((ioc) => ioc.severity === 'high').length,
    observed: observedIocs.length,
    events: events.length,
  }), [allIocs, events.length, observedIocs.length]);

  const threatLevel = stats.critical > 0 ? 'CRITICAL' : stats.high > 0 ? 'HIGH' : stats.observed > 0 ? 'ELEVATED' : 'QUIET';

  const addManualIoc = () => {
    const value = newValue.trim();
    const type = classifyValue(value);
    if (!type) return;

    setManualIocs((current) => [{
      id: `manual:${Date.now()}`,
      type,
      value,
      severity: newSeverity,
      source: 'SOC Analyst',
      lastSeen: new Date().toISOString(),
      detections: 0,
      eventCount: 0,
      confidence: 50,
      tags: ['manual'],
      observed: false,
    }, ...current]);
    setNewValue('');
    setNewSeverity('medium');
    setShowAdd(false);
  };

  const copyValue = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(value);
      window.setTimeout(() => setCopied(null), 1200);
    } catch {
      setCopied(null);
    }
  };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <div className="glass border-b sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h1 className="text-3xl font-bold font-mono">INTELLIGENCE</h1>
                <p className="text-sm text-muted-foreground">IOC discovery from persisted J.A.R.V.I.S. telemetry</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge className={error ? 'bg-red-500/20 text-red-300 border-red-500/30' : 'bg-green-500/20 text-green-300 border-green-500/30'}>
                  {error ? 'API ERROR' : 'LIVE TELEMETRY'}
                </Badge>
                <Button variant="outline" onClick={() => void loadIntelligence()} disabled={isLoading} className="gap-2">
                  <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
                  Refresh
                </Button>
                <Button onClick={() => setShowAdd(true)} className="bg-accent hover:bg-accent/90 text-background gap-2">
                  <Plus className="w-4 h-4" />
                  Add IOC
                </Button>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
          {error && (
            <Card className="border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-200">
              {error}
            </Card>
          )}

          <Card className="glass glow-border p-6">
            <div className="flex items-start justify-between gap-6">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <ShieldAlert className="w-5 h-5 text-accent" />
                  <h2 className="text-lg font-mono font-bold text-accent">THREAT POSTURE</h2>
                </div>
                <p className="text-sm text-muted-foreground max-w-2xl">
                  This view is derived from events stored by the J.A.R.V.I.S. security API. It does not invent external threat-feed results.
                </p>
              </div>
              <div className="text-right">
                <p className="text-xs text-muted-foreground font-mono">CURRENT LEVEL</p>
                <p className="text-3xl font-mono font-bold text-red-300">{threatLevel}</p>
              </div>
            </div>
          </Card>

          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <StatCard label="Total IOCs" value={stats.total} />
            <StatCard label="Critical" value={stats.critical} color="red" />
            <StatCard label="High" value={stats.high} color="orange" />
            <StatCard label="Observed" value={stats.observed} color="cyan" />
            <StatCard label="Telemetry Events" value={stats.events} color="blue" />
          </div>

          <Card className="glass glow-border p-6">
            <div className="flex items-center justify-between mb-4 gap-4">
              <div>
                <h2 className="text-lg font-mono font-bold text-accent">IOC LOOKUP</h2>
                <p className="text-xs text-muted-foreground mt-1">Search observed IPs, domains, URLs, hashes and analyst-added indicators.</p>
              </div>
              {lastUpdated && <p className="text-xs text-muted-foreground font-mono">Updated {formatTime(lastUpdated)}</p>}
            </div>
            <div className="flex flex-col md:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search indicator, source or MITRE technique..." className="pl-9" />
              </div>
              <div className="flex gap-2 flex-wrap">
                {(['all', 'ip', 'domain', 'url', 'hash'] as const).map((type) => (
                  <Button key={type} size="sm" variant={typeFilter === type ? 'default' : 'outline'} onClick={() => setTypeFilter(type)}>
                    {type.toUpperCase()}
                  </Button>
                ))}
              </div>
            </div>
          </Card>

          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-mono font-bold text-accent">INDICATORS OF COMPROMISE</h2>
              <span className="text-xs text-muted-foreground font-mono">{filteredIocs.length} result(s)</span>
            </div>

            {filteredIocs.length === 0 ? (
              <Card className="glass border border-border/20 p-10 text-center">
                <Globe className="w-8 h-8 mx-auto mb-3 text-muted-foreground" />
                <p className="font-mono">No indicators found</p>
                <p className="text-sm text-muted-foreground mt-1">Run an Attack Lab scenario or add an IOC manually.</p>
              </Card>
            ) : (
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                {filteredIocs.map((ioc) => (
                  <Card key={ioc.id} className="glass border border-border/20 p-5 hover:border-accent/40 transition-colors">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap mb-3">
                          <Badge className={`${typeClass(ioc.type)} border uppercase text-xs`}>{ioc.type}</Badge>
                          <Badge className={`${severityClass(ioc.severity)} border uppercase text-xs`}>{ioc.severity}</Badge>
                          <Badge variant="outline" className="text-xs">{ioc.observed ? 'OBSERVED' : 'MANUAL'}</Badge>
                        </div>
                        <p className="font-mono text-sm break-all text-foreground">{ioc.value}</p>
                        <p className="text-xs text-muted-foreground mt-2">Source: {ioc.source}</p>
                      </div>
                      <div className="flex gap-1 shrink-0">
                        <Button size="sm" variant="ghost" onClick={() => void copyValue(ioc.value)} title="Copy IOC">
                          <Copy className="w-4 h-4" />
                        </Button>
                        {!ioc.observed && (
                          <Button size="sm" variant="ghost" onClick={() => setManualIocs((current) => current.filter((item) => item.id !== ioc.id))} title="Remove manual IOC">
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-4">
                      <Metric label="Events" value={ioc.eventCount} />
                      <Metric label="Detections" value={ioc.detections} />
                      <Metric label="Confidence" value={`${ioc.confidence}%`} />
                      <Metric label="Last Seen" value={formatTime(ioc.lastSeen)} />
                    </div>

                    {ioc.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-3">
                        {ioc.tags.map((tag) => <Badge key={tag} variant="outline" className="text-[10px]">{tag}</Badge>)}
                      </div>
                    )}
                    {copied === ioc.value && <p className="text-xs text-accent mt-2 font-mono">Copied to clipboard.</p>}
                  </Card>
                ))}
              </div>
            )}
          </div>

          <Card className="glass glow-border p-6">
            <h2 className="text-lg font-mono font-bold text-accent mb-4">THREAT LANDSCAPE</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <LandscapeCard label="Observed Indicator Types" value={new Set(observedIocs.map((ioc) => ioc.type)).size.toString()} detail="from persisted telemetry" />
              <LandscapeCard label="Highest Severity" value={observedIocs[0]?.severity?.toUpperCase() ?? 'NONE'} detail="based on observed indicators" />
              <LandscapeCard label="ATT&CK Coverage" value={`${new Set(events.flatMap((event) => event.mitreTechniques ?? [])).size}`} detail="unique techniques in telemetry" />
            </div>
          </Card>
        </div>
      </main>

      {showAdd && (
        <div className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onMouseDown={(event) => { if (event.target === event.currentTarget) setShowAdd(false); }}>
          <Card className="w-full max-w-lg glass glow-border p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-xl font-mono font-bold">ADD IOC</h2>
                <p className="text-xs text-muted-foreground mt-1">Manual indicators are kept in this browser session.</p>
              </div>
              <Button size="sm" variant="ghost" onClick={() => setShowAdd(false)}><X className="w-4 h-4" /></Button>
            </div>
            <div className="space-y-4">
              <Input value={newValue} onChange={(event) => setNewValue(event.target.value)} placeholder="IP, domain, URL or MD5/SHA hash" autoFocus />
              <div className="grid grid-cols-4 gap-2">
                {(['critical', 'high', 'medium', 'low'] as const).map((severity) => (
                  <Button key={severity} type="button" variant={newSeverity === severity ? 'default' : 'outline'} onClick={() => setNewSeverity(severity)} className="capitalize">{severity}</Button>
                ))}
              </div>
              {newValue && !classifyValue(newValue) && <p className="text-xs text-red-300">Enter a valid IPv4 address, domain, URL, or MD5/SHA hash.</p>}
              <Button className="w-full bg-accent text-background hover:bg-accent/90" disabled={!classifyValue(newValue)} onClick={addManualIoc}>Add Indicator</Button>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, color = 'cyan' }: { label: string; value: number; color?: 'red' | 'orange' | 'cyan' | 'blue' }) {
  const classes = { red: 'text-red-400', orange: 'text-orange-400', cyan: 'text-cyan-400', blue: 'text-blue-400' };
  return <Card className="glass border border-border/20 p-4"><p className="text-xs text-muted-foreground font-mono uppercase">{label}</p><p className={`text-2xl font-mono font-bold mt-2 ${classes[color]}`}>{value}</p></Card>;
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return <div className="p-2 bg-card/30 rounded border border-border/20 min-w-0"><p className="text-[10px] text-muted-foreground uppercase">{label}</p><p className="font-mono text-xs truncate mt-1">{value}</p></div>;
}

function LandscapeCard({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <div className="p-5 bg-card/30 rounded border border-border/20"><p className="text-xs text-muted-foreground mb-2">{label}</p><p className="text-2xl font-mono font-bold text-cyan-300">{value}</p><p className="text-xs text-muted-foreground mt-1">{detail}</p></div>;
}
