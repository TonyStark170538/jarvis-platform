import { useEffect, useState } from 'react';
import { ArrowLeft, Clock3, ExternalLink, Fingerprint, Network, RefreshCw, ShieldAlert } from 'lucide-react';
import { Link, useParams } from 'wouter';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { securityApi } from '@/security/api';
import type { SecurityIocContext, SecuritySeverity } from '@/security/types';

const severityClass: Record<SecuritySeverity, string> = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  info: 'bg-slate-500/20 text-slate-300 border-slate-500/30',
};

function formatTime(value?: string) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function IocInvestigation() {
  const { id } = useParams<{ id: string }>();
  const [context, setContext] = useState<SecurityIocContext | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      setContext(await securityApi.iocContext(id));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load IOC context');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, [id]);

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <div className="sticky top-0 z-40 glass border-b">
          <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <Link href="/intelligence"><Button variant="ghost" size="sm"><ArrowLeft className="w-4 h-4" /> Back</Button></Link>
              <div className="h-6 w-px bg-border/40" />
              <div className="min-w-0"><h1 className="text-2xl font-bold font-mono">IOC INVESTIGATION</h1><p className="text-xs text-muted-foreground">Evidence graph for a persisted threat indicator</p></div>
            </div>
            <Button variant="outline" onClick={() => void load()} disabled={loading} className="gap-2"><RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh</Button>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
          {error && <Card className="glass border border-red-500/30 bg-red-500/5 p-5 text-red-200">{error}</Card>}
          {loading && !context && <Card className="glass p-10 text-center text-muted-foreground font-mono">Loading investigation context…</Card>}
          {context && (
            <>
              <Card className="glass glow-border p-6">
                <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-5">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-3">
                      <Badge variant="outline" className="uppercase">{context.ioc.type}</Badge>
                      <Badge className={`${severityClass[context.ioc.severity]} border uppercase`}>{context.ioc.severity}</Badge>
                      <Badge variant="outline">{context.ioc.source}</Badge>
                    </div>
                    <h2 className="text-xl md:text-2xl font-mono font-bold break-all">{context.ioc.value}</h2>
                    <div className="flex flex-wrap gap-x-6 gap-y-2 mt-4 text-xs text-muted-foreground font-mono">
                      <span>First seen: {formatTime(context.firstSeen)}</span><span>Last seen: {formatTime(context.lastSeen)}</span><span>Confidence: {context.ioc.confidence}%</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-accent"><Fingerprint className="w-6 h-6" /><span className="font-mono text-sm">CORRELATED EVIDENCE</span></div>
                </div>
              </Card>

              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <Stat label="Events" value={context.events.length} />
                <Stat label="Detections" value={context.detections.length} />
                <Stat label="Incidents" value={context.incidents.length} />
                <Stat label="ATT&CK" value={context.attackTechniques.length} />
                <Stat label="Matches" value={context.matchReasons.length} />
              </div>

              <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                <Card className="glass p-6 xl:col-span-1">
                  <div className="flex items-center gap-2 mb-4"><ShieldAlert className="w-5 h-5 text-accent" /><h2 className="font-mono font-bold text-accent">WHY IT MATCHED</h2></div>
                  <div className="space-y-2">{context.matchReasons.length ? context.matchReasons.map(reason => <div key={reason} className="rounded border border-border/30 bg-card/30 p-3 text-sm">{reason}</div>) : <p className="text-sm text-muted-foreground">No telemetry currently matches this indicator.</p>}</div>
                  <div className="mt-6"><p className="text-xs text-muted-foreground uppercase font-mono mb-2">MITRE ATT&CK</p><div className="flex flex-wrap gap-2">{context.attackTechniques.length ? context.attackTechniques.map(t => <Badge key={t} variant="outline">{t}</Badge>) : <span className="text-sm text-muted-foreground">No techniques linked.</span>}</div></div>
                </Card>

                <Card className="glass p-6 xl:col-span-2">
                  <div className="flex items-center gap-2 mb-4"><Network className="w-5 h-5 text-accent" /><h2 className="font-mono font-bold text-accent">DETECTIONS</h2></div>
                  <div className="space-y-3 max-h-[420px] overflow-auto">{context.detections.length ? context.detections.map(d => <div key={d.id} className="rounded border border-border/30 p-4"><div className="flex justify-between gap-3"><div><p className="font-medium">{d.title}</p><p className="text-xs text-muted-foreground mt-1">{d.description}</p></div><Badge className={`${severityClass[d.severity]} border shrink-0`}>{d.confidence}%</Badge></div><div className="flex gap-2 mt-3 flex-wrap">{d.mitreTechniques.map(t => <Badge key={t} variant="outline" className="text-[10px]">{t}</Badge>)}</div></div>) : <p className="text-sm text-muted-foreground">No detections are linked to this IOC.</p>}</div>
                </Card>
              </div>

              <Card className="glass p-6">
                <div className="flex items-center gap-2 mb-4"><Clock3 className="w-5 h-5 text-accent" /><h2 className="font-mono font-bold text-accent">RELATED TELEMETRY</h2></div>
                <div className="overflow-x-auto"><table className="w-full text-left"><thead><tr className="border-b border-border/30 text-xs text-muted-foreground uppercase"><th className="py-3 pr-4">Time</th><th className="py-3 pr-4">Severity</th><th className="py-3 pr-4">Event</th><th className="py-3 pr-4">Source</th><th className="py-3">Host / IP</th></tr></thead><tbody>{context.events.map(event => <tr key={event.id} className="border-b border-border/20"><td className="py-3 pr-4 text-xs whitespace-nowrap">{formatTime(event.timestamp)}</td><td className="py-3 pr-4"><Badge className={`${severityClass[event.severity]} border uppercase text-[10px]`}>{event.severity}</Badge></td><td className="py-3 pr-4"><p className="text-sm font-medium">{event.title}</p><p className="text-xs text-muted-foreground">{event.type}</p></td><td className="py-3 pr-4 text-xs font-mono">{event.source}</td><td className="py-3 text-xs font-mono">{event.hostname ?? event.sourceIP ?? event.destinationIP ?? '—'}</td></tr>)}</tbody></table>{!context.events.length && <p className="text-sm text-muted-foreground py-6 text-center">No matching events.</p>}</div>
              </Card>

              <Card className="glass p-6">
                <div className="flex items-center justify-between gap-4 mb-4"><div><h2 className="font-mono font-bold text-accent">RELATED INCIDENTS</h2><p className="text-xs text-muted-foreground mt-1">Incidents containing telemetry associated with this IOC.</p></div></div>
                {context.incidents.length ? <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">{context.incidents.map(incident => <Link key={incident.id} href={`/incidents?incident=${encodeURIComponent(incident.id)}`}><div className="rounded border border-border/30 p-4 hover:border-accent/50 transition-colors cursor-pointer"><div className="flex justify-between gap-3"><p className="font-medium">{incident.title}</p><Badge className={`${severityClass[incident.severity]} border`}>{incident.severity}</Badge></div><p className="text-xs text-muted-foreground mt-2 font-mono">{incident.id} · {incident.status} · {incident.eventIds.length} events</p><div className="flex items-center gap-1 mt-3 text-xs text-accent"><ExternalLink className="w-3 h-3" /> Open incident</div></div></Link>)}</div> : <p className="text-sm text-muted-foreground">No incidents are currently associated with this indicator.</p>}
              </Card>
            </>
          )}
        </div>
      </main>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return <Card className="glass border border-border/20 p-4"><p className="text-xs text-muted-foreground uppercase font-mono">{label}</p><p className="text-2xl font-mono font-bold mt-2 text-accent">{value}</p></Card>;
}
