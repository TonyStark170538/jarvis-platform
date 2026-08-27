import { useMemo, useState, useSyncExternalStore } from 'react';
import { Activity, Search, ShieldCheck, Target, Zap } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { DETECTION_RULES } from '@/security/detectionEngine';
import { securityStore } from '@/security/securityStore';
import type { SecuritySeverity } from '@/security/types';

const severityRank: Record<SecuritySeverity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function severityClass(severity: SecuritySeverity) {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/30';
    case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
    case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
    case 'low': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
    default: return 'bg-slate-500/20 text-slate-300 border-slate-500/30';
  }
}

export default function DetectionCenter() {
  const snapshot = useSyncExternalStore(
    securityStore.subscribe.bind(securityStore),
    securityStore.getSnapshot.bind(securityStore),
    securityStore.getSnapshot.bind(securityStore)
  );
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<'all' | SecuritySeverity>('all');

  const rules = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...DETECTION_RULES]
      .filter((rule) => severity === 'all' || rule.severity === severity)
      .filter((rule) => !q || [rule.id, rule.name, rule.description, ...rule.mitreTechniques].some((value) => value.toLowerCase().includes(q)))
      .sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
  }, [query, severity]);

  const ruleStats = useMemo(() => {
    const counts = new Map<string, number>();
    for (const detection of snapshot.detections) counts.set(detection.ruleId, (counts.get(detection.ruleId) ?? 0) + 1);
    return counts;
  }, [snapshot.detections]);

  const activeRules = DETECTION_RULES.length;
  const triggeredRules = DETECTION_RULES.filter((rule) => (ruleStats.get(rule.id) ?? 0) > 0).length;
  const coverage = activeRules ? Math.round((triggeredRules / activeRules) * 100) : 0;
  const highest = snapshot.detections.reduce<SecuritySeverity>((current, detection) => severityRank[detection.severity] > severityRank[current] ? detection.severity : current, 'info');

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <div className="glass border-b sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between gap-4">
            <div><h1 className="text-3xl font-bold font-mono">DETECTION CENTER</h1><p className="text-sm text-muted-foreground">Detection engineering, rule coverage and live trigger telemetry</p></div>
            <Badge className="bg-green-500/20 text-green-300 border-green-500/30">DETERMINISTIC ENGINE</Badge>
          </div>
        </div>
        <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Stat icon={ShieldCheck} label="Active Rules" value={activeRules} />
            <Stat icon={Activity} label="Triggered Rules" value={triggeredRules} />
            <Stat icon={Target} label="Rule Coverage" value={`${coverage}%`} />
            <Stat icon={Zap} label="Highest Severity" value={highest.toUpperCase()} />
          </div>
          <Card className="glass glow-border p-6">
            <div className="flex flex-col md:flex-row gap-3">
              <div className="relative flex-1"><Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" /><Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search rule, description, ID or MITRE technique..." className="pl-9" /></div>
              <div className="flex gap-2 flex-wrap">{(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map((value) => <Button key={value} size="sm" variant={severity === value ? 'default' : 'outline'} onClick={() => setSeverity(value)} className="uppercase">{value}</Button>)}</div>
            </div>
          </Card>
          <section>
            <div className="flex items-center justify-between mb-4"><div><h2 className="text-lg font-mono font-bold text-accent">DETECTION RULES</h2><p className="text-xs text-muted-foreground mt-1">Rules are the source of truth for deterministic security detection.</p></div><span className="text-xs text-muted-foreground font-mono">{rules.length} rule(s)</span></div>
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              {rules.map((rule) => { const triggered = ruleStats.get(rule.id) ?? 0; return <Card key={rule.id} className="glass border border-border/20 p-5"><div className="flex items-start justify-between gap-4"><div className="min-w-0"><div className="flex items-center gap-2 flex-wrap mb-2"><Badge className={`${severityClass(rule.severity)} border uppercase text-xs`}>{rule.severity}</Badge><Badge variant="outline" className="font-mono text-[10px]">{rule.id}</Badge></div><h3 className="font-mono font-bold text-base">{rule.name}</h3><p className="text-sm text-muted-foreground mt-2 leading-relaxed">{rule.description}</p></div><div className="text-right shrink-0"><p className="text-[10px] uppercase text-muted-foreground">Triggers</p><p className="text-2xl font-mono font-bold text-accent">{triggered}</p></div></div><div className="mt-4 pt-4 border-t border-border/20 flex flex-wrap gap-2">{rule.mitreTechniques.map((technique) => <Badge key={technique} variant="outline" className="font-mono text-[10px]">MITRE {technique}</Badge>)}</div></Card>; })}
            </div>
          </section>
          <Card className="glass glow-border p-6"><h2 className="text-lg font-mono font-bold text-accent mb-3">ENGINE BOUNDARY</h2><p className="text-sm text-muted-foreground leading-relaxed">J.A.R.V.I.S. evaluates security telemetry with deterministic rules. This keeps detection decisions reproducible and auditable; future AI features can explain, summarize or prioritize a match without silently replacing the rule engine.</p></Card>
        </div>
      </main>
    </div>
  );
}

function Stat({ icon: Icon, label, value }: { icon: typeof ShieldCheck; label: string; value: number | string }) {
  return <Card className="glass border border-border/20 p-4"><Icon className="w-4 h-4 text-accent mb-3" /><p className="text-xs text-muted-foreground font-mono uppercase">{label}</p><p className="text-2xl font-mono font-bold mt-1">{value}</p></Card>;
}
