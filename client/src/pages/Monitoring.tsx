import { useEffect, useMemo, useState } from 'react';
import { Activity, Wifi, Server, Lock, ShieldAlert, Radio, Search, Target, Crosshair } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { securityStore } from '@/security/securityStore';
import type { DetectionResult, SecurityEvent, SecuritySeverity, SecurityStoreSnapshot } from '@/security/types';

interface Device {
  id: number;
  name: string;
  type: 'server' | 'endpoint' | 'iot';
  status: 'online' | 'offline' | 'warning';
  cpu: number;
  memory: number;
  network: number;
}

const initialDevices: Device[] = [
  { id: 1, name: 'web-server-01', type: 'server', status: 'online', cpu: 35, memory: 62, network: 45 },
  { id: 2, name: 'db-server-01', type: 'server', status: 'online', cpu: 28, memory: 78, network: 12 },
  { id: 3, name: 'desktop-01', type: 'endpoint', status: 'online', cpu: 15, memory: 41, network: 8 },
  { id: 4, name: 'laptop-02', type: 'endpoint', status: 'warning', cpu: 92, memory: 89, network: 75 },
  { id: 5, name: 'iot-device-01', type: 'iot', status: 'online', cpu: 5, memory: 22, network: 3 },
];

const severityOrder: SecuritySeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

export default function Monitoring() {
  const [devices] = useState<Device[]>(initialDevices);
  const [snapshot, setSnapshot] = useState<SecurityStoreSnapshot>(securityStore.getSnapshot());
  const [severityFilter, setSeverityFilter] = useState<'all' | SecuritySeverity>('all');
  const [ruleFilter, setRuleFilter] = useState('all');
  const [search, setSearch] = useState('');

  useEffect(() => securityStore.subscribe(setSnapshot), []);

  const securityEvents = useMemo(() => snapshot.events.slice(0, 20), [snapshot.events]);
  const warningDevices = devices.filter((device) => device.status === 'warning').length;
  const highRiskEvents = securityEvents.filter((event) => ['critical', 'high'].includes(event.severity)).length;

  const detectionRules = useMemo(
    () => Array.from(new Set(snapshot.detections.map((detection) => detection.ruleName))).sort(),
    [snapshot.detections]
  );

  const filteredDetections = useMemo(() => {
    const query = search.trim().toLowerCase();
    return snapshot.detections
      .filter((detection) => severityFilter === 'all' || detection.severity === severityFilter)
      .filter((detection) => ruleFilter === 'all' || detection.ruleName === ruleFilter)
      .filter((detection) => !query || `${detection.ruleName} ${detection.title} ${detection.description} ${detection.sourceIP ?? ''} ${detection.destinationIP ?? ''}`.toLowerCase().includes(query))
      .slice(0, 50);
  }, [snapshot.detections, severityFilter, ruleFilter, search]);

  const detectionStats = useMemo(() => {
    const stats: Record<SecuritySeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    snapshot.detections.forEach((detection) => { stats[detection.severity] += 1; });
    return stats;
  }, [snapshot.detections]);

  const mitreCoverage = useMemo(() => {
    const counts = new Map<string, number>();
    snapshot.detections.forEach((detection) => detection.mitreTechniques.forEach((technique) => counts.set(technique, (counts.get(technique) ?? 0) + 1)));
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [snapshot.detections]);

  const averageConfidence = useMemo(() => {
    if (!snapshot.detections.length) return 0;
    return Math.round(snapshot.detections.reduce((sum, detection) => sum + detection.confidence, 0) / snapshot.detections.length);
  }, [snapshot.detections]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'bg-green-500/20 text-green-300 border-green-500/30';
      case 'offline': return 'bg-gray-500/20 text-gray-300 border-gray-500/30';
      case 'warning': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'normal': return 'text-gray-400';
      case 'suspicious': return 'text-orange-400';
      case 'alert': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getSeverityColor = (severity: SecuritySeverity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      default: return 'bg-gray-500/20 text-gray-300 border-gray-500/30';
    }
  };

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'server': return <Server className="w-4 h-4" />;
      case 'endpoint': return <Activity className="w-4 h-4" />;
      case 'iot': return <Lock className="w-4 h-4" />;
      default: return <Wifi className="w-4 h-4" />;
    }
  };

  const formatTime = (value: string) => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString();
  };

  const eventStatus = (event: SecurityEvent) => {
    if (event.severity === 'critical') return 'alert';
    if (event.severity === 'high') return 'suspicious';
    return 'normal';
  };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <div className="glass border-b sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold font-mono">MONITORING</h1>
                <p className="text-sm text-muted-foreground">Real-time telemetry, detections and SOC visibility</p>
              </div>
              <Badge className="bg-green-500/10 text-green-300 border border-green-500/30 gap-2">
                <Radio className="w-3 h-3 animate-pulse" /> LIVE
              </Badge>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <SummaryCard label="Total Devices" value={devices.length} icon={<Server className="w-5 h-5" />} />
            <SummaryCard label="Online" value={devices.filter((d) => d.status === 'online').length} icon={<Activity className="w-5 h-5" />} color="green" />
            <SummaryCard label="Warnings" value={warningDevices} icon={<Wifi className="w-5 h-5" />} color="yellow" />
            <SummaryCard label="Detections" value={snapshot.detections.length} icon={<Crosshair className="w-5 h-5" />} color={snapshot.detections.some((d) => d.severity === 'critical') ? 'red' : undefined} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2">
              <Card className="glass glow-border">
                <div className="p-6">
                  <h2 className="text-lg font-mono font-bold mb-4 text-accent">CONNECTED DEVICES</h2>
                  <div className="space-y-3">
                    {devices.map((device) => (
                      <div key={device.id} className="p-4 bg-card/30 rounded border border-border/20 hover:border-accent/30 transition-all">
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex items-center gap-3">
                            {getDeviceIcon(device.type)}
                            <div>
                              <p className="font-mono font-bold text-sm">{device.name}</p>
                              <p className="text-xs text-muted-foreground capitalize">{device.type}</p>
                            </div>
                          </div>
                          <Badge className={`${getStatusColor(device.status)} border capitalize`}>{device.status}</Badge>
                        </div>
                        <div className="grid grid-cols-3 gap-3 text-xs">
                          {[['CPU', device.cpu], ['Memory', device.memory], ['Network', device.network]].map(([label, value]) => (
                            <div key={label as string}>
                              <p className="text-muted-foreground mb-1">{label as string}</p>
                              <div className="w-full bg-card/50 rounded h-1.5 overflow-hidden"><div className="bg-accent h-full" style={{ width: `${value as number}%` }} /></div>
                              <p className="text-xs mt-1 font-mono">{value as number}%</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </Card>
            </div>

            <div className="lg:col-span-1">
              <Card className="glass glow-border h-full">
                <div className="p-6">
                  <h2 className="text-lg font-mono font-bold mb-4 text-accent">SOC HEALTH</h2>
                  <div className="space-y-4">
                    <div><p className="text-sm text-muted-foreground mb-2">Telemetry Events</p><p className="text-2xl font-mono font-bold text-cyan-400">{snapshot.events.length}</p></div>
                    <div className="pt-4 border-t border-border/20"><p className="text-sm text-muted-foreground mb-2">High-Risk Events</p><p className="text-2xl font-mono font-bold text-orange-400">{highRiskEvents}</p></div>
                    <div className="pt-4 border-t border-border/20"><p className="text-sm text-muted-foreground mb-2">Detection Confidence</p><p className="text-2xl font-mono font-bold text-green-400">{averageConfidence}%</p></div>
                    <div className="pt-4 border-t border-border/20"><p className="text-sm text-muted-foreground mb-2">Backend</p><p className={`text-sm font-mono font-bold ${snapshot.backendOnline ? 'text-green-400' : 'text-yellow-400'}`}>{snapshot.backendOnline ? 'CONNECTED' : 'LOCAL / OFFLINE'}</p></div>
                  </div>
                </div>
              </Card>
            </div>
          </div>

          <div className="mt-8">
            <Card className="glass glow-border">
              <div className="p-6">
                <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-6">
                  <div><h2 className="text-lg font-mono font-bold text-accent">DETECTION CENTER</h2><p className="text-xs text-muted-foreground mt-1">Deterministic detections generated from persisted security telemetry</p></div>
                  <div className="flex flex-wrap gap-2">
                    {severityOrder.map((severity) => (
                      <button key={severity} onClick={() => setSeverityFilter(severityFilter === severity ? 'all' : severity)} className={`px-2.5 py-1 rounded border text-[10px] font-mono uppercase transition-all ${severityFilter === severity ? getSeverityColor(severity) : 'border-border/30 text-muted-foreground hover:text-foreground'}`}>
                        {severity} {detectionStats[severity]}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-[1fr_220px] gap-3 mb-5">
                  <div className="relative"><Search className="absolute left-3 top-2.5 w-4 h-4 text-muted-foreground" /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search detections, indicators or IPs..." className="w-full h-9 rounded border border-border/30 bg-card/30 pl-9 pr-3 text-xs outline-none focus:border-accent/50" /></div>
                  <select value={ruleFilter} onChange={(event) => setRuleFilter(event.target.value)} className="h-9 rounded border border-border/30 bg-card/30 px-3 text-xs font-mono outline-none focus:border-accent/50"><option value="all">ALL DETECTION RULES</option>{detectionRules.map((rule) => <option key={rule} value={rule}>{rule}</option>)}</select>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-5">
                  {severityOrder.map((severity) => <div key={severity} className="rounded border border-border/20 bg-card/20 p-3"><p className="text-[10px] text-muted-foreground uppercase font-mono">{severity}</p><p className="text-xl font-mono font-bold mt-1">{detectionStats[severity]}</p></div>)}
                </div>

                {filteredDetections.length === 0 ? <div className="py-10 text-center"><Target className="w-8 h-8 mx-auto mb-3 text-muted-foreground" /><p className="font-mono text-sm text-muted-foreground">No detections match the current filters.</p></div> : (
                  <div className="space-y-2">
                    {filteredDetections.map((detection: DetectionResult) => (
                      <div key={detection.id} className="rounded border border-border/20 bg-card/20 hover:bg-card/30 transition-colors p-4">
                        <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
                          <div className="min-w-0"><div className="flex items-center gap-2 flex-wrap"><Badge className={`${getSeverityColor(detection.severity)} border text-[10px]`}>{detection.severity.toUpperCase()}</Badge><span className="font-mono text-sm font-bold">{detection.ruleName}</span><span className="text-[10px] text-muted-foreground font-mono">{formatTime(detection.timestamp)}</span></div><p className="text-sm mt-2">{detection.title}</p><p className="text-xs text-muted-foreground mt-1">{detection.description}</p></div>
                          <div className="shrink-0 text-right"><p className="text-[10px] text-muted-foreground uppercase">Confidence</p><p className="font-mono font-bold text-accent">{Math.round(detection.confidence)}%</p></div>
                        </div>
                        <div className="flex flex-wrap gap-2 mt-3">{detection.mitreTechniques.map((technique) => <Badge key={technique} variant="outline" className="text-[10px] font-mono">{technique}</Badge>)}{detection.sourceIP && <span className="text-[10px] font-mono text-muted-foreground">SRC {detection.sourceIP}</span>}{detection.destinationIP && <span className="text-[10px] font-mono text-muted-foreground">DST {detection.destinationIP}</span>}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mt-8">
            <Card className="glass glow-border lg:col-span-1"><div className="p-6"><h2 className="text-lg font-mono font-bold text-accent mb-4">MITRE COVERAGE</h2>{mitreCoverage.length === 0 ? <p className="text-xs text-muted-foreground">No ATT&CK techniques observed yet.</p> : <div className="space-y-3">{mitreCoverage.map(([technique, count]) => <div key={technique} className="flex items-center justify-between"><span className="font-mono text-xs">{technique}</span><Badge variant="outline" className="text-[10px]">{count} detection{count === 1 ? '' : 's'}</Badge></div>)}</div>}</div></Card>
            <Card className="glass glow-border lg:col-span-2"><div className="p-6"><div className="flex items-center justify-between mb-4"><div><h2 className="text-lg font-mono font-bold text-accent">LIVE SECURITY EVENTS</h2><p className="text-xs text-muted-foreground mt-1">Events produced by Attack Lab and telemetry adapters</p></div><Badge className="bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">{securityEvents.length} loaded</Badge></div>{securityEvents.length === 0 ? <div className="py-8 text-center"><Radio className="w-8 h-8 mx-auto mb-3 text-muted-foreground" /><p className="font-mono text-sm text-muted-foreground">No live security events yet.</p></div> : <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b border-border/20"><th className="text-left py-2 px-3 font-mono text-muted-foreground">Time</th><th className="text-left py-2 px-3 font-mono text-muted-foreground">Event</th><th className="text-left py-2 px-3 font-mono text-muted-foreground">Source</th><th className="text-left py-2 px-3 font-mono text-muted-foreground">Destination</th><th className="text-left py-2 px-3 font-mono text-muted-foreground">Severity</th></tr></thead><tbody>{securityEvents.map((event) => <tr key={event.id} className="border-b border-border/10 hover:bg-card/20 transition-colors"><td className="py-2 px-3 font-mono text-xs text-muted-foreground">{formatTime(event.timestamp)}</td><td className="py-2 px-3 text-xs">{event.type}</td><td className="py-2 px-3 font-mono text-xs">{event.source}</td><td className="py-2 px-3 font-mono text-xs">{event.destinationIP ?? '—'}</td><td className="py-2 px-3"><Badge className={`${getSeverityColor(event.severity)} border text-[10px]`}>{event.severity.toUpperCase()}</Badge></td></tr>)}</tbody></table></div>}</div></Card>
          </div>
        </div>
      </main>
    </div>
  );
}

interface SummaryCardProps { label: string; value: string | number; icon: React.ReactNode; color?: 'green' | 'yellow' | 'red'; }

function SummaryCard({ label, value, icon, color }: SummaryCardProps) {
  const colorClass = color === 'green' ? 'text-green-400' : color === 'yellow' ? 'text-yellow-400' : color === 'red' ? 'text-red-400' : 'text-cyan-400';
  return <Card className="glass border border-border/20 p-4"><div className="flex items-center justify-between"><div><p className="text-xs text-muted-foreground font-mono uppercase">{label}</p><p className={`text-2xl font-mono font-bold mt-1 ${colorClass}`}>{value}</p></div><div className={`${colorClass} opacity-50`}>{icon}</div></div></Card>;
}
