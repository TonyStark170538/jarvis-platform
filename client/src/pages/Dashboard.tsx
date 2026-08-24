import { useEffect, useMemo, useState } from 'react';
import { AlertCircle, Zap, Wifi, Shield, Activity, TrendingUp, Radio } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { securityStore } from '@/security/securityStore';
import type { SecuritySeverity, SecurityStoreSnapshot } from '@/security/types';

export default function Dashboard() {
  const [snapshot, setSnapshot] = useState<SecurityStoreSnapshot>(securityStore.getSnapshot());

  useEffect(() => securityStore.subscribe(setSnapshot), []);

  const activeDetections = snapshot.detections.filter((detection) => detection.severity !== 'low');
  const criticalCount = snapshot.detections.filter((detection) => detection.severity === 'critical').length;
  const highCount = snapshot.detections.filter((detection) => detection.severity === 'high').length;
  const riskScore = useMemo(() => {
    if (snapshot.events.length === 0) return 0;
    const weights: Record<SecuritySeverity, number> = {
  info: 0,
  low: 1,
  medium: 3,
  high: 6,
  critical: 10,
};
    const weighted = snapshot.events.reduce((sum, event) => sum + weights[event.severity], 0);
    return Math.min(10, Number((weighted / Math.max(snapshot.events.length, 1)).toFixed(1)));
  }, [snapshot.events]);

  const getSeverityColor = (severity: SecuritySeverity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      default: return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
    }
  };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <div className="glass border-b sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold font-mono">J.A.R.V.I.S.</h1>
                <p className="text-sm text-muted-foreground">Joint Attack & Response Virtual Intelligence System</p>
              </div>
              <div className="flex items-center gap-2">
                <div className={`w-3 h-3 rounded-full ${snapshot.isSimulationRunning ? 'bg-yellow-500' : 'bg-green-500'} animate-pulse`} />
                <span className="text-sm font-mono">{snapshot.isSimulationRunning ? 'SIMULATION ACTIVE' : 'SYSTEM ONLINE'}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
            <MetricCard label="Security Events" value={snapshot.events.length} icon={<Zap className="w-5 h-5" />} color="cyan" />
            <MetricCard label="Detections" value={snapshot.detections.length} icon={<Activity className="w-5 h-5" />} color="blue" />
            <MetricCard label="High Risk" value={activeDetections.length} icon={<Wifi className="w-5 h-5" />} color="green" />
            <MetricCard label="Detection Status" value="Active" icon={<Shield className="w-5 h-5" />} color="cyan" />
            <MetricCard label="Critical" value={criticalCount} icon={<AlertCircle className="w-5 h-5" />} color="red" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-1">
              <Card className="glass glow-border">
                <div className="p-6">
                  <h2 className="text-lg font-mono font-bold mb-4 text-accent">ACTIVE DETECTIONS</h2>
                  <div className="space-y-3">
                    {activeDetections.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No detections. Launch an Attack Lab scenario to generate telemetry.</p>
                    ) : activeDetections.slice(0, 5).map((detection) => (
                      <div key={detection.id} className={`p-3 rounded border ${getSeverityColor(detection.severity)}`}>
                        <p className="text-sm font-medium">{detection.title}</p>
                        <p className="text-xs mt-1 opacity-70">Confidence {detection.confidence}%</p>
                      </div>
                    ))}
                  </div>
                </div>
              </Card>
            </div>

            <div className="lg:col-span-1">
              <Card className="glass glow-border h-full">
                <div className="p-6 flex flex-col items-center justify-center h-full">
                  <div className="relative w-48 h-48 mb-6">
                    <div className="absolute inset-0 rounded-full border-2 border-accent/30 animate-spin" style={{ animationDuration: '20s' }} />
                    <div className="absolute inset-4 rounded-full border border-accent/50" />
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="text-center">
                        <TrendingUp className="w-8 h-8 mx-auto text-accent mb-2" />
                        <p className="text-xs font-mono text-muted-foreground">THREAT MAP</p>
                        <p className="text-2xl font-mono font-bold text-accent mt-2">{snapshot.events.length}</p>
                        <p className="text-[10px] text-muted-foreground">EVENTS OBSERVED</p>
                      </div>
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground text-center">Security telemetry and detection activity</p>
                </div>
              </Card>
            </div>

            <div className="lg:col-span-1">
              <Card className="glass glow-border">
                <div className="p-6">
                  <h2 className="text-lg font-mono font-bold mb-4 text-accent">RISK ASSESSMENT</h2>
                  <p className="text-sm text-muted-foreground mb-2">Current telemetry risk</p>
                  <div className="text-3xl font-mono font-bold text-orange-400">{riskScore.toFixed(1)}/10</div>
                  <div className="w-full bg-card/50 rounded h-2 mt-2 overflow-hidden">
                    <div className="bg-gradient-to-r from-yellow-500 to-orange-500 h-full transition-all" style={{ width: `${riskScore * 10}%` }} />
                  </div>
                  <div className="pt-4 mt-4 border-t border-border/20 space-y-2">
                    <div className="flex justify-between text-sm"><span>Critical</span><Badge className="bg-red-500/10 text-red-300">{criticalCount}</Badge></div>
                    <div className="flex justify-between text-sm"><span>High</span><Badge className="bg-orange-500/10 text-orange-300">{highCount}</Badge></div>
                    <div className="flex justify-between text-sm"><span>Events</span><Badge className="bg-cyan-500/10 text-cyan-300">{snapshot.events.length}</Badge></div>
                  </div>
                </div>
              </Card>
            </div>
          </div>

          <div className="mt-8">
            <Card className="glass glow-border">
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-mono font-bold text-accent">DETECTION FEED</h2>
                  <Badge className="bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 gap-2"><Radio className="w-3 h-3" />LIVE</Badge>
                </div>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {snapshot.detections.length === 0 ? (
                    <div className="p-4 bg-card/30 rounded border border-border/20 text-sm font-mono text-muted-foreground">Awaiting security telemetry...</div>
                  ) : snapshot.detections.slice(0, 10).map((detection) => (
                    <div key={detection.id} className="p-3 bg-card/30 rounded border border-border/20 text-sm font-mono">
                      <span className="text-accent">[{new Date(detection.timestamp).toLocaleTimeString()}]</span>
                      <span className="ml-2">{detection.title}</span>
                      <span className="ml-2 text-muted-foreground">— {detection.description}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}

interface MetricCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  color: 'cyan' | 'blue' | 'green' | 'red';
}

function MetricCard({ label, value, icon, color }: MetricCardProps) {
  const colorClasses = {
    cyan: 'text-cyan-400 border-cyan-500/30 shadow-[0_0_15px_rgba(102,200,255,0.2)]',
    blue: 'text-blue-400 border-blue-500/30 shadow-[0_0_15px_rgba(59,130,246,0.2)]',
    green: 'text-green-400 border-green-500/30 shadow-[0_0_15px_rgba(34,197,94,0.2)]',
    red: 'text-red-400 border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.2)]',
  };

  return (
    <Card className={`glass border ${colorClasses[color]}`}>
      <div className="p-4">
        <div className="flex items-center justify-between mb-2">
          <p className="text-xs text-muted-foreground font-mono uppercase">{label}</p>
          {icon}
        </div>
        <p className="text-2xl font-mono font-bold">{value}</p>
      </div>
    </Card>
  );
}
