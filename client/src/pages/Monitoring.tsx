import { useEffect, useMemo, useState } from 'react';
import { Activity, Wifi, Server, Lock, ShieldAlert, Radio } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { securityStore } from '@/security/securityStore';
import type { SecurityEvent, SecuritySeverity, SecurityStoreSnapshot } from '@/security/types';

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

export default function Monitoring() {
  const [devices] = useState<Device[]>(initialDevices);
  const [snapshot, setSnapshot] = useState<SecurityStoreSnapshot>(securityStore.getSnapshot());

  useEffect(() => securityStore.subscribe(setSnapshot), []);

  const securityEvents = useMemo(() => snapshot.events.slice(0, 20), [snapshot.events]);
  const warningDevices = devices.filter((device) => device.status === 'warning').length;
  const highRiskEvents = securityEvents.filter((event) => ['critical', 'high'].includes(event.severity)).length;

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
                <p className="text-sm text-muted-foreground">Real-time network and endpoint telemetry</p>
              </div>
              <Badge className="bg-green-500/10 text-green-300 border border-green-500/30 gap-2">
                <Radio className="w-3 h-3 animate-pulse" />
                LIVE
              </Badge>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <SummaryCard label="Total Devices" value={devices.length} icon={<Server className="w-5 h-5" />} />
            <SummaryCard label="Online" value={devices.filter((d) => d.status === 'online').length} icon={<Activity className="w-5 h-5" />} color="green" />
            <SummaryCard label="Warnings" value={warningDevices} icon={<Wifi className="w-5 h-5" />} color="yellow" />
            <SummaryCard label="Security Events" value={snapshot.events.length} icon={<ShieldAlert className="w-5 h-5" />} color={highRiskEvents > 0 ? 'red' : undefined} />
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
                          {[
                            ['CPU', device.cpu, 'bg-cyan-500'],
                            ['Memory', device.memory, 'bg-blue-500'],
                            ['Network', device.network, 'bg-green-500'],
                          ].map(([label, value, barClass]) => (
                            <div key={label as string}>
                              <p className="text-muted-foreground mb-1">{label as string}</p>
                              <div className="w-full bg-card/50 rounded h-1.5 overflow-hidden">
                                <div className={`${barClass as string} h-full`} style={{ width: `${value as number}%` }} />
                              </div>
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
                  <h2 className="text-lg font-mono font-bold mb-4 text-accent">NETWORK HEALTH</h2>
                  <div className="space-y-4">
                    <div>
                      <p className="text-sm text-muted-foreground mb-2">Bandwidth Usage</p>
                      <p className="text-2xl font-mono font-bold text-cyan-400">847 Mbps</p>
                      <p className="text-xs text-muted-foreground mt-1">of 1000 Mbps</p>
                    </div>
                    <div className="pt-4 border-t border-border/20">
                      <p className="text-sm text-muted-foreground mb-2">Packet Loss</p>
                      <p className="text-2xl font-mono font-bold text-green-400">0.02%</p>
                    </div>
                    <div className="pt-4 border-t border-border/20">
                      <p className="text-sm text-muted-foreground mb-2">Latency</p>
                      <p className="text-2xl font-mono font-bold text-blue-400">12ms</p>
                    </div>
                    <div className="pt-4 border-t border-border/20">
                      <p className="text-sm text-muted-foreground mb-2">High-Risk Events</p>
                      <p className="text-2xl font-mono font-bold text-orange-400">{highRiskEvents}</p>
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </div>

          <div className="mt-8">
            <Card className="glass glow-border">
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h2 className="text-lg font-mono font-bold text-accent">LIVE SECURITY EVENTS</h2>
                    <p className="text-xs text-muted-foreground mt-1">Events produced by Attack Lab and future telemetry adapters</p>
                  </div>
                  <Badge className="bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">{securityEvents.length} loaded</Badge>
                </div>

                {securityEvents.length === 0 ? (
                  <div className="py-10 text-center">
                    <Radio className="w-8 h-8 mx-auto mb-3 text-muted-foreground" />
                    <p className="font-mono text-sm text-muted-foreground">No live security events yet.</p>
                    <p className="text-xs text-muted-foreground mt-1">Launch a scenario from Attack Lab to populate this feed.</p>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border/20">
                          <th className="text-left py-2 px-3 font-mono text-muted-foreground">Time</th>
                          <th className="text-left py-2 px-3 font-mono text-muted-foreground">Event</th>
                          <th className="text-left py-2 px-3 font-mono text-muted-foreground">Source</th>
                          <th className="text-left py-2 px-3 font-mono text-muted-foreground">Destination</th>
                          <th className="text-left py-2 px-3 font-mono text-muted-foreground">Severity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {securityEvents.map((event) => (
                          <tr key={event.id} className="border-b border-border/10 hover:bg-card/20 transition-colors">
                            <td className="py-2 px-3 font-mono text-xs text-muted-foreground">{formatTime(event.timestamp)}</td>
                            <td className="py-2 px-3 text-xs">{event.eventType}</td>
                            <td className="py-2 px-3 font-mono text-xs">{event.source}</td>
                            <td className="py-2 px-3 font-mono text-xs">{event.destination ?? '—'}</td>
                            <td className="py-2 px-3">
                              <Badge className={`${getSeverityColor(event.severity)} border text-[10px]`}>{event.severity.toUpperCase()}</Badge>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}

interface SummaryCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  color?: 'green' | 'yellow' | 'red';
}

function SummaryCard({ label, value, icon, color }: SummaryCardProps) {
  const colorClass = color === 'green'
    ? 'text-green-400'
    : color === 'yellow'
      ? 'text-yellow-400'
      : color === 'red'
        ? 'text-red-400'
        : 'text-cyan-400';

  return (
    <Card className="glass border border-border/20 p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-muted-foreground font-mono uppercase">{label}</p>
          <p className={`text-2xl font-mono font-bold mt-1 ${colorClass}`}>{value}</p>
        </div>
        <div className={`${colorClass} opacity-50`}>{icon}</div>
      </div>
    </Card>
  );
}
