import { useState } from 'react';
import { Activity, Wifi, Server, Lock } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

/**
 * J.A.R.V.I.S. Monitoring
 * Real-time network and endpoint monitoring with live telemetry
 * Design: Dark holographic interface with data stream animations
 */

interface Device {
  id: number;
  name: string;
  type: 'server' | 'endpoint' | 'iot';
  status: 'online' | 'offline' | 'warning';
  cpu: number;
  memory: number;
  network: number;
}

export default function Monitoring() {
  const [devices] = useState<Device[]>([
    { id: 1, name: 'web-server-01', type: 'server', status: 'online', cpu: 35, memory: 62, network: 45 },
    { id: 2, name: 'db-server-01', type: 'server', status: 'online', cpu: 28, memory: 78, network: 12 },
    { id: 3, name: 'desktop-01', type: 'endpoint', status: 'online', cpu: 15, memory: 41, network: 8 },
    { id: 4, name: 'laptop-02', type: 'endpoint', status: 'warning', cpu: 92, memory: 89, network: 75 },
    { id: 5, name: 'iot-device-01', type: 'iot', status: 'online', cpu: 5, memory: 22, network: 3 },
  ]);

  const [networkEvents] = useState([
    { time: '14:32:15', event: 'DNS Query', source: '192.168.1.10', destination: 'google.com', status: 'normal' },
    { time: '14:32:18', event: 'SSH Connection', source: '192.168.1.5', destination: '10.0.0.1:22', status: 'suspicious' },
    { time: '14:32:22', event: 'HTTP Request', source: '192.168.1.15', destination: '8.8.8.8:80', status: 'normal' },
    { time: '14:32:25', event: 'Port Scan', source: '192.168.1.20', destination: '10.0.0.0/24', status: 'alert' },
    { time: '14:32:28', event: 'HTTPS Connection', source: '192.168.1.8', destination: 'github.com:443', status: 'normal' },
  ]);

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

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'server': return <Server className="w-4 h-4" />;
      case 'endpoint': return <Activity className="w-4 h-4" />;
      case 'iot': return <Lock className="w-4 h-4" />;
      default: return <Wifi className="w-4 h-4" />;
    }
  };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      
      <main className="flex-1 overflow-auto">
        {/* Header */}
        <div className="glass border-b sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div>
              <h1 className="text-3xl font-bold font-mono">MONITORING</h1>
              <p className="text-sm text-muted-foreground">Real-time network and endpoint telemetry</p>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <SummaryCard label="Total Devices" value="5" icon={<Server className="w-5 h-5" />} />
            <SummaryCard label="Online" value="4" icon={<Activity className="w-5 h-5" />} color="green" />
            <SummaryCard label="Warnings" value="1" icon={<Wifi className="w-5 h-5" />} color="yellow" />
            <SummaryCard label="Network Events" value="2.4K" icon={<Lock className="w-5 h-5" />} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Device List */}
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
                          <Badge className={`${getStatusColor(device.status)} border capitalize`}>
                            {device.status}
                          </Badge>
                        </div>
                        <div className="grid grid-cols-3 gap-3 text-xs">
                          <div>
                            <p className="text-muted-foreground mb-1">CPU</p>
                            <div className="w-full bg-card/50 rounded h-1.5 overflow-hidden">
                              <div className="bg-cyan-500 h-full" style={{ width: `${device.cpu}%` }}></div>
                            </div>
                            <p className="text-xs mt-1 font-mono">{device.cpu}%</p>
                          </div>
                          <div>
                            <p className="text-muted-foreground mb-1">Memory</p>
                            <div className="w-full bg-card/50 rounded h-1.5 overflow-hidden">
                              <div className="bg-blue-500 h-full" style={{ width: `${device.memory}%` }}></div>
                            </div>
                            <p className="text-xs mt-1 font-mono">{device.memory}%</p>
                          </div>
                          <div>
                            <p className="text-muted-foreground mb-1">Network</p>
                            <div className="w-full bg-card/50 rounded h-1.5 overflow-hidden">
                              <div className="bg-green-500 h-full" style={{ width: `${device.network}%` }}></div>
                            </div>
                            <p className="text-xs mt-1 font-mono">{device.network}%</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </Card>
            </div>

            {/* Network Health */}
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
                  </div>
                </div>
              </Card>
            </div>
          </div>

          {/* Network Events */}
          <div className="mt-8">
            <Card className="glass glow-border">
              <div className="p-6">
                <h2 className="text-lg font-mono font-bold mb-4 text-accent">NETWORK EVENTS</h2>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border/20">
                        <th className="text-left py-2 px-3 font-mono text-muted-foreground">Time</th>
                        <th className="text-left py-2 px-3 font-mono text-muted-foreground">Event</th>
                        <th className="text-left py-2 px-3 font-mono text-muted-foreground">Source</th>
                        <th className="text-left py-2 px-3 font-mono text-muted-foreground">Destination</th>
                        <th className="text-left py-2 px-3 font-mono text-muted-foreground">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {networkEvents.map((event, i) => (
                        <tr key={i} className="border-b border-border/10 hover:bg-card/20 transition-colors">
                          <td className="py-2 px-3 font-mono text-xs text-muted-foreground">{event.time}</td>
                          <td className="py-2 px-3 text-xs">{event.event}</td>
                          <td className="py-2 px-3 font-mono text-xs">{event.source}</td>
                          <td className="py-2 px-3 font-mono text-xs">{event.destination}</td>
                          <td className={`py-2 px-3 font-mono text-xs ${getStatusColor(event.status)}`}>{event.status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
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
  color?: 'green' | 'yellow';
}

function SummaryCard({ label, value, icon, color }: SummaryCardProps) {
  const colorClass = color === 'green' ? 'text-green-400' : color === 'yellow' ? 'text-yellow-400' : 'text-cyan-400';

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
