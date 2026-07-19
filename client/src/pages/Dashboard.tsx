import { useState } from 'react';
import { AlertCircle, Zap, Wifi, Shield, Activity, TrendingUp } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

/**
 * J.A.R.V.I.S. Dashboard
 * Main command center displaying system status, active alerts, and threat intelligence
 * Design: Dark holographic interface with neon cyan accents and glassmorphism effects
 */

export default function Dashboard() {
  const [activeAlerts] = useState([
    { id: 1, severity: 'critical', message: 'Unauthorized SSH Access Attempt', time: '2 min ago' },
    { id: 2, severity: 'high', message: 'Suspicious PowerShell Execution', time: '5 min ago' },
    { id: 3, severity: 'medium', message: 'Unusual Network Traffic Pattern', time: '12 min ago' },
  ]);

  const [systemMetrics] = useState({
    cpu: 42,
    memory: 68,
    networkHealth: 95,
    detectionStatus: 'Active',
    activeIncidents: 3,
  });

  const getSeverityColor = (severity: string) => {
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
        {/* Top Status Bar */}
        <div className="glass border-b sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold font-mono">J.A.R.V.I.S.</h1>
                <p className="text-sm text-muted-foreground">Joint Attack & Response Virtual Intelligence System</p>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
                <span className="text-sm font-mono">SYSTEM ONLINE</span>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          {/* System Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
            <MetricCard 
              label="CPU Usage" 
              value={`${systemMetrics.cpu}%`} 
              icon={<Zap className="w-5 h-5" />}
              color="cyan"
            />
            <MetricCard 
              label="Memory" 
              value={`${systemMetrics.memory}%`} 
              icon={<Activity className="w-5 h-5" />}
              color="blue"
            />
            <MetricCard 
              label="Network Health" 
              value={`${systemMetrics.networkHealth}%`} 
              icon={<Wifi className="w-5 h-5" />}
              color="green"
            />
            <MetricCard 
              label="Detection Status" 
              value={systemMetrics.detectionStatus} 
              icon={<Shield className="w-5 h-5" />}
              color="cyan"
            />
            <MetricCard 
              label="Active Incidents" 
              value={systemMetrics.activeIncidents} 
              icon={<AlertCircle className="w-5 h-5" />}
              color="red"
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Left Panel - Alerts */}
            <div className="lg:col-span-1">
              <Card className="glass glow-border">
                <div className="p-6">
                  <h2 className="text-lg font-mono font-bold mb-4 text-accent">ACTIVE ALERTS</h2>
                  <div className="space-y-3">
                    {activeAlerts.map((alert) => (
                      <div 
                        key={alert.id}
                        className={`p-3 rounded border ${getSeverityColor(alert.severity)} transition-all hover:shadow-lg`}
                      >
                        <p className="text-sm font-medium">{alert.message}</p>
                        <p className="text-xs mt-1 opacity-70">{alert.time}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </Card>
            </div>

            {/* Center Panel - Main Visualization */}
            <div className="lg:col-span-1">
              <Card className="glass glow-border h-full">
                <div className="p-6 flex flex-col items-center justify-center h-full">
                  <div className="relative w-48 h-48 mb-6">
                    {/* Animated globe placeholder */}
                    <div className="absolute inset-0 rounded-full border-2 border-accent/30 animate-spin" style={{ animationDuration: '20s' }}></div>
                    <div className="absolute inset-4 rounded-full border border-accent/50"></div>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="text-center">
                        <TrendingUp className="w-8 h-8 mx-auto text-accent mb-2" />
                        <p className="text-xs font-mono text-muted-foreground">THREAT MAP</p>
                      </div>
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground text-center">Real-time threat intelligence and attack origins</p>
                </div>
              </Card>
            </div>

            {/* Right Panel - Risk & Trends */}
            <div className="lg:col-span-1">
              <Card className="glass glow-border">
                <div className="p-6">
                  <h2 className="text-lg font-mono font-bold mb-4 text-accent">RISK ASSESSMENT</h2>
                  <div className="space-y-4">
                    <div>
                      <p className="text-sm text-muted-foreground mb-2">Overall Risk Score</p>
                      <div className="text-3xl font-mono font-bold text-orange-400">7.2/10</div>
                      <div className="w-full bg-card/50 rounded h-2 mt-2 overflow-hidden">
                        <div className="bg-gradient-to-r from-yellow-500 to-orange-500 h-full" style={{ width: '72%' }}></div>
                      </div>
                    </div>
                    <div className="pt-4 border-t border-border/20">
                      <p className="text-sm text-muted-foreground mb-3">Top Threats</p>
                      <div className="space-y-2">
                        <div className="flex justify-between text-sm">
                          <span>Brute Force</span>
                          <Badge variant="outline" className="bg-red-500/10 text-red-300">High</Badge>
                        </div>
                        <div className="flex justify-between text-sm">
                          <span>Data Exfiltration</span>
                          <Badge variant="outline" className="bg-orange-500/10 text-orange-300">Medium</Badge>
                        </div>
                        <div className="flex justify-between text-sm">
                          <span>Privilege Escalation</span>
                          <Badge variant="outline" className="bg-yellow-500/10 text-yellow-300">Medium</Badge>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </div>

          {/* Detection Feed */}
          <div className="mt-8">
            <Card className="glass glow-border">
              <div className="p-6">
                <h2 className="text-lg font-mono font-bold mb-4 text-accent">DETECTION FEED</h2>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {[...Array(5)].map((_, i) => (
                    <div key={i} className="p-3 bg-card/30 rounded border border-border/20 text-sm font-mono text-xs">
                      <span className="text-accent">[{new Date().toLocaleTimeString()}]</span>
                      <span className="ml-2 text-muted-foreground">Process creation detected: svchost.exe</span>
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
