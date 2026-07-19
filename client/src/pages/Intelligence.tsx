import { useState } from 'react';
import { Globe, Plus, Trash2, Copy } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import ThreatIntelligenceFeed from '@/components/ThreatIntelligenceFeed';

/**
 * J.A.R.V.I.S. Intelligence
 * Threat intelligence and IOC (Indicators of Compromise) management
 * Design: Dark holographic interface with threat data visualization
 */

interface IOC {
  id: number;
  type: 'ip' | 'domain' | 'hash' | 'url';
  value: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  dateAdded: string;
  detections: number;
}

export default function Intelligence() {
  const [iocs] = useState<IOC[]>([
    { id: 1, type: 'ip', value: '192.168.1.100', severity: 'critical', source: 'Internal Detection', dateAdded: '2 hours ago', detections: 5 },
    { id: 2, type: 'domain', value: 'malware-c2.com', severity: 'critical', source: 'Threat Feed', dateAdded: '6 hours ago', detections: 12 },
    { id: 3, type: 'hash', value: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6', severity: 'high', source: 'VirusTotal', dateAdded: '1 day ago', detections: 3 },
    { id: 4, type: 'url', value: 'http://phishing-site.com/login', severity: 'high', source: 'Email Security', dateAdded: '1 day ago', detections: 8 },
    { id: 5, type: 'ip', value: '10.0.0.50', severity: 'medium', source: 'Anomaly Detection', dateAdded: '2 days ago', detections: 1 },
  ]);

  const [threatFeeds] = useState([
    { name: 'OSINT Threat Feed', status: 'active', lastUpdate: '5 min ago', indicators: 1250 },
    { name: 'Abuse.ch Malware', status: 'active', lastUpdate: '1 hour ago', indicators: 8943 },
    { name: 'AlienVault OTX', status: 'active', lastUpdate: '2 hours ago', indicators: 15234 },
    { name: 'Custom Internal Feed', status: 'active', lastUpdate: '30 min ago', indicators: 342 },
  ]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      default: return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'ip': return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
      case 'domain': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      case 'hash': return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
      case 'url': return 'bg-green-500/20 text-green-300 border-green-500/30';
      default: return 'bg-gray-500/20 text-gray-300 border-gray-500/30';
    }
  };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      
      <main className="flex-1 overflow-auto">
        {/* Header */}
        <div className="glass border-b sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold font-mono">INTELLIGENCE</h1>
                <p className="text-sm text-muted-foreground">Threat intelligence and IOC management</p>
              </div>
              <Button className="bg-accent hover:bg-accent/90 text-background font-mono gap-2">
                <Plus className="w-4 h-4" />
                Add IOC
              </Button>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          {/* Live Threat Intelligence Feed */}
          <Card className="glass glow-border p-6 mb-8">
            <ThreatIntelligenceFeed autoRefresh={true} refreshInterval={30000} />
          </Card>

          {/* Summary Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <StatCard label="Total IOCs" value={iocs.length} />
            <StatCard label="Critical" value={iocs.filter(i => i.severity === 'critical').length} color="red" />
            <StatCard label="High" value={iocs.filter(i => i.severity === 'high').length} color="orange" />
            <StatCard label="Total Detections" value={iocs.reduce((sum, i) => sum + i.detections, 0)} color="cyan" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
            {/* IOC Search */}
            <div className="lg:col-span-2">
              <Card className="glass glow-border p-6 mb-6">
                <h2 className="text-lg font-mono font-bold mb-4 text-accent">IOC LOOKUP</h2>
                <div className="flex gap-2">
                  <Input
                    placeholder="Search IP, domain, hash, or URL..."
                    className="bg-card/30 border-border/20 text-foreground placeholder:text-muted-foreground"
                  />
                  <Button className="bg-accent hover:bg-accent/90 text-background">Search</Button>
                </div>
              </Card>

              {/* IOC List */}
              <h2 className="text-lg font-mono font-bold mb-4 text-accent">INDICATORS OF COMPROMISE</h2>
              <div className="space-y-3">
                {iocs.map((ioc) => (
                  <Card key={ioc.id} className="glass border border-border/20 p-4 hover:shadow-lg transition-all">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge className={`${getTypeColor(ioc.type)} border uppercase text-xs`}>
                            {ioc.type}
                          </Badge>
                          <Badge className={`${getSeverityColor(ioc.severity)} border uppercase text-xs`}>
                            {ioc.severity}
                          </Badge>
                        </div>
                        <p className="font-mono text-sm break-all">{ioc.value}</p>
                        <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
                          <span>Source: {ioc.source}</span>
                          <span>Added: {ioc.dateAdded}</span>
                          <span className="text-accent">Detections: {ioc.detections}</span>
                        </div>
                      </div>
                      <div className="flex gap-2 ml-4">
                        <Button size="sm" variant="ghost" className="text-muted-foreground hover:text-foreground">
                          <Copy className="w-4 h-4" />
                        </Button>
                        <Button size="sm" variant="ghost" className="text-muted-foreground hover:text-destructive">
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                  </Card>
                ))}
              </div>
            </div>

            {/* Threat Feeds */}
            <div>
              <Card className="glass glow-border p-6">
                <h2 className="text-lg font-mono font-bold mb-4 text-accent">THREAT FEEDS</h2>
                <div className="space-y-3">
                  {threatFeeds.map((feed, i) => (
                    <div key={i} className="p-3 bg-card/30 rounded border border-border/20">
                      <div className="flex items-start justify-between mb-2">
                        <p className="font-mono text-sm font-bold">{feed.name}</p>
                        <Badge className="bg-green-500/20 text-green-300 border-green-500/30 border text-xs">
                          {feed.status}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mb-1">Last update: {feed.lastUpdate}</p>
                      <p className="text-xs font-mono text-accent">{feed.indicators} indicators</p>
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          </div>

          {/* Threat Map */}
          <Card className="glass glow-border p-6">
            <h2 className="text-lg font-mono font-bold mb-4 text-accent">THREAT LANDSCAPE</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 bg-card/30 rounded border border-border/20 text-center">
                <p className="text-sm text-muted-foreground mb-2">Most Active Region</p>
                <p className="text-2xl font-mono font-bold text-cyan-400">Eastern Europe</p>
                <p className="text-xs text-muted-foreground mt-1">42% of detected threats</p>
              </div>
              <div className="p-4 bg-card/30 rounded border border-border/20 text-center">
                <p className="text-sm text-muted-foreground mb-2">Most Common Attack</p>
                <p className="text-2xl font-mono font-bold text-orange-400">Brute Force</p>
                <p className="text-xs text-muted-foreground mt-1">35% of incidents</p>
              </div>
              <div className="p-4 bg-card/30 rounded border border-border/20 text-center">
                <p className="text-sm text-muted-foreground mb-2">Threat Level</p>
                <p className="text-2xl font-mono font-bold text-red-400">HIGH</p>
                <p className="text-xs text-muted-foreground mt-1">↑ 12% from last week</p>
              </div>
            </div>
          </Card>
        </div>
      </main>
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: number;
  color?: 'red' | 'orange' | 'cyan';
}

function StatCard({ label, value, color }: StatCardProps) {
  const colorClass = color === 'red' ? 'text-red-400' : color === 'orange' ? 'text-orange-400' : 'text-cyan-400';

  return (
    <Card className="glass border border-border/20 p-4">
      <p className="text-xs text-muted-foreground font-mono uppercase">{label}</p>
      <p className={`text-2xl font-mono font-bold mt-2 ${colorClass}`}>{value}</p>
    </Card>
  );
}
