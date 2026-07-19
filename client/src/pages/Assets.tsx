import { useState } from 'react';
import { Server, Laptop, Smartphone, Plus, Search } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

/**
 * J.A.R.V.I.S. Assets
 * Asset inventory and management
 * Design: Dark holographic interface with asset categorization
 */

interface Asset {
  id: number;
  name: string;
  type: 'server' | 'workstation' | 'mobile';
  ip: string;
  os: string;
  status: 'healthy' | 'warning' | 'critical';
  lastSeen: string;
  vulnerabilities: number;
}

export default function Assets() {
  const [searchTerm, setSearchTerm] = useState('');
  const [assets] = useState<Asset[]>([
    { id: 1, name: 'web-server-01', type: 'server', ip: '10.0.1.10', os: 'Ubuntu 22.04 LTS', status: 'healthy', lastSeen: '1 min ago', vulnerabilities: 2 },
    { id: 2, name: 'db-server-01', type: 'server', ip: '10.0.1.20', os: 'CentOS 8', status: 'healthy', lastSeen: '2 min ago', vulnerabilities: 0 },
    { id: 3, name: 'workstation-01', type: 'workstation', ip: '192.168.1.10', os: 'Windows 11', status: 'warning', lastSeen: '5 min ago', vulnerabilities: 5 },
    { id: 4, name: 'workstation-02', type: 'workstation', ip: '192.168.1.11', os: 'Windows 11', status: 'healthy', lastSeen: '3 min ago', vulnerabilities: 1 },
    { id: 5, name: 'mobile-device-01', type: 'mobile', ip: '192.168.1.50', os: 'iOS 17', status: 'healthy', lastSeen: '10 min ago', vulnerabilities: 0 },
    { id: 6, name: 'mobile-device-02', type: 'mobile', ip: '192.168.1.51', os: 'Android 14', status: 'critical', lastSeen: '1 hour ago', vulnerabilities: 8 },
  ]);

  const filteredAssets = assets.filter(asset =>
    asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    asset.ip.includes(searchTerm)
  );

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'bg-green-500/20 text-green-300 border-green-500/30';
      case 'warning': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/30';
      default: return 'bg-gray-500/20 text-gray-300 border-gray-500/30';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'server': return <Server className="w-4 h-4" />;
      case 'workstation': return <Laptop className="w-4 h-4" />;
      case 'mobile': return <Smartphone className="w-4 h-4" />;
      default: return <Server className="w-4 h-4" />;
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
                <h1 className="text-3xl font-bold font-mono">ASSETS</h1>
                <p className="text-sm text-muted-foreground">Device and service inventory</p>
              </div>
              <Button className="bg-accent hover:bg-accent/90 text-background font-mono gap-2">
                <Plus className="w-4 h-4" />
                Add Asset
              </Button>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          {/* Summary Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <StatCard label="Total Assets" value={assets.length} />
            <StatCard label="Healthy" value={assets.filter(a => a.status === 'healthy').length} color="green" />
            <StatCard label="Warnings" value={assets.filter(a => a.status === 'warning').length} color="yellow" />
            <StatCard label="Critical" value={assets.filter(a => a.status === 'critical').length} color="red" />
          </div>

          {/* Search Bar */}
          <div className="mb-6">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search by name or IP address..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 bg-card/30 border-border/20 text-foreground placeholder:text-muted-foreground"
              />
            </div>
          </div>

          {/* Asset List */}
          <div className="space-y-4">
            {filteredAssets.map((asset) => (
              <Card key={asset.id} className="glass glow-border p-6 hover:shadow-lg transition-all">
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-4 flex-1">
                    <div className="p-3 bg-card/50 rounded border border-border/20 text-accent">
                      {getTypeIcon(asset.type)}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-mono font-bold text-lg">{asset.name}</h3>
                        <Badge variant="outline" className="text-xs capitalize">
                          {asset.type}
                        </Badge>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <p className="text-xs text-muted-foreground">IP Address</p>
                          <p className="font-mono text-sm">{asset.ip}</p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground">Operating System</p>
                          <p className="font-mono text-sm">{asset.os}</p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground">Last Seen</p>
                          <p className="font-mono text-sm">{asset.lastSeen}</p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground">Vulnerabilities</p>
                          <p className={`font-mono text-sm ${asset.vulnerabilities > 0 ? 'text-red-400' : 'text-green-400'}`}>
                            {asset.vulnerabilities}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-3">
                    <Badge className={`${getStatusColor(asset.status)} border`}>
                      {asset.status.toUpperCase()}
                    </Badge>
                    <Button size="sm" variant="outline" className="text-xs">
                      Details
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>

          {/* Asset Categories */}
          <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-4">
            <CategoryCard title="Servers" count={2} icon={<Server className="w-6 h-6" />} />
            <CategoryCard title="Workstations" count={2} icon={<Laptop className="w-6 h-6" />} />
            <CategoryCard title="Mobile Devices" count={2} icon={<Smartphone className="w-6 h-6" />} />
          </div>
        </div>
      </main>
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: number;
  color?: 'green' | 'yellow' | 'red';
}

function StatCard({ label, value, color }: StatCardProps) {
  const colorClass = color === 'green' ? 'text-green-400' : color === 'yellow' ? 'text-yellow-400' : color === 'red' ? 'text-red-400' : 'text-cyan-400';

  return (
    <Card className="glass border border-border/20 p-4">
      <p className="text-xs text-muted-foreground font-mono uppercase">{label}</p>
      <p className={`text-2xl font-mono font-bold mt-2 ${colorClass}`}>{value}</p>
    </Card>
  );
}

interface CategoryCardProps {
  title: string;
  count: number;
  icon: React.ReactNode;
}

function CategoryCard({ title, count, icon }: CategoryCardProps) {
  return (
    <Card className="glass glow-border p-6 text-center">
      <div className="flex justify-center mb-3 text-accent">{icon}</div>
      <h3 className="font-mono font-bold mb-1">{title}</h3>
      <p className="text-2xl font-mono font-bold text-cyan-400">{count}</p>
    </Card>
  );
}
