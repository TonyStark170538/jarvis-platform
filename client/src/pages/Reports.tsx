import { useState } from 'react';
import { Download, Calendar, BarChart3 } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

/**
 * J.A.R.V.I.S. Reports
 * Security reports and analytics
 * Design: Dark holographic interface with data visualization
 */

interface Report {
  id: number;
  title: string;
  type: 'daily' | 'weekly' | 'monthly';
  date: string;
  incidents: number;
  alerts: number;
  status: 'completed' | 'pending';
}

export default function Reports() {
  const [reports] = useState<Report[]>([
    { id: 1, title: 'Daily Security Report - July 4, 2026', type: 'daily', date: 'Today', incidents: 3, alerts: 12, status: 'completed' },
    { id: 2, title: 'Daily Security Report - July 3, 2026', type: 'daily', date: 'Yesterday', incidents: 2, alerts: 8, status: 'completed' },
    { id: 3, title: 'Weekly Security Report - Week 27', type: 'weekly', date: 'Last Week', incidents: 15, alerts: 67, status: 'completed' },
    { id: 4, title: 'Monthly Security Report - June 2026', type: 'monthly', date: 'Last Month', incidents: 42, alerts: 234, status: 'completed' },
  ]);

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'daily': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      case 'weekly': return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
      case 'monthly': return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
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
                <h1 className="text-3xl font-bold font-mono">REPORTS</h1>
                <p className="text-sm text-muted-foreground">Security analytics and insights</p>
              </div>
              <Button className="bg-accent hover:bg-accent/90 text-background font-mono gap-2">
                <BarChart3 className="w-4 h-4" />
                Generate Report
              </Button>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          {/* Key Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <MetricCard label="Total Incidents (30d)" value="42" trend="↓ 12%" />
            <MetricCard label="Average MTTR" value="4.2h" trend="↓ 8%" />
            <MetricCard label="Detection Rate" value="94%" trend="↑ 3%" />
            <MetricCard label="False Positives" value="2.1%" trend="↓ 0.5%" />
          </div>

          {/* Report List */}
          <div className="mb-8">
            <h2 className="text-lg font-mono font-bold mb-4 text-accent">RECENT REPORTS</h2>
            <div className="space-y-4">
              {reports.map((report) => (
                <Card key={report.id} className="glass glow-border p-6 hover:shadow-lg transition-all">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-mono font-bold text-lg">{report.title}</h3>
                        <Badge className={`${getTypeColor(report.type)} border capitalize`}>
                          {report.type}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mb-4">{report.date}</p>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div>
                          <p className="text-xs text-muted-foreground">Incidents</p>
                          <p className="text-lg font-mono font-bold text-cyan-400">{report.incidents}</p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground">Alerts</p>
                          <p className="text-lg font-mono font-bold text-blue-400">{report.alerts}</p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground">Critical</p>
                          <p className="text-lg font-mono font-bold text-red-400">{Math.floor(report.incidents * 0.3)}</p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground">Resolved</p>
                          <p className="text-lg font-mono font-bold text-green-400">{Math.floor(report.incidents * 0.85)}</p>
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-2 ml-4">
                      <Button size="sm" variant="outline" className="text-xs gap-2">
                        <Download className="w-3 h-3" />
                        PDF
                      </Button>
                      <Button size="sm" variant="outline" className="text-xs gap-2">
                        <Download className="w-3 h-3" />
                        CSV
                      </Button>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          </div>

          {/* Report Scheduling */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <Card className="glass glow-border p-6">
              <h2 className="text-lg font-mono font-bold mb-4 text-accent">SCHEDULED REPORTS</h2>
              <div className="space-y-3">
                <div className="p-3 bg-card/30 rounded border border-border/20">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-mono text-sm font-bold">Daily Report</p>
                      <p className="text-xs text-muted-foreground">Every day at 08:00 UTC</p>
                    </div>
                    <Badge className="bg-green-500/20 text-green-300 border-green-500/30 border">Active</Badge>
                  </div>
                </div>
                <div className="p-3 bg-card/30 rounded border border-border/20">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-mono text-sm font-bold">Weekly Report</p>
                      <p className="text-xs text-muted-foreground">Every Monday at 09:00 UTC</p>
                    </div>
                    <Badge className="bg-green-500/20 text-green-300 border-green-500/30 border">Active</Badge>
                  </div>
                </div>
                <div className="p-3 bg-card/30 rounded border border-border/20">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-mono text-sm font-bold">Monthly Report</p>
                      <p className="text-xs text-muted-foreground">1st of each month at 10:00 UTC</p>
                    </div>
                    <Badge className="bg-green-500/20 text-green-300 border-green-500/30 border">Active</Badge>
                  </div>
                </div>
              </div>
            </Card>

            <Card className="glass glow-border p-6">
              <h2 className="text-lg font-mono font-bold mb-4 text-accent">REPORT STATISTICS</h2>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Total Reports Generated</p>
                  <p className="text-3xl font-mono font-bold text-cyan-400">127</p>
                </div>
                <div className="pt-4 border-t border-border/20">
                  <p className="text-sm text-muted-foreground mb-2">Average Report Size</p>
                  <p className="text-3xl font-mono font-bold text-blue-400">2.4 MB</p>
                </div>
                <div className="pt-4 border-t border-border/20">
                  <p className="text-sm text-muted-foreground mb-2">Storage Used</p>
                  <p className="text-3xl font-mono font-bold text-green-400">305 MB</p>
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
  value: string;
  trend: string;
}

function MetricCard({ label, value, trend }: MetricCardProps) {
  const isPositive = trend.startsWith('↓');

  return (
    <Card className="glass border border-border/20 p-4">
      <p className="text-xs text-muted-foreground font-mono uppercase">{label}</p>
      <div className="flex items-end justify-between mt-2">
        <p className="text-2xl font-mono font-bold text-cyan-400">{value}</p>
        <p className={`text-xs font-mono ${isPositive ? 'text-green-400' : 'text-yellow-400'}`}>{trend}</p>
      </div>
    </Card>
  );
}
