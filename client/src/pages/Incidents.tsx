import { useState } from 'react';
import { AlertTriangle, Clock, User, FileText } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import IncidentDetailModal from '@/components/IncidentDetailModal';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

/**
 * J.A.R.V.I.S. Incidents
 * Incident management, investigation, and response tracking
 * Design: Dark holographic interface with severity-based color coding
 */

interface Incident {
  id: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'resolved';
  created: string;
  assignee: string;
  description: string;
  evidence: number;
}

export default function Incidents() {
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [incidents] = useState<Incident[]>([
    {
      id: 1,
      title: 'Unauthorized SSH Access Attempt',
      severity: 'critical',
      status: 'investigating',
      created: '2 hours ago',
      assignee: 'Security Team',
      description: 'Multiple failed SSH login attempts from external IP detected on production server',
      evidence: 5,
    },
    {
      id: 2,
      title: 'Suspicious PowerShell Execution',
      severity: 'high',
      status: 'investigating',
      created: '4 hours ago',
      assignee: 'Incident Response',
      description: 'Encoded PowerShell script executed with admin privileges',
      evidence: 8,
    },
    {
      id: 3,
      title: 'Data Exfiltration Attempt',
      severity: 'high',
      status: 'open',
      created: '6 hours ago',
      assignee: 'Unassigned',
      description: 'Large volume of data transferred to external IP address',
      evidence: 12,
    },
    {
      id: 4,
      title: 'Malware Detected',
      severity: 'critical',
      status: 'resolved',
      created: '1 day ago',
      assignee: 'Security Team',
      description: 'Known malware signature identified in system memory',
      evidence: 15,
    },
  ]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      default: return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'investigating': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'resolved': return 'bg-green-500/20 text-green-300 border-green-500/30';
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
                <h1 className="text-3xl font-bold font-mono">INCIDENTS</h1>
                <p className="text-sm text-muted-foreground">Incident management and investigation</p>
              </div>
              <div className="flex gap-2">
                <Badge className="bg-red-500/20 text-red-300 border-red-500/30 border">
                  {incidents.filter(i => i.status === 'open').length} Open
                </Badge>
                <Badge className="bg-yellow-500/20 text-yellow-300 border-yellow-500/30 border">
                  {incidents.filter(i => i.status === 'investigating').length} Investigating
                </Badge>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          {/* Incident Timeline */}
          <div className="space-y-4">
            {incidents.map((incident) => (
              <Card key={incident.id} className="glass glow-border p-6 hover:shadow-lg transition-all cursor-pointer">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <AlertTriangle className="w-5 h-5 text-accent flex-shrink-0" />
                      <h3 className="font-mono font-bold text-lg">{incident.title}</h3>
                    </div>
                    <p className="text-sm text-muted-foreground">{incident.description}</p>
                  </div>
                  <div className="flex flex-col gap-2 ml-4">
                    <Badge className={`${getSeverityColor(incident.severity)} border`}>
                      {incident.severity.toUpperCase()}
                    </Badge>
                    <Badge className={`${getStatusColor(incident.status)} border`}>
                      {incident.status.toUpperCase()}
                    </Badge>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 pt-4 border-t border-border/20">
                  <div className="flex items-center gap-2 text-sm">
                    <Clock className="w-4 h-4 text-muted-foreground" />
                    <div>
                      <p className="text-xs text-muted-foreground">Created</p>
                      <p className="font-mono text-xs">{incident.created}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <User className="w-4 h-4 text-muted-foreground" />
                    <div>
                      <p className="text-xs text-muted-foreground">Assignee</p>
                      <p className="font-mono text-xs">{incident.assignee}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <FileText className="w-4 h-4 text-muted-foreground" />
                    <div>
                      <p className="text-xs text-muted-foreground">Evidence</p>
                      <p className="font-mono text-xs">{incident.evidence} items</p>
                    </div>
                  </div>
                  <div className="flex justify-end gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-xs"
                      onClick={() => setSelectedIncident(incident)}
                    >
                      View Details
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>

          {/* Incident Statistics */}
          <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="glass glow-border p-6">
              <p className="text-sm text-muted-foreground mb-2 font-mono">MTTR (Mean Time to Resolve)</p>
              <p className="text-3xl font-mono font-bold text-cyan-400">4.2 hours</p>
              <p className="text-xs text-muted-foreground mt-2">Average response time</p>
            </Card>
            <Card className="glass glow-border p-6">
              <p className="text-sm text-muted-foreground mb-2 font-mono">Total Incidents (30 days)</p>
              <p className="text-3xl font-mono font-bold text-blue-400">24</p>
              <p className="text-xs text-muted-foreground mt-2">↓ 15% from last month</p>
            </Card>
            <Card className="glass glow-border p-6">
              <p className="text-sm text-muted-foreground mb-2 font-mono">Resolution Rate</p>
              <p className="text-3xl font-mono font-bold text-green-400">92%</p>
              <p className="text-xs text-muted-foreground mt-2">Successfully resolved</p>
            </Card>
          </div>
        </div>
      </main>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <IncidentDetailModal
          isOpen={!!selectedIncident}
          onClose={() => setSelectedIncident(null)}
          incident={selectedIncident}
        />
      )}
    </div>
  );
}
