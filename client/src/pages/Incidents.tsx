import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Clock, User, FileText, Radio, GitBranch } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import IncidentDetailModal from '@/components/IncidentDetailModal';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { securityStore } from '@/security/securityStore';
import type { SecuritySeverity, SecurityStoreSnapshot } from '@/security/types';

interface Incident {
  id: number;
  title: string;
  severity: SecuritySeverity;
  status: 'open' | 'investigating' | 'resolved';
  created: string;
  assignee: string;
  description: string;
  evidence: number;
}

const severityRank: Record<SecuritySeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export default function Incidents() {
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [snapshot, setSnapshot] = useState<SecurityStoreSnapshot>(securityStore.getSnapshot());

  useEffect(() => securityStore.subscribe(setSnapshot), []);

  const incidents = useMemo<Incident[]>(() => {
    return snapshot.incidentThreads.map((thread, index) => {
      const rootEvent = snapshot.events.find((event) => event.id === thread.rootEventId);
      const status =
        thread.severity === 'critical' || thread.severity === 'high'
          ? 'investigating'
          : 'open';

      return {
        id: index + 1,
        title: thread.pattern,
        severity: thread.severity,
        status,
        created: new Date(thread.lastSeen).toLocaleString(),
        assignee: 'Security Team',
        description:
          rootEvent?.description ??
          `${thread.events.length} correlated security events detected.`,
        evidence: thread.events.length,
      };
    });
  }, [snapshot.incidentThreads, snapshot.events]);

  const getSeverityColor = (severity: SecuritySeverity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      default: return 'bg-gray-500/20 text-gray-300 border-gray-500/30';
    }
  };

  const getStatusColor = (status: Incident['status']) => {
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
        <div className="glass border-b sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold font-mono">INCIDENTS</h1>
                <p className="text-sm text-muted-foreground">Correlated security incidents and investigation threads</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge className="bg-cyan-500/10 text-cyan-300 border-cyan-500/30 border gap-2">
                  <Radio className="w-3 h-3" />LIVE
                </Badge>
                <Badge className="bg-red-500/20 text-red-300 border-red-500/30 border">
                  {incidents.filter((incident) => incident.status === 'open').length} Open
                </Badge>
                <Badge className="bg-yellow-500/20 text-yellow-300 border-yellow-500/30 border">
                  {incidents.filter((incident) => incident.status === 'investigating').length} Investigating
                </Badge>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          {incidents.length === 0 ? (
            <Card className="glass glow-border p-10 text-center">
              <AlertTriangle className="w-8 h-8 mx-auto mb-3 text-muted-foreground" />
              <p className="font-mono text-sm text-muted-foreground">No incidents generated yet.</p>
              <p className="text-xs text-muted-foreground mt-1">
                Run a scenario in Attack Lab to generate telemetry, detections, and correlated incidents.
              </p>
            </Card>
          ) : (
            <div className="space-y-4">
              {incidents.map((incident) => {
                const thread = snapshot.incidentThreads[incident.id - 1];
                return (
                  <Card key={incident.id} className="glass glow-border p-6 hover:shadow-lg transition-all">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <AlertTriangle className="w-5 h-5 text-accent flex-shrink-0" />
                          <h3 className="font-mono font-bold text-lg">{incident.title}</h3>
                          {thread && thread.correlationStrength > 0 && (
                            <Badge variant="outline" className="text-cyan-300 border-cyan-500/30 gap-1">
                              <GitBranch className="w-3 h-3" />
                              {Math.round(thread.correlationStrength * 100)}% correlated
                            </Badge>
                          )}
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
                          <p className="text-xs text-muted-foreground">Last observed</p>
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
                          <p className="font-mono text-xs">{incident.evidence} events</p>
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
                );
              })}
            </div>
          )}

          <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="glass glow-border p-6">
              <p className="text-sm text-muted-foreground mb-2 font-mono">Incident Threads</p>
              <p className="text-3xl font-mono font-bold text-cyan-400">{snapshot.incidentThreads.length}</p>
              <p className="text-xs text-muted-foreground mt-2">Correlation engine output</p>
            </Card>
            <Card className="glass glow-border p-6">
              <p className="text-sm text-muted-foreground mb-2 font-mono">Critical Incidents</p>
              <p className="text-3xl font-mono font-bold text-red-400">
                {incidents.filter((incident) => severityRank[incident.severity] >= severityRank.critical).length}
              </p>
              <p className="text-xs text-muted-foreground mt-2">Require immediate investigation</p>
            </Card>
            <Card className="glass glow-border p-6">
              <p className="text-sm text-muted-foreground mb-2 font-mono">Observed Events</p>
              <p className="text-3xl font-mono font-bold text-blue-400">{snapshot.events.length}</p>
              <p className="text-xs text-muted-foreground mt-2">Telemetry in current session</p>
            </Card>
          </div>
        </div>
      </main>

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
