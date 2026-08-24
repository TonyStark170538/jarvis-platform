import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Clock, User, FileText, Radio, GitBranch, RefreshCw } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import IncidentDetailModal from '@/components/IncidentDetailModal';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { securityStore } from '@/security/securityStore';
import type { SecurityIncidentStatus, SecurityStoreSnapshot } from '@/security/types';

interface Incident {
  id: number;
  backendId: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: SecurityIncidentStatus;
  created: string;
  assignee: string;
  description: string;
  evidence: number;
}

const severityRank: Record<Incident['severity'], number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

export default function Incidents() {
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [snapshot, setSnapshot] = useState<SecurityStoreSnapshot>(securityStore.getSnapshot());
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    securityStore.startBackendPolling();
    return () => securityStore.stopBackendPolling();
  }, []);
  useEffect(() => securityStore.subscribe(setSnapshot), []);

  const incidents = useMemo<Incident[]>(() => {
    return snapshot.incidents.map((incident, index) => {
      const thread = snapshot.incidentThreads.find((candidate) =>
        incident.eventIds.includes(candidate.rootEventId) || candidate.events.some((id) => incident.eventIds.includes(id))
      );
      const rootEvent = snapshot.events.find((event) => event.id === incident.eventIds[0]);
      return {
        id: index + 1,
        backendId: incident.id,
        title: incident.title,
        severity: incident.severity,
        status: incident.status,
        created: new Date(incident.updatedAt || incident.createdAt).toLocaleString(),
        assignee: 'Security Team',
        description: rootEvent?.description ?? `${incident.eventIds.length} correlated security events detected.`,
        evidence: incident.eventIds.length,
      };
    });
  }, [snapshot.incidents, snapshot.incidentThreads, snapshot.events]);

  const changeStatus = async (incident: Incident, status: SecurityIncidentStatus) => {
    setUpdatingId(incident.backendId);
    setError(null);
    try {
      await securityStore.updateIncidentStatus(incident.backendId, status);
      if (selectedIncident?.backendId === incident.backendId) {
        setSelectedIncident({ ...selectedIncident, status });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update incident');
    } finally {
      setUpdatingId(null);
    }
  };

  const getSeverityColor = (severity: Incident['severity']) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      default: return 'bg-gray-500/20 text-gray-300 border-gray-500/30';
    }
  };

  const getStatusColor = (status: SecurityIncidentStatus) => {
    switch (status) {
      case 'open': return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'investigating': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'resolved': return 'bg-green-500/20 text-green-300 border-green-500/30';
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
                <p className="text-sm text-muted-foreground">Persisted security incidents and investigation lifecycle</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge className="bg-cyan-500/10 text-cyan-300 border-cyan-500/30 border gap-2"><Radio className="w-3 h-3" />{snapshot.backendOnline ? 'LIVE' : 'OFFLINE'}</Badge>
                <Badge className="bg-red-500/20 text-red-300 border-red-500/30 border">{incidents.filter((i) => i.status === 'open').length} Open</Badge>
                <Badge className="bg-yellow-500/20 text-yellow-300 border-yellow-500/30 border">{incidents.filter((i) => i.status === 'investigating').length} Investigating</Badge>
                <Button size="sm" variant="outline" onClick={() => void securityStore.hydrateFromBackend()}><RefreshCw className="w-4 h-4" /></Button>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          {error && <Card className="mb-4 border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">{error}</Card>}
          {incidents.length === 0 ? (
            <Card className="glass glow-border p-10 text-center">
              <AlertTriangle className="w-8 h-8 mx-auto mb-3 text-muted-foreground" />
              <p className="font-mono text-sm text-muted-foreground">No persisted incidents yet.</p>
              <p className="text-xs text-muted-foreground mt-1">Run a scenario in Attack Lab to generate telemetry, detections, and correlated incidents.</p>
            </Card>
          ) : (
            <div className="space-y-4">
              {incidents.map((incident) => {
                const thread = snapshot.incidentThreads.find((candidate) => incident.backendId === candidate.id || candidate.events.some((id) => snapshot.incidents.find((item) => item.id === incident.backendId)?.eventIds.includes(id)));
                return (
                  <Card key={incident.backendId} className="glass glow-border p-6 hover:shadow-lg transition-all">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <AlertTriangle className="w-5 h-5 text-accent flex-shrink-0" />
                          <h3 className="font-mono font-bold text-lg">{incident.title}</h3>
                          {thread && <Badge variant="outline" className="text-cyan-300 border-cyan-500/30 gap-1"><GitBranch className="w-3 h-3" />{Math.round(thread.correlationStrength * 100)}% correlated</Badge>}
                        </div>
                        <p className="text-sm text-muted-foreground">{incident.description}</p>
                      </div>
                      <div className="flex flex-col gap-2 ml-4">
                        <Badge className={`${getSeverityColor(incident.severity)} border`}>{incident.severity.toUpperCase()}</Badge>
                        <Badge className={`${getStatusColor(incident.status)} border`}>{incident.status.toUpperCase()}</Badge>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 pt-4 border-t border-border/20">
                      <div className="flex items-center gap-2 text-sm"><Clock className="w-4 h-4 text-muted-foreground" /><div><p className="text-xs text-muted-foreground">Updated</p><p className="font-mono text-xs">{incident.created}</p></div></div>
                      <div className="flex items-center gap-2 text-sm"><User className="w-4 h-4 text-muted-foreground" /><div><p className="text-xs text-muted-foreground">Assignee</p><p className="font-mono text-xs">{incident.assignee}</p></div></div>
                      <div className="flex items-center gap-2 text-sm"><FileText className="w-4 h-4 text-muted-foreground" /><div><p className="text-xs text-muted-foreground">Evidence</p><p className="font-mono text-xs">{incident.evidence} events</p></div></div>
                      <div className="flex flex-wrap justify-end gap-2">
                        <Button size="sm" variant="outline" className="text-xs" onClick={() => setSelectedIncident(incident)}>View Details</Button>
                        {incident.status === 'open' && <Button size="sm" className="text-xs" disabled={updatingId === incident.backendId} onClick={() => void changeStatus(incident, 'investigating')}>Investigate</Button>}
                        {incident.status === 'investigating' && <Button size="sm" className="text-xs" disabled={updatingId === incident.backendId} onClick={() => void changeStatus(incident, 'resolved')}>Resolve</Button>}
                        {incident.status === 'resolved' && <Button size="sm" variant="outline" className="text-xs" disabled={updatingId === incident.backendId} onClick={() => void changeStatus(incident, 'investigating')}>Reopen</Button>}
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>
          )}

          <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="glass glow-border p-6"><p className="text-sm text-muted-foreground mb-2 font-mono">Persisted Incidents</p><p className="text-3xl font-mono font-bold text-cyan-400">{incidents.length}</p><p className="text-xs text-muted-foreground mt-2">PostgreSQL-backed lifecycle</p></Card>
            <Card className="glass glow-border p-6"><p className="text-sm text-muted-foreground mb-2 font-mono">Critical Incidents</p><p className="text-3xl font-mono font-bold text-red-400">{incidents.filter((i) => severityRank[i.severity] >= severityRank.critical).length}</p><p className="text-xs text-muted-foreground mt-2">Require immediate investigation</p></Card>
            <Card className="glass glow-border p-6"><p className="text-sm text-muted-foreground mb-2 font-mono">Observed Events</p><p className="text-3xl font-mono font-bold text-blue-400">{snapshot.events.length}</p><p className="text-xs text-muted-foreground mt-2">Telemetry from backend</p></Card>
          </div>
        </div>
      </main>

      {selectedIncident && <IncidentDetailModal isOpen={!!selectedIncident} onClose={() => setSelectedIncident(null)} incident={selectedIncident} />}
    </div>
  );
}
