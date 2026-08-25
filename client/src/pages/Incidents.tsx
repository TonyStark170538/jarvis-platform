import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Clock, FileText, GitBranch, Radio, RefreshCw, Search, User, X } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import ForensicIncidentModal from '@/components/ForensicIncidentModal';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { securityStore } from '@/security/securityStore';
import type { SecurityIncidentStatus, SecurityStoreSnapshot } from '@/security/types';

interface Incident {
  id: number;
  backendId: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: SecurityIncidentStatus;
  created: string;
  createdAt: string;
  updatedAt: string;
  assignee: string;
  description: string;
  evidence: number;
}

type SeverityFilter = 'all' | Incident['severity'];
type StatusFilter = 'all' | SecurityIncidentStatus;
type SortMode = 'updated' | 'severity' | 'oldest';

const severityRank: Record<Incident['severity'], number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const severityClass: Record<Incident['severity'], string> = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
};

const statusClass: Record<SecurityIncidentStatus, string> = {
  open: 'bg-red-500/20 text-red-300 border-red-500/30',
  investigating: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  resolved: 'bg-green-500/20 text-green-300 border-green-500/30',
};

export default function Incidents() {
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [snapshot, setSnapshot] = useState<SecurityStoreSnapshot>(securityStore.getSnapshot());
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [sortMode, setSortMode] = useState<SortMode>('updated');

  useEffect(() => {
    securityStore.startBackendPolling();
    return () => securityStore.stopBackendPolling();
  }, []);

  useEffect(() => securityStore.subscribe(setSnapshot), []);

  const incidents = useMemo<Incident[]>(
    () =>
      snapshot.incidents.map((incident, index) => {
        const event = snapshot.events.find((eventItem) => eventItem.id === incident.eventIds[0]);
        return {
          id: index + 1,
          backendId: incident.id,
          title: incident.title,
          severity: incident.severity,
          status: incident.status,
          created: new Date(incident.updatedAt || incident.createdAt).toLocaleString(),
          createdAt: incident.createdAt,
          updatedAt: incident.updatedAt,
          assignee: incident.assignee ?? 'Unassigned',
          description:
            event?.description ?? `${incident.eventIds.length} correlated security events detected.`,
          evidence: incident.eventIds.length,
        };
      }),
    [snapshot.incidents, snapshot.events]
  );

  const filteredIncidents = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return incidents
      .filter((incident) => {
        if (severityFilter !== 'all' && incident.severity !== severityFilter) return false;
        if (statusFilter !== 'all' && incident.status !== statusFilter) return false;
        if (!normalizedQuery) return true;
        return [incident.title, incident.backendId, incident.assignee, incident.description]
          .join(' ')
          .toLowerCase()
          .includes(normalizedQuery);
      })
      .sort((a, b) => {
        if (sortMode === 'severity') return severityRank[b.severity] - severityRank[a.severity];
        if (sortMode === 'oldest') return a.createdAt.localeCompare(b.createdAt);
        return b.updatedAt.localeCompare(a.updatedAt);
      });
  }, [incidents, query, severityFilter, statusFilter, sortMode]);

  const changeStatus = async (incident: Incident, status: SecurityIncidentStatus) => {
    setUpdatingId(incident.backendId);
    setError(null);
    try {
      await securityStore.updateIncidentStatus(incident.backendId, status);
      setSelectedIncident((current) =>
        current?.backendId === incident.backendId ? { ...current, status } : current
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update incident');
    } finally {
      setUpdatingId(null);
    }
  };

  const hasFilters = Boolean(query.trim()) || severityFilter !== 'all' || statusFilter !== 'all' || sortMode !== 'updated';

  const clearFilters = () => {
    setQuery('');
    setSeverityFilter('all');
    setStatusFilter('all');
    setSortMode('updated');
  };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <div className="glass border-b sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4">
              <div>
                <h1 className="text-3xl font-bold font-mono">INCIDENTS</h1>
                <p className="text-sm text-muted-foreground">
                  Persisted incidents and live forensic investigation
                </p>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <Badge className="bg-cyan-500/10 text-cyan-300 border-cyan-500/30 border gap-2">
                  <Radio className="w-3 h-3" />
                  {snapshot.backendOnline ? 'LIVE' : 'OFFLINE'}
                </Badge>
                <Badge className="bg-red-500/20 text-red-300 border-red-500/30 border">
                  {incidents.filter((incident) => incident.status === 'open').length} Open
                </Badge>
                <Badge className="bg-yellow-500/20 text-yellow-300 border-yellow-500/30 border">
                  {incidents.filter((incident) => incident.status === 'investigating').length} Investigating
                </Badge>
                <Button size="sm" variant="outline" onClick={() => void securityStore.hydrateFromBackend()}>
                  <RefreshCw className="w-4 h-4" />
                </Button>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          <Card className="glass glow-border p-4 mb-6">
            <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_180px_180px_170px_auto] gap-3 items-center">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search incidents, IDs, analysts, descriptions…"
                  className="pl-9"
                />
              </div>

              <select
                value={severityFilter}
                onChange={(event) => setSeverityFilter(event.target.value as SeverityFilter)}
                className="h-10 rounded-md border border-border/40 bg-background px-3 text-sm font-mono text-foreground"
                aria-label="Filter by severity"
              >
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>

              <select
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value as StatusFilter)}
                className="h-10 rounded-md border border-border/40 bg-background px-3 text-sm font-mono text-foreground"
                aria-label="Filter by status"
              >
                <option value="all">All statuses</option>
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
              </select>

              <select
                value={sortMode}
                onChange={(event) => setSortMode(event.target.value as SortMode)}
                className="h-10 rounded-md border border-border/40 bg-background px-3 text-sm font-mono text-foreground"
                aria-label="Sort incidents"
              >
                <option value="updated">Newest activity</option>
                <option value="severity">Highest severity</option>
                <option value="oldest">Oldest first</option>
              </select>

              {hasFilters ? (
                <Button variant="outline" size="sm" onClick={clearFilters} className="gap-2">
                  <X className="w-4 h-4" />
                  Clear
                </Button>
              ) : (
                <div className="text-xs font-mono text-muted-foreground text-right whitespace-nowrap">
                  {filteredIncidents.length} visible
                </div>
              )}
            </div>
          </Card>

          {error && (
            <Card className="mb-4 border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
              {error}
            </Card>
          )}

          {incidents.length === 0 ? (
            <Card className="glass glow-border p-10 text-center">
              <AlertTriangle className="w-8 h-8 mx-auto mb-3 text-muted-foreground" />
              <p className="font-mono text-sm text-muted-foreground">No persisted incidents yet.</p>
              <p className="text-xs text-muted-foreground mt-1">Run a scenario in Attack Lab to generate telemetry.</p>
            </Card>
          ) : filteredIncidents.length === 0 ? (
            <Card className="glass glow-border p-10 text-center">
              <Search className="w-8 h-8 mx-auto mb-3 text-muted-foreground" />
              <p className="font-mono text-sm text-muted-foreground">No incidents match the current filters.</p>
              <Button variant="outline" size="sm" className="mt-4" onClick={clearFilters}>
                Clear filters
              </Button>
            </Card>
          ) : (
            <div className="space-y-4">
              {filteredIncidents.map((incident) => {
                const thread = snapshot.incidentThreads.find((candidate) =>
                  candidate.events.some((id) =>
                    snapshot.incidents.find((item) => item.id === incident.backendId)?.eventIds.includes(id)
                  )
                );

                return (
                  <Card key={incident.backendId} className="glass glow-border p-6 hover:shadow-lg transition-all">
                    <div className="flex items-start justify-between mb-4 gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-3 mb-2">
                          <AlertTriangle className="w-5 h-5 text-accent shrink-0" />
                          <h3 className="font-mono font-bold text-lg break-words">{incident.title}</h3>
                          {thread && (
                            <Badge variant="outline" className="text-cyan-300 border-cyan-500/30 gap-1">
                              <GitBranch className="w-3 h-3" />
                              {Math.round(thread.correlationStrength * 100)}% correlated
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground leading-relaxed">{incident.description}</p>
                      </div>
                      <div className="flex flex-col gap-2 ml-4 shrink-0">
                        <Badge className={`${severityClass[incident.severity]} border`}>
                          {incident.severity.toUpperCase()}
                        </Badge>
                        <Badge className={`${statusClass[incident.status]} border`}>
                          {incident.status.toUpperCase()}
                        </Badge>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 pt-4 border-t border-border/20">
                      <div className="flex items-center gap-2 text-sm">
                        <Clock className="w-4 h-4 text-muted-foreground" />
                        <div>
                          <p className="text-xs text-muted-foreground">Updated</p>
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
                      <div className="flex flex-wrap justify-end gap-2">
                        <Button size="sm" variant="outline" className="text-xs" onClick={() => setSelectedIncident(incident)}>
                          View Forensics
                        </Button>
                        {incident.status === 'open' && (
                          <Button
                            size="sm"
                            disabled={updatingId === incident.backendId}
                            onClick={() => void changeStatus(incident, 'investigating')}
                          >
                            Investigate
                          </Button>
                        )}
                        {incident.status === 'investigating' && (
                          <Button
                            size="sm"
                            disabled={updatingId === incident.backendId}
                            onClick={() => void changeStatus(incident, 'resolved')}
                          >
                            Resolve
                          </Button>
                        )}
                        {incident.status === 'resolved' && (
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={updatingId === incident.backendId}
                            onClick={() => void changeStatus(incident, 'investigating')}
                          >
                            Reopen
                          </Button>
                        )}
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>
          )}

          <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="glass glow-border p-6">
              <p className="text-sm text-muted-foreground mb-2 font-mono">Persisted Incidents</p>
              <p className="text-3xl font-mono font-bold text-cyan-400">{incidents.length}</p>
            </Card>
            <Card className="glass glow-border p-6">
              <p className="text-sm text-muted-foreground mb-2 font-mono">Critical Incidents</p>
              <p className="text-3xl font-mono font-bold text-red-400">
                {incidents.filter((incident) => severityRank[incident.severity] >= severityRank.critical).length}
              </p>
            </Card>
            <Card className="glass glow-border p-6">
              <p className="text-sm text-muted-foreground mb-2 font-mono">Observed Events</p>
              <p className="text-3xl font-mono font-bold text-blue-400">{snapshot.events.length}</p>
            </Card>
          </div>
        </div>
      </main>

      {selectedIncident && (
        <ForensicIncidentModal
          isOpen={!!selectedIncident}
          onClose={() => setSelectedIncident(null)}
          incident={selectedIncident}
        />
      )}
    </div>
  );
}
