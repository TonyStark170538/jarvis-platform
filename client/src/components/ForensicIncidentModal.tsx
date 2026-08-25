import { useEffect, useState } from 'react';
import { Clock, Network, RefreshCw, ShieldAlert, User, MessageSquare, Activity } from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { securityApi, type SecurityIncidentDetail } from '@/security/api';
import type { SecuritySeverity } from '@/security/types';

export interface ForensicIncident {
  id: number;
  backendId: string;
  title: string;
  severity: SecuritySeverity;
  status: 'open' | 'investigating' | 'resolved';
  created: string;
  assignee: string;
  description: string;
  evidence: number;
}

const severityClass: Record<SecuritySeverity, string> = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
};

export default function ForensicIncidentModal({
  isOpen,
  onClose,
  incident,
}: {
  isOpen: boolean;
  onClose: () => void;
  incident: ForensicIncident;
}) {
  const [detail, setDetail] = useState<SecurityIncidentDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [assignee, setAssignee] = useState(incident.assignee || 'SOC Analyst');
  const [note, setNote] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      setDetail(await securityApi.incidentDetail(incident.backendId));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load forensic data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      setAssignee(incident.assignee || 'SOC Analyst');
      void load();
    } else {
      setDetail(null);
    }
  }, [isOpen, incident.backendId, incident.assignee]);

  const saveAssignee = async () => {
    if (!assignee.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await securityApi.updateIncidentAssignee(incident.backendId, assignee.trim());
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update assignee');
    } finally {
      setSaving(false);
    }
  };

  const addNote = async () => {
    if (!note.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await securityApi.addIncidentNote(incident.backendId, note.trim());
      setNote('');
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add note');
    } finally {
      setSaving(false);
    }
  };

  const events = detail?.events ?? [];
  const detections = detail?.detections ?? [];
  const techniques = detail?.attackTechniques ?? [];

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        showCloseButton
        className="w-[94vw] max-w-[1200px] sm:max-w-6xl max-h-[92vh] overflow-y-auto bg-card border-border/20 glass p-7 md:p-8"
      >
        <DialogHeader className="border-b border-border/20 pb-5 pr-10">
          <div className="flex items-start gap-5">
            <div className="min-w-0 flex-1">
              <DialogTitle className="text-xl md:text-3xl font-mono font-bold text-accent leading-tight break-words">
                {incident.title}
              </DialogTitle>
              <div className="flex flex-wrap items-center gap-2 mt-3">
                <Badge className={`${severityClass[incident.severity]} border`}>
                  {incident.severity.toUpperCase()}
                </Badge>
                <Badge variant="outline">{incident.status.toUpperCase()}</Badge>
                <span className="text-xs font-mono text-muted-foreground break-all">
                  {incident.backendId}
                </span>
              </div>
            </div>
          </div>
        </DialogHeader>

        {error && (
          <Card className="border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
            {error}
          </Card>
        )}

        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Stat label="Events" value={detail?.correlation.eventCount ?? 0} />
          <Stat label="Detections" value={detail?.correlation.detectionCount ?? 0} />
          <Stat
            label="Confidence"
            value={detail ? `${Math.round(detail.correlation.confidence * 100)}%` : '—'}
          />
          <Stat label="Assignee" value={detail?.incident.assignee ?? incident.assignee} />
          <Stat label="Updated" value={new Date(incident.created).toLocaleString()} />
        </div>

        <Card className="p-4 bg-card/50 border-border/20">
          <div className="grid md:grid-cols-[1fr_auto] gap-3 items-end">
            <div>
              <label className="text-[10px] font-mono text-muted-foreground">
                ASSIGN TO ANALYST
              </label>
              <Input className="mt-1" value={assignee} onChange={(e) => setAssignee(e.target.value)} />
            </div>
            <Button onClick={() => void saveAssignee()} disabled={saving || !assignee.trim()}>
              <User className="w-4 h-4 mr-2" />
              Assign
            </Button>
          </div>
        </Card>

        <Tabs defaultValue="timeline" className="mt-2">
          <TabsList className="grid w-full grid-cols-2 md:grid-cols-6 h-auto">
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
            <TabsTrigger value="detections">Detections</TabsTrigger>
            <TabsTrigger value="mitre">MITRE ATT&CK</TabsTrigger>
            <TabsTrigger value="indicators">Indicators</TabsTrigger>
            <TabsTrigger value="notes">Notes</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>

          <TabsContent value="timeline" className="space-y-3 mt-4">
            {loading ? (
              <Empty text="Loading forensic data…" />
            ) : events.length === 0 ? (
              <Empty text="No persisted events attached to this incident." />
            ) : (
              events.map((event) => (
                <Card key={event.id} className="p-4 md:p-5 bg-card/50 border-border/20">
                  <div className="flex gap-3">
                    <div className="mt-1 h-2.5 w-2.5 rounded-full bg-accent shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap justify-between gap-2">
                        <h4 className="font-mono font-bold text-sm md:text-base">{event.title}</h4>
                        <Badge className={`${severityClass[event.severity]} border text-xs`}>
                          {event.severity}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mt-2 leading-relaxed">
                        {event.description}
                      </p>
                      <div className="flex flex-wrap gap-3 mt-3 text-[11px] font-mono text-muted-foreground">
                        <span>
                          <Clock className="inline w-3 h-3 mr-1" />
                          {new Date(event.timestamp).toLocaleString()}
                        </span>
                        <span>TYPE:{event.type}</span>
                        <span>SOURCE:{event.source}</span>
                        {event.hostname && <span>HOST:{event.hostname}</span>}
                        {event.username && <span>USER:{event.username}</span>}
                      </div>
                    </div>
                  </div>
                </Card>
              ))
            )}
          </TabsContent>

          <TabsContent value="detections" className="space-y-3 mt-4">
            {detections.length === 0 ? (
              <Empty text="No persisted detections attached." />
            ) : (
              detections.map((d) => (
                <Card key={d.id} className="p-4 md:p-5 bg-card/50 border-border/20">
                  <div className="flex flex-wrap justify-between gap-3">
                    <div className="min-w-0">
                      <h4 className="font-mono font-bold text-sm md:text-base">{d.ruleName}</h4>
                      <p className="text-sm text-muted-foreground mt-1 leading-relaxed">{d.description}</p>
                    </div>
                    <Badge className={`${severityClass[d.severity]} border`}>
                      {Math.round(d.confidence * 100)}%
                    </Badge>
                  </div>
                  <p className="text-[11px] font-mono text-muted-foreground mt-3 break-all">
                    RULE:{d.ruleId} · EVENT:{d.eventId}
                  </p>
                </Card>
              ))
            )}
          </TabsContent>

          <TabsContent value="mitre" className="mt-4">
            <Card className="p-5 bg-card/50 border-border/20">
              <div className="flex items-center gap-2 mb-4">
                <ShieldAlert className="w-4 h-4 text-accent" />
                <span className="font-mono font-bold">Observed techniques</span>
              </div>
              {techniques.length === 0 ? (
                <Empty text="No MITRE ATT&CK techniques mapped." />
              ) : (
                <div className="flex flex-wrap gap-2">
                  {techniques.map((t) => (
                    <Badge key={t} variant="outline" className="font-mono">
                      {t}
                    </Badge>
                  ))}
                </div>
              )}
              {detail?.correlation.reasons?.length ? (
                <div className="mt-5">
                  <p className="text-xs font-mono text-muted-foreground mb-2">CORRELATION REASONS</p>
                  {detail.correlation.reasons.map((r, i) => (
                    <p key={i} className="text-sm text-muted-foreground">
                      • {r}
                    </p>
                  ))}
                </div>
              ) : null}
            </Card>
          </TabsContent>

          <TabsContent value="indicators" className="space-y-3 mt-4">
            {events.filter((e) => e.sourceIP || e.destinationIP || e.processName || e.filePath).map((e) => (
              <Card key={e.id} className="p-4 bg-card/50 border-border/20">
                <div className="flex items-center gap-2 mb-3">
                  <Network className="w-4 h-4 text-accent" />
                  <span className="font-mono text-sm">{e.id}</span>
                </div>
                <div className="grid md:grid-cols-2 gap-2 text-xs font-mono">
                  {e.sourceIP && <Indicator label="SOURCE IP" value={e.sourceIP} />}
                  {e.destinationIP && <Indicator label="DESTINATION IP" value={e.destinationIP} />}
                  {e.protocol && <Indicator label="PROTOCOL" value={e.protocol} />}
                  {e.processName && <Indicator label="PROCESS" value={e.processName} />}
                  {e.filePath && <Indicator label="FILE" value={e.filePath} />}
                </div>
              </Card>
            ))}
            {!events.some((e) => e.sourceIP || e.destinationIP || e.processName || e.filePath) && (
              <Empty text="No network or endpoint indicators recorded." />
            )}
          </TabsContent>

          <TabsContent value="notes" className="space-y-4 mt-4">
            <Card className="p-4 bg-card/50 border-border/20">
              <div className="flex items-center gap-2 mb-2">
                <MessageSquare className="w-4 h-4 text-accent" />
                <span className="font-mono text-sm font-bold">Analyst note</span>
              </div>
              <Textarea
                placeholder="Record investigation findings, containment decisions, or next steps…"
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
              <div className="flex justify-end mt-2">
                <Button onClick={() => void addNote()} disabled={saving || !note.trim()}>
                  Add Note
                </Button>
              </div>
            </Card>
            {(detail?.notes ?? []).map((n) => (
              <Card key={n.id} className="p-4 bg-card/50 border-border/20">
                <div className="flex justify-between gap-3">
                  <span className="font-mono text-xs text-accent">{n.author}</span>
                  <span className="text-[10px] text-muted-foreground">
                    {new Date(n.createdAt).toLocaleString()}
                  </span>
                </div>
                <p className="text-sm mt-2 whitespace-pre-wrap">{n.body}</p>
              </Card>
            ))}
            {!detail?.notes.length && <Empty text="No analyst notes yet." />}
          </TabsContent>

          <TabsContent value="activity" className="space-y-3 mt-4">
            {(detail?.activity ?? []).map((a) => (
              <Card key={a.id} className="p-3 bg-card/50 border-border/20">
                <div className="flex items-center gap-2">
                  <Activity className="w-3 h-3 text-accent" />
                  <span className="font-mono text-xs">{a.action}</span>
                  <span className="text-xs text-muted-foreground">by {a.actor}</span>
                  <span className="ml-auto text-[10px] text-muted-foreground">
                    {new Date(a.createdAt).toLocaleString()}
                  </span>
                </div>
              </Card>
            ))}
            {!detail?.activity.length && <Empty text="No response activity recorded yet." />}
          </TabsContent>
        </Tabs>

        <div className="flex items-center justify-between border-t border-border/20 pt-4">
          <div className="text-xs text-muted-foreground font-mono">
            <User className="inline w-3 h-3 mr-1" />
            {detail?.incident.assignee ?? incident.assignee}
          </div>
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh forensic data
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="p-3 rounded border border-border/20 bg-card/50 min-w-0">
      <p className="text-[10px] text-muted-foreground font-mono">{label}</p>
      <p className="font-mono text-sm mt-1 truncate" title={String(value)}>
        {value}
      </p>
    </div>
  );
}

function Indicator({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-2 rounded bg-background/40 break-all">
      <span className="text-muted-foreground">{label}: </span>
      {value}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <div className="p-8 text-center text-sm text-muted-foreground font-mono">{text}</div>;
}
