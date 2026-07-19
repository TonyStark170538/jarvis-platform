import { useState, useMemo, useEffect } from 'react';
import { X, Clock, FileText, AlertCircle, CheckCircle, Download, Zap, Wifi } from 'lucide-react';
import { useTimelineEvents } from '@/hooks/useTimelineEvents';
import { useDetectionEvents } from '@/hooks/useDetectionEvents';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { correlateEvents, createIncidentThreads } from '@/lib/incidentCorrelation';
import IncidentCorrelationTab from '@/components/IncidentCorrelationTab';
import ResponseActionPanel from '@/components/ResponseActionPanel';

/**
 * Incident Detail Modal
 * Comprehensive incident investigation view with timeline, evidence, and MITRE mappings
 * Design: Dark holographic interface with detailed forensic information
 */

interface TimelineEvent {
  id?: string;
  time: string;
  event: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  details: string;
  isNew?: boolean;
}

interface Evidence {
  id: number;
  type: 'log' | 'file' | 'network' | 'process';
  name: string;
  timestamp: string;
  hash: string;
  size: string;
}

interface MitreMapping {
  technique: string;
  tactictactic: string;
  id: string;
  description: string;
}

interface IncidentDetailModalProps {
  isOpen: boolean;
  onClose: () => void;
  incident: {
    id: number;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    status: 'open' | 'investigating' | 'resolved';
    created: string;
    assignee: string;
    description: string;
    evidence: number;
  };
}

export default function IncidentDetailModal({ isOpen, onClose, incident }: IncidentDetailModalProps) {
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null);

  // Initial timeline data
  const initialTimeline: TimelineEvent[] = [
    {
      id: 'evt-001',
      time: '2026-07-04 14:32:15',
      event: 'Initial Detection',
      severity: 'critical',
      source: 'IDS/IPS',
      details: 'Suspicious SSH connection attempt detected from external IP 203.0.113.45',
    },
    {
      id: 'evt-002',
      time: '2026-07-04 14:32:18',
      event: 'Failed Authentication',
      severity: 'high',
      source: 'SSH Server',
      details: 'Multiple failed login attempts for user root within 3 seconds',
    },
    {
      id: 'evt-003',
      time: '2026-07-04 14:32:22',
      event: 'Pattern Detected',
      severity: 'high',
      source: 'Behavioral Analytics',
      details: 'Brute force attack pattern identified - 50 attempts in 10 seconds',
    },
    {
      id: 'evt-004',
      time: '2026-07-04 14:32:25',
      event: 'Firewall Block',
      severity: 'medium',
      source: 'Firewall',
      details: 'Source IP added to blocklist after threshold exceeded',
    },
    {
      id: 'evt-005',
      time: '2026-07-04 14:32:30',
      event: 'Incident Created',
      severity: 'critical',
      source: 'SOAR',
      details: 'Automated incident created and assigned to Security Team',
    },
  ];

  // Use real-time timeline hook
  const { events: timeline, isLive, toggleRealTime, eventCount } = useTimelineEvents({
    initialEvents: initialTimeline,
    enableRealTime: true,
  });

  // Calculate incident correlations
  const correlationData = useMemo(() => {
    const timelineWithIds = timeline.map((evt, idx) => ({
      ...evt,
      id: (evt as any).id || `evt-${idx}`,
    }));
    const correlatedEvents = correlateEvents(timelineWithIds);
    const threads = createIncidentThreads(timelineWithIds, correlatedEvents);
    return { correlatedEvents, threads };
  }, [timeline]);

  // Get the first thread for response actions
  const primaryThread = correlationData.threads[0];

  // Mock evidence data
  const evidenceList: Evidence[] = [
    {
      id: 1,
      type: 'log',
      name: 'ssh_auth.log',
      timestamp: '2026-07-04 14:32:15',
      hash: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
      size: '2.4 MB',
    },
    {
      id: 2,
      type: 'network',
      name: 'pcap_capture_001.pcap',
      timestamp: '2026-07-04 14:32:18',
      hash: 'f1e2d3c4b5a6g7h8i9j0k1l2m3n4o5p6',
      size: '15.8 MB',
    },
    {
      id: 3,
      type: 'process',
      name: 'process_list_snapshot.json',
      timestamp: '2026-07-04 14:32:22',
      hash: 'c1b2a3f4e5d6g7h8i9j0k1l2m3n4o5p6',
      size: '1.2 MB',
    },
    {
      id: 4,
      type: 'file',
      name: 'firewall_block_log.csv',
      timestamp: '2026-07-04 14:32:25',
      hash: 'd1c2b3a4f5e6g7h8i9j0k1l2m3n4o5p6',
      size: '856 KB',
    },
    {
      id: 5,
      type: 'log',
      name: 'system_audit.log',
      timestamp: '2026-07-04 14:32:30',
      hash: 'e1d2c3b4a5f6g7h8i9j0k1l2m3n4o5p6',
      size: '3.1 MB',
    },
  ];

  // Mock MITRE ATT&CK mappings
  const mitreMappings: MitreMapping[] = [
    {
      technique: 'Brute Force',
      tactictactic: 'Credential Access',
      id: 'T1110',
      description: 'Adversary attempts multiple password guesses to gain access to accounts',
    },
    {
      technique: 'Valid Accounts',
      tactictactic: 'Defense Evasion',
      id: 'T1078',
      description: 'Adversary attempts to use legitimate credentials to access systems',
    },
    {
      technique: 'External Remote Services',
      tactictactic: 'Initial Access',
      id: 'T1133',
      description: 'Adversary exploits remote services to gain initial access',
    },
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'high':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      default:
        return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
    }
  };

  const getEvidenceIcon = (type: string) => {
    switch (type) {
      case 'log':
        return '📋';
      case 'file':
        return '📄';
      case 'network':
        return '🌐';
      case 'process':
        return '⚙️';
      default:
        return '📦';
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto bg-card border-border/20 glass">
        <DialogHeader className="sticky top-0 z-10 bg-card/95 backdrop-blur pb-4 border-b border-border/20">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <DialogTitle className="text-2xl font-mono font-bold text-accent mb-2">
                {incident.title}
              </DialogTitle>
              <div className="flex items-center gap-3">
                <Badge className={`${getSeverityColor(incident.severity)} border`}>
                  {incident.severity.toUpperCase()}
                </Badge>
                <Badge className="bg-yellow-500/20 text-yellow-300 border-yellow-500/30 border">
                  {incident.status.toUpperCase()}
                </Badge>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-muted-foreground hover:text-foreground transition-colors"
            >
              <X className="w-6 h-6" />
            </button>
          </div>
        </DialogHeader>

        <div className="space-y-6 pt-4">
          {/* Incident Summary */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3 bg-card/50 rounded border border-border/20">
              <p className="text-xs text-muted-foreground font-mono mb-1">Created</p>
              <p className="font-mono text-sm">{incident.created}</p>
            </div>
            <div className="p-3 bg-card/50 rounded border border-border/20">
              <p className="text-xs text-muted-foreground font-mono mb-1">Assignee</p>
              <p className="font-mono text-sm">{incident.assignee}</p>
            </div>
            <div className="p-3 bg-card/50 rounded border border-border/20">
              <p className="text-xs text-muted-foreground font-mono mb-1">Evidence Items</p>
              <p className="font-mono text-sm text-cyan-400">{incident.evidence}</p>
            </div>
            <div className="p-3 bg-card/50 rounded border border-border/20">
              <p className="text-xs text-muted-foreground font-mono mb-1">Incident ID</p>
              <p className="font-mono text-sm text-accent">INC-{incident.id.toString().padStart(6, '0')}</p>
            </div>
          </div>

          {/* Description */}
          <Card className="glass glow-border p-4">
            <h3 className="font-mono font-bold text-accent mb-2">Description</h3>
            <p className="text-sm text-muted-foreground">{incident.description}</p>
          </Card>

          {/* Tabs for Timeline, Evidence, MITRE */}
          <Tabs defaultValue="timeline" className="w-full">
            <TabsList className="grid w-full grid-cols-4 bg-card/50 border border-border/20">
              <TabsTrigger value="timeline" className="data-[state=active]:bg-accent/20">
                Timeline
              </TabsTrigger>
              <TabsTrigger value="evidence" className="data-[state=active]:bg-accent/20">
                Evidence
              </TabsTrigger>
              <TabsTrigger value="correlation" className="data-[state=active]:bg-accent/20">
                Correlation
              </TabsTrigger>
              <TabsTrigger value="response" className="data-[state=active]:bg-accent/20">
                Response
              </TabsTrigger>
            </TabsList>

            {/* Timeline Tab */}
            <TabsContent value="timeline" className="space-y-4 mt-4">
              {/* Live Update Indicator */}
              <div className="flex items-center justify-between p-3 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 rounded border border-cyan-500/30">
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${isLive ? 'bg-green-400 animate-pulse' : 'bg-gray-500'}`}></div>
                  <span className="text-xs font-mono">
                    {isLive ? 'LIVE - Events streaming in real-time' : 'PAUSED'}
                  </span>
                  <span className="text-xs text-muted-foreground ml-2">({eventCount} total events)</span>
                </div>
                <button
                  onClick={toggleRealTime}
                  className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                    isLive
                      ? 'bg-red-500/20 text-red-300 hover:bg-red-500/30 border border-red-500/30'
                      : 'bg-green-500/20 text-green-300 hover:bg-green-500/30 border border-green-500/30'
                  }`}
                >
                  {isLive ? 'Pause' : 'Resume'}
                </button>
              </div>

              <div className="space-y-3">
                {timeline.map((event, index) => {
                  const eventWithId = { ...event, id: (event as any).id || `evt-${index}` };
                  return (
                    <div
                      key={eventWithId.id}
                      className={`relative transition-all duration-500 ${
                        event.isNew ? 'animate-pulse' : ''
                      }`}
                    >
                      {/* Timeline connector */}
                      {index < timeline.length - 1 && (
                        <div className="absolute left-6 top-12 w-0.5 h-8 bg-gradient-to-b from-accent/50 to-transparent"></div>
                      )}

                      <div className="flex gap-4">
                        {/* Timeline dot */}
                        <div className="flex flex-col items-center pt-1">
                          <div
                            className={`w-4 h-4 rounded-full border-2 transition-all ${
                              event.isNew
                                ? 'animate-glow-pulse border-accent bg-accent/40 shadow-lg shadow-accent/50'
                                : event.severity === 'critical'
                                ? 'border-red-500 bg-red-500/20'
                                : event.severity === 'high'
                                ? 'border-orange-500 bg-orange-500/20'
                                : 'border-accent bg-accent/20'
                            }`}
                          ></div>
                        </div>

                        {/* Event details */}
                        <div className="flex-1 pb-4">
                          <div
                            className={`p-3 rounded border transition-all ${
                              event.isNew
                                ? 'bg-accent/10 border-accent/50 shadow-lg shadow-accent/20'
                                : 'bg-card/50 border-border/20 hover:border-accent/50'
                            }`}
                          >
                            <div className="flex items-start justify-between mb-2">
                              <div className="flex items-start gap-2">
                                {event.isNew && (
                                  <Zap className="w-4 h-4 text-accent flex-shrink-0 mt-0.5 animate-pulse" />
                                )}
                                <div>
                                  <p className="font-mono font-bold text-sm">{event.event}</p>
                                  <p className="text-xs text-muted-foreground font-mono mt-1">{event.time}</p>
                                </div>
                              </div>
                              <Badge className={`${getSeverityColor(event.severity)} border text-xs`}>
                                {event.severity}
                              </Badge>
                            </div>
                            <p className="text-xs text-muted-foreground mb-2">{event.details}</p>
                            <p className="text-xs font-mono text-accent">Source: {event.source}</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </TabsContent>

            {/* Incident Correlation Tab */}
            <TabsContent value="correlation" className="space-y-4 mt-4">
              <IncidentCorrelationTab
                threads={correlationData.threads}
                currentIncidentId={incident.id.toString()}
              />
            </TabsContent>

            {/* Response Actions Tab */}
            <TabsContent value="response" className="space-y-4 mt-4">
              <ResponseActionPanel
                incidentType={primaryThread?.pattern || 'Unknown Attack'}
                incidentSeverity={incident.severity}
                targetIP="203.0.113.45"
                targetHost="prod-server-01"
              />
            </TabsContent>

            {/* Evidence Tab */}
            <TabsContent value="evidence" className="space-y-4 mt-4">
              <div className="space-y-3">
                {evidenceList.map((item) => (
                  <div
                    key={item.id}
                    onClick={() => setSelectedEvidence(item)}
                    className="p-4 bg-card/50 rounded border border-border/20 hover:border-accent/50 cursor-pointer transition-all hover:shadow-lg"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-start gap-3">
                        <span className="text-2xl">{getEvidenceIcon(item.type)}</span>
                        <div>
                          <p className="font-mono font-bold text-sm">{item.name}</p>
                          <p className="text-xs text-muted-foreground mt-1">{item.timestamp}</p>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-xs capitalize">
                        {item.type}
                      </Badge>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div>
                        <p className="text-muted-foreground">Hash (SHA-256)</p>
                        <p className="font-mono text-cyan-400 break-all">{item.hash}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Size</p>
                        <p className="font-mono">{item.size}</p>
                      </div>
                    </div>

                    <div className="flex gap-2 mt-3">
                      <Button size="sm" variant="outline" className="text-xs gap-1">
                        <Download className="w-3 h-3" />
                        Download
                      </Button>
                      <Button size="sm" variant="outline" className="text-xs gap-1">
                        <FileText className="w-3 h-3" />
                        View
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </TabsContent>

            {/* MITRE ATT&CK Tab - Hidden */}
            <div style={{ display: 'none' }}>
              <div className="space-y-3">
                {mitreMappings.map((mapping, index) => (
                  <div key={index} className="p-4 bg-card/50 rounded border border-border/20 hover:border-accent/50 transition-colors">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <p className="font-mono font-bold text-sm text-accent">{mapping.technique}</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          Tactic: {mapping.tactictactic}
                        </p>
                      </div>
                      <Badge variant="outline" className="font-mono text-xs">
                        {mapping.id}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">{mapping.description}</p>
                    <Button
                      size="sm"
                      variant="outline"
                      className="mt-3 text-xs"
                      onClick={() =>
                        window.open(`https://attack.mitre.org/techniques/${mapping.id}`, '_blank')
                      }
                    >
                      View on MITRE ATT&CK
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          </Tabs>

          {/* Action Buttons */}
          <div className="flex gap-3 pt-4 border-t border-border/20">
            <Button variant="outline" className="text-xs gap-2">
              <Download className="w-4 h-4" />
              Export Report
            </Button>
            <Button variant="outline" className="text-xs gap-2">
              <FileText className="w-4 h-4" />
              Add Note
            </Button>
            <Button className="ml-auto bg-accent hover:bg-accent/90 text-background text-xs gap-2">
              <CheckCircle className="w-4 h-4" />
              Mark Resolved
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
