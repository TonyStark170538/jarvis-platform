import { useEffect, useMemo, useState } from 'react';
import { Play, Square, Radio, ShieldAlert, Activity } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ATTACK_SCENARIOS } from '@/security/eventGenerator';
import { securityStore } from '@/security/securityStore';
import type { AttackScenario, SecuritySeverity, SecurityStoreSnapshot } from '@/security/types';

interface ScenarioCard {
  scenario: AttackScenario;
  severity: SecuritySeverity;
  status: 'idle' | 'running' | 'completed';
  progress: number;
}

const severityWeight: Record<SecuritySeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function getScenarioSeverity(scenario: AttackScenario): SecuritySeverity {
  return scenario.events.reduce<SecuritySeverity>(
    (highest, item) =>
      severityWeight[item.event.severity] > severityWeight[highest]
        ? item.event.severity
        : highest,
    'info'
  );
}

const initialScenarios: ScenarioCard[] = ATTACK_SCENARIOS.map((scenario) => ({
  scenario,
  severity: getScenarioSeverity(scenario),
  status: 'idle',
  progress: 0,
}));

export default function AttackLab() {
  const [scenarios, setScenarios] = useState<ScenarioCard[]>(initialScenarios);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<SecurityStoreSnapshot>(securityStore.getSnapshot());

  useEffect(() => securityStore.subscribe(setSnapshot), []);

  const startAttack = async (scenarioId: string) => {
    if (runningId) return;

    setRunningId(scenarioId);
    setScenarios((current) => current.map((item) =>
      item.scenario.id === scenarioId
        ? { ...item, status: 'running', progress: 5 }
        : item
    ));

    try {
      await securityStore.runScenario(scenarioId);
      setScenarios((current) => current.map((item) =>
        item.scenario.id === scenarioId
          ? { ...item, status: 'completed', progress: 100 }
          : item
      ));
    } catch (error) {
      console.error('Attack Lab simulation failed:', error);
      setScenarios((current) => current.map((item) =>
        item.scenario.id === scenarioId
          ? { ...item, status: 'idle', progress: 0 }
          : item
      ));
    } finally {
      setRunningId(null);
    }
  };

  const stopAttack = () => {
    securityStore.stopSimulation();
    setRunningId(null);
    setScenarios((current) => current.map((item) =>
      item.status === 'running'
        ? { ...item, status: 'idle', progress: 0 }
        : item
    ));
  };

  const latestDetections = snapshot.detections.slice(0, 5);
  const latestThreads = snapshot.incidentThreads.slice(0, 3);

  const totalScenarioEvents = useMemo(
    () => ATTACK_SCENARIOS.reduce((sum, scenario) => sum + scenario.events.length, 0),
    []
  );

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Initial Access': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      case 'Execution': return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
      case 'Exfiltration': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'Malware': return 'bg-red-500/20 text-red-300 border-red-500/30';
      default: return 'bg-gray-500/20 text-gray-300 border-gray-500/30';
    }
  };

  const getSeverityColor = (severity: SecuritySeverity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
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
                <h1 className="text-3xl font-bold font-mono">ATTACK LAB</h1>
                <p className="text-sm text-muted-foreground">Safe Red Team Simulation Environment</p>
              </div>
              <div className="flex items-center gap-3">
                <Badge className="bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 gap-2">
                  <Radio className="w-3 h-3" />
                  {snapshot.events.length} EVENTS
                </Badge>
                <Badge className="bg-blue-500/10 text-blue-300 border border-blue-500/30 gap-2">
                  <Activity className="w-3 h-3" />
                  {snapshot.runs.length} RUNS
                </Badge>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <Card className="glass glow-border p-4">
              <p className="text-xs text-muted-foreground font-mono">AVAILABLE SCENARIOS</p>
              <p className="text-2xl font-mono font-bold text-cyan-400 mt-1">{ATTACK_SCENARIOS.length}</p>
            </Card>
            <Card className="glass glow-border p-4">
              <p className="text-xs text-muted-foreground font-mono">SIMULATED EVENT TEMPLATES</p>
              <p className="text-2xl font-mono font-bold text-blue-400 mt-1">{totalScenarioEvents}</p>
            </Card>
            <Card className="glass glow-border p-4">
              <p className="text-xs text-muted-foreground font-mono">ACTIVE DETECTIONS</p>
              <p className="text-2xl font-mono font-bold text-orange-400 mt-1">{snapshot.detections.length}</p>
            </Card>
          </div>

          <div className="mb-8">
            <h2 className="text-lg font-mono font-bold mb-4 text-accent">SIMULATION SCENARIOS</h2>
            <div className="space-y-4">
              {scenarios.map(({ scenario, severity, status, progress }) => (
                <Card key={scenario.id} className="glass glow-border p-6">
                  <div className="flex items-start justify-between mb-4 gap-4">
                    <div className="flex-1">
                      <div className="flex flex-wrap items-center gap-3 mb-2">
                        <h3 className="font-mono font-bold text-lg">{scenario.name}</h3>
                        <Badge className={`${getCategoryColor(scenario.category)} border`}>
                          {scenario.category}
                        </Badge>
                        <Badge className={`${getSeverityColor(severity)} border`}>
                          {severity.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">{scenario.description}</p>
                      <p className="text-xs text-muted-foreground font-mono mt-2">
                        {scenario.events.length} telemetry events · {scenario.mitreTechniques.join(', ')}
                      </p>
                    </div>
                    <div className="flex gap-2 shrink-0">
                      {status === 'running' ? (
                        <Button
                          size="sm"
                          onClick={stopAttack}
                          className="bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/50"
                        >
                          <Square className="w-4 h-4 mr-2" />
                          Stop
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          disabled={Boolean(runningId)}
                          onClick={() => void startAttack(scenario.id)}
                          className="bg-green-500/20 hover:bg-green-500/30 text-green-300 border border-green-500/50"
                        >
                          <Play className="w-4 h-4 mr-2" />
                          {status === 'completed' ? 'Run Again' : 'Start'}
                        </Button>
                      )}
                    </div>
                  </div>

                  {status !== 'idle' && (
                    <div className="mt-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-mono text-muted-foreground">
                          {status === 'running' ? 'Generating telemetry' : 'Completed'}
                        </span>
                        <span className="text-xs font-mono text-accent">{progress}%</span>
                      </div>
                      <div className="w-full bg-card/50 rounded h-2 overflow-hidden">
                        <div
                          className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full transition-all duration-300"
                          style={{ width: `${progress}%` }}
                        />
                      </div>
                    </div>
                  )}
                </Card>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <Card className="glass glow-border p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-lg font-mono font-bold text-accent">LIVE DETECTION OUTPUT</h2>
                  <p className="text-xs text-muted-foreground mt-1">Detections generated by deterministic security rules</p>
                </div>
                <ShieldAlert className="w-5 h-5 text-accent" />
              </div>
              <div className="space-y-2">
                {latestDetections.length === 0 ? (
                  <p className="text-sm text-muted-foreground font-mono">Awaiting simulated security telemetry...</p>
                ) : latestDetections.map((detection) => (
                  <div key={detection.id} className="p-3 bg-card/30 rounded border border-border/20 flex items-center justify-between gap-4">
                    <div>
                      <p className="text-sm font-mono">{detection.title}</p>
                      <p className="text-xs text-muted-foreground mt-1">{detection.description}</p>
                    </div>
                    <Badge className={`${getSeverityColor(detection.severity)} border shrink-0`}>
                      {detection.confidence}% CONF.
                    </Badge>
                  </div>
                ))}
              </div>
            </Card>

            <Card className="glass glow-border p-6">
              <h2 className="text-lg font-mono font-bold mb-4 text-accent">INCIDENT CORRELATION</h2>
              <div className="space-y-3">
                {latestThreads.length === 0 ? (
                  <p className="text-sm text-muted-foreground font-mono">No correlated incidents yet.</p>
                ) : latestThreads.map((thread) => (
                  <div key={thread.id} className="p-3 bg-card/30 rounded border border-border/20">
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-mono">{thread.pattern}</p>
                      <Badge className={`${getSeverityColor(thread.severity)} border shrink-0`}>
                        {thread.severity.toUpperCase()}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {thread.events.length} related event(s) · {Math.round(thread.correlationStrength * 100)}% correlation
                    </p>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          <div className="mt-8">
            <Card className="glass glow-border p-6">
              <h2 className="text-lg font-mono font-bold mb-4 text-accent">SAFETY BOUNDARY</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Attack Lab generates synthetic security telemetry only. Scenarios do not open network connections,
                execute operating-system commands, scan real hosts, or modify the machine running J.A.R.V.I.S.
              </p>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}
