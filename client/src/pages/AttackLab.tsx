import { useEffect, useState } from 'react';
import { Play, Square, Plus, Trash2, Radio, ShieldAlert } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { getAttackScenarios } from '@/security/eventGenerator';
import { securityStore } from '@/security/securityStore';
import type { AttackScenario, SecuritySeverity, SecurityStoreSnapshot } from '@/security/types';

interface ScenarioCard {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: SecuritySeverity;
  status: 'idle' | 'running' | 'completed';
  progress: number;
}

const scenarioDefinitions = getAttackScenarios();

const initialScenarios: ScenarioCard[] = scenarioDefinitions.map((scenario) => ({
  id: scenario.id,
  name: scenario.name,
  description: scenario.description,
  category: scenario.category,
  severity: scenario.severity,
  status: 'idle',
  progress: 0,
}));

const scenarioAliases: Record<string, string> = {
  ransomware: 'scenario-malware-detection',
  'insider-threat': 'scenario-privilege-escalation',
  'web-exploitation': 'scenario-port-scan',
  'credential-theft': 'scenario-ssh-brute-force',
};

export default function AttackLab() {
  const [scenarios, setScenarios] = useState<ScenarioCard[]>(initialScenarios);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<SecurityStoreSnapshot>(securityStore.getSnapshot());

  useEffect(() => securityStore.subscribe(setSnapshot), []);

  const startAttack = async (id: string) => {
    if (runningId) return;

    setRunningId(id);
    setScenarios((current) => current.map((scenario) =>
      scenario.id === id
        ? { ...scenario, status: 'running', progress: 5 }
        : scenario
    ));

    try {
      await securityStore.runScenario(id);
      setScenarios((current) => current.map((scenario) =>
        scenario.id === id
          ? { ...scenario, status: 'completed', progress: 100 }
          : scenario
      ));
    } catch (error) {
      console.error('Attack Lab simulation failed:', error);
      setScenarios((current) => current.map((scenario) =>
        scenario.id === id
          ? { ...scenario, status: 'idle', progress: 0 }
          : scenario
      ));
    } finally {
      setRunningId(null);
    }
  };

  const stopAttack = () => {
    securityStore.stopSimulation();
    setRunningId(null);
    setScenarios((current) => current.map((scenario) =>
      scenario.status === 'running'
        ? { ...scenario, status: 'idle', progress: 0 }
        : scenario
    ));
  };

  const launchQuickScenario = (id: string) => {
    const scenarioId = scenarioAliases[id];
    if (scenarioId) void startAttack(scenarioId);
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Initial Access': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      case 'Execution': return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
      case 'Privilege Escalation': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'Lateral Movement': return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
      case 'Impact': return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'Command and Control': return 'bg-pink-500/20 text-pink-300 border-pink-500/30';
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

  const latestDetections = snapshot.detections.slice(0, 5);

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
                <Button disabled className="bg-accent/20 text-accent border border-accent/30 font-mono gap-2">
                  <Plus className="w-4 h-4" />
                  New Scenario
                </Button>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="mb-8">
            <h2 className="text-lg font-mono font-bold mb-4 text-accent">ONE-CLICK SCENARIOS</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                ['ransomware', 'Ransomware'],
                ['insider-threat', 'Insider Threat'],
                ['web-exploitation', 'Web Exploitation'],
                ['credential-theft', 'Credential Theft'],
              ].map(([id, label]) => (
                <Card key={id} className="glass glow-border p-4">
                  <p className="font-mono text-sm mb-3">{label}</p>
                  <Button
                    size="sm"
                    disabled={Boolean(runningId)}
                    onClick={() => launchQuickScenario(id)}
                    className="w-full bg-accent/20 hover:bg-accent/30 text-accent border border-accent/50"
                  >
                    <Play className="w-3 h-3 mr-2" />
                    Launch
                  </Button>
                </Card>
              ))}
            </div>
          </div>

          <div>
            <h2 className="text-lg font-mono font-bold mb-4 text-accent">SIMULATION SCENARIOS</h2>
            <div className="space-y-4">
              {scenarios.map((scenario) => (
                <Card key={scenario.id} className="glass glow-border p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <div className="flex flex-wrap items-center gap-3 mb-2">
                        <h3 className="font-mono font-bold text-lg">{scenario.name}</h3>
                        <Badge className={`${getCategoryColor(scenario.category)} border`}>
                          {scenario.category}
                        </Badge>
                        <Badge className={`${getSeverityColor(scenario.severity)} border`}>
                          {scenario.severity.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">{scenario.description}</p>
                    </div>
                    <div className="flex gap-2 ml-4">
                      {scenario.status === 'running' ? (
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
                          onClick={() => startAttack(scenario.id)}
                          className="bg-green-500/20 hover:bg-green-500/30 text-green-300 border border-green-500/50"
                        >
                          <Play className="w-4 h-4 mr-2" />
                          Start
                        </Button>
                      )}
                      <Button size="sm" variant="ghost" disabled className="text-muted-foreground">
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>

                  {scenario.status !== 'idle' && (
                    <div className="mt-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-mono text-muted-foreground">
                          {scenario.status === 'running' ? 'Generating telemetry' : 'Completed'}
                        </span>
                        <span className="text-xs font-mono text-accent">{Math.round(scenario.progress)}%</span>
                      </div>
                      <div className="w-full bg-card/50 rounded h-2 overflow-hidden">
                        <div
                          className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full transition-all duration-300"
                          style={{ width: `${scenario.progress}%` }}
                        />
                      </div>
                    </div>
                  )}
                </Card>
              ))}
            </div>
          </div>

          <div className="mt-8">
            <Card className="glass glow-border p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-lg font-mono font-bold text-accent">LIVE DETECTION OUTPUT</h2>
                  <p className="text-xs text-muted-foreground mt-1">Detections generated by the security engine</p>
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
          </div>

          <div className="mt-8">
            <Card className="glass glow-border p-6">
              <h2 className="text-lg font-mono font-bold mb-4 text-accent">SCENARIO BUILDER</h2>
              <p className="text-sm text-muted-foreground mb-4">Create custom attack workflows by chaining detection techniques</p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {['Reconnaissance', 'Execution', 'Persistence'].map((step) => (
                  <div key={step} className="p-4 bg-card/30 rounded border border-border/20 text-center">
                    <p className="font-mono text-sm mb-2">{step}</p>
                    <Button size="sm" variant="outline" className="w-full text-xs" disabled>
                      + Add Step
                    </Button>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}
