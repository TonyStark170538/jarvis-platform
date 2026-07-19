import { useState } from 'react';
import { Play, Square, Plus, Trash2 } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

/**
 * J.A.R.V.I.S. Attack Lab
 * Create and execute realistic cyberattacks against isolated lab environments
 * Design: Dark holographic interface with neon accents
 */

interface AttackScenario {
  id: number;
  name: string;
  description: string;
  category: string;
  status: 'idle' | 'running' | 'completed';
  progress: number;
}

export default function AttackLab() {
  const [scenarios, setScenarios] = useState<AttackScenario[]>([
    { id: 1, name: 'Ransomware Simulation', description: 'Simulate a ransomware attack on lab environment', category: 'Impact', status: 'idle', progress: 0 },
    { id: 2, name: 'Brute Force Attack', description: 'SSH password spray against lab servers', category: 'Initial Access', status: 'idle', progress: 0 },
    { id: 3, name: 'Privilege Escalation', description: 'Linux kernel exploit simulation', category: 'Privilege Escalation', status: 'idle', progress: 0 },
    { id: 4, name: 'Lateral Movement', description: 'SMB pivoting through network segments', category: 'Lateral Movement', status: 'idle', progress: 0 },
  ]);

  const [runningId, setRunningId] = useState<number | null>(null);

  const startAttack = (id: number) => {
    setRunningId(id);
    setScenarios(scenarios.map(s => 
      s.id === id ? { ...s, status: 'running', progress: 0 } : s
    ));

    // Simulate progress
    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 30;
      if (progress >= 100) {
        clearInterval(interval);
        setScenarios(prev => prev.map(s =>
          s.id === id ? { ...s, status: 'completed', progress: 100 } : s
        ));
        setRunningId(null);
      } else {
        setScenarios(prev => prev.map(s =>
          s.id === id ? { ...s, progress } : s
        ));
      }
    }, 800);
  };

  const stopAttack = (id: number) => {
    setRunningId(null);
    setScenarios(scenarios.map(s =>
      s.id === id ? { ...s, status: 'idle', progress: 0 } : s
    ));
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Initial Access': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      case 'Privilege Escalation': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'Lateral Movement': return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
      case 'Impact': return 'bg-red-500/20 text-red-300 border-red-500/30';
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
                <h1 className="text-3xl font-bold font-mono">ATTACK LAB</h1>
                <p className="text-sm text-muted-foreground">Red Team Simulation Environment</p>
              </div>
              <Button className="bg-accent hover:bg-accent/90 text-background font-mono gap-2">
                <Plus className="w-4 h-4" />
                New Scenario
              </Button>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8">
          {/* Quick Start Scenarios */}
          <div className="mb-8">
            <h2 className="text-lg font-mono font-bold mb-4 text-accent">ONE-CLICK SCENARIOS</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {['Ransomware', 'Insider Threat', 'Web Exploitation', 'Credential Theft'].map((scenario, i) => (
                <Card key={i} className="glass glow-border p-4 cursor-pointer hover:shadow-lg transition-all">
                  <p className="font-mono text-sm mb-3">{scenario}</p>
                  <Button size="sm" className="w-full bg-accent/20 hover:bg-accent/30 text-accent border border-accent/50">
                    <Play className="w-3 h-3 mr-2" />
                    Launch
                  </Button>
                </Card>
              ))}
            </div>
          </div>

          {/* Custom Scenarios */}
          <div>
            <h2 className="text-lg font-mono font-bold mb-4 text-accent">CUSTOM SCENARIOS</h2>
            <div className="space-y-4">
              {scenarios.map((scenario) => (
                <Card key={scenario.id} className="glass glow-border p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-mono font-bold text-lg">{scenario.name}</h3>
                        <Badge className={`${getCategoryColor(scenario.category)} border`}>
                          {scenario.category}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">{scenario.description}</p>
                    </div>
                    <div className="flex gap-2">
                      {scenario.status === 'idle' ? (
                        <Button
                          size="sm"
                          onClick={() => startAttack(scenario.id)}
                          className="bg-green-500/20 hover:bg-green-500/30 text-green-300 border border-green-500/50"
                        >
                          <Play className="w-4 h-4 mr-2" />
                          Start
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          onClick={() => stopAttack(scenario.id)}
                          className="bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/50"
                        >
                          <Square className="w-4 h-4 mr-2" />
                          Stop
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-muted-foreground hover:text-destructive"
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>

                  {/* Progress Bar */}
                  {scenario.status !== 'idle' && (
                    <div className="mt-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-mono text-muted-foreground">
                          {scenario.status === 'running' ? 'Running' : 'Completed'}
                        </span>
                        <span className="text-xs font-mono text-accent">{Math.round(scenario.progress)}%</span>
                      </div>
                      <div className="w-full bg-card/50 rounded h-2 overflow-hidden">
                        <div 
                          className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full transition-all duration-300"
                          style={{ width: `${scenario.progress}%` }}
                        ></div>
                      </div>
                    </div>
                  )}
                </Card>
              ))}
            </div>
          </div>

          {/* Scenario Builder */}
          <div className="mt-8">
            <Card className="glass glow-border p-6">
              <h2 className="text-lg font-mono font-bold mb-4 text-accent">SCENARIO BUILDER</h2>
              <p className="text-sm text-muted-foreground mb-4">Create custom attack workflows by chaining detection techniques</p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {['Reconnaissance', 'Execution', 'Persistence'].map((step, i) => (
                  <div key={i} className="p-4 bg-card/30 rounded border border-border/20 text-center">
                    <p className="font-mono text-sm mb-2">{step}</p>
                    <Button size="sm" variant="outline" className="w-full text-xs">
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
