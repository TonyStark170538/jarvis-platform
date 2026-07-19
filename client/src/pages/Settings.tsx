import { useState } from 'react';
import { Save, Bell, Lock, Database, Zap, Network } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import DetectionSystemConfig from '@/components/DetectionSystemConfig';

/**
 * J.A.R.V.I.S. Settings
 * System configuration and preferences
 * Design: Dark holographic interface with organized settings sections
 */

export default function Settings() {
  const [showDetectionSystems, setShowDetectionSystems] = useState(false);
  const [settings, setSettings] = useState({
    alertThreshold: 'high',
    emailNotifications: true,
    slackIntegration: false,
    autoResponse: true,
    dataRetention: '90',
  });

  const handleSave = () => {
    console.log('Settings saved:', settings);
  };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar />
      
      <main className="flex-1 overflow-auto">
        {/* Header */}
        <div className="glass border-b sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div>
              <h1 className="text-3xl font-bold font-mono">SETTINGS</h1>
              <p className="text-sm text-muted-foreground">System configuration and preferences</p>
            </div>
          </div>
        </div>

        <div className="max-w-4xl mx-auto px-6 py-8 space-y-6">
          {/* Detection Systems */}
          <Card className="glass glow-border p-6">
            <div className="flex items-center gap-3 mb-6">
              <Network className="w-5 h-5 text-accent" />
              <h2 className="text-lg font-mono font-bold text-accent">DETECTION SYSTEMS</h2>
            </div>
            <DetectionSystemConfig />
          </Card>

          {/* General Settings */}
          <Card className="glass glow-border p-6">
            <div className="flex items-center gap-3 mb-6">
              <Zap className="w-5 h-5 text-accent" />
              <h2 className="text-lg font-mono font-bold text-accent">GENERAL</h2>
            </div>
            <div className="space-y-6">
              <div>
                <Label className="text-sm font-mono mb-2 block">System Name</Label>
                <Input
                  defaultValue="J.A.R.V.I.S. Command Center"
                  className="bg-card/30 border-border/20 text-foreground"
                />
              </div>
              <div>
                <Label className="text-sm font-mono mb-2 block">Organization</Label>
                <Input
                  defaultValue="Security Operations"
                  className="bg-card/30 border-border/20 text-foreground"
                />
              </div>
              <div>
                <Label className="text-sm font-mono mb-2 block">Alert Threshold</Label>
                <select defaultValue="high" className="w-full px-3 py-2 bg-card/30 border border-border/20 rounded text-foreground text-sm">
                  <option value="low">Low</option>
                  <option value="high">High</option>
                  <option value="critical">Critical Only</option>
                </select>
              </div>
            </div>
          </Card>

          {/* Notifications */}
          <Card className="glass glow-border p-6 mb-6">
            <div className="flex items-center gap-3 mb-6">
              <Bell className="w-5 h-5 text-accent" />
              <h2 className="text-lg font-mono font-bold text-accent">NOTIFICATIONS</h2>
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 bg-card/30 rounded border border-border/20">
                <div>
                  <p className="font-mono text-sm">Email Notifications</p>
                  <p className="text-xs text-muted-foreground">Send alerts via email</p>
                </div>
                <Switch
                  checked={settings.emailNotifications}
                  onCheckedChange={(checked) => setSettings({ ...settings, emailNotifications: checked })}
                />
              </div>
              <div className="flex items-center justify-between p-3 bg-card/30 rounded border border-border/20">
                <div>
                  <p className="font-mono text-sm">Slack Integration</p>
                  <p className="text-xs text-muted-foreground">Send alerts to Slack channel</p>
                </div>
                <Switch
                  checked={settings.slackIntegration}
                  onCheckedChange={(checked) => setSettings({ ...settings, slackIntegration: checked })}
                />
              </div>
              <div className="flex items-center justify-between p-3 bg-card/30 rounded border border-border/20">
                <div>
                  <p className="font-mono text-sm">Critical Alerts Only</p>
                  <p className="text-xs text-muted-foreground">Only notify on critical incidents</p>
                </div>
                <Switch defaultChecked />
              </div>
            </div>
          </Card>

          {/* Security */}
          <Card className="glass glow-border p-6 mb-6">
            <div className="flex items-center gap-3 mb-6">
              <Lock className="w-5 h-5 text-accent" />
              <h2 className="text-lg font-mono font-bold text-accent">SECURITY</h2>
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 bg-card/30 rounded border border-border/20">
                <div>
                  <p className="font-mono text-sm">Two-Factor Authentication</p>
                  <p className="text-xs text-muted-foreground">Require 2FA for all users</p>
                </div>
                <Switch defaultChecked />
              </div>
              <div className="flex items-center justify-between p-3 bg-card/30 rounded border border-border/20">
                <div>
                  <p className="font-mono text-sm">Automatic Response</p>
                  <p className="text-xs text-muted-foreground">Enable automated incident response</p>
                </div>
                <Switch
                  checked={settings.autoResponse}
                  onCheckedChange={(checked) => setSettings({ ...settings, autoResponse: checked })}
                />
              </div>
              <div className="flex items-center justify-between p-3 bg-card/30 rounded border border-border/20">
                <div>
                  <p className="font-mono text-sm">API Rate Limiting</p>
                  <p className="text-xs text-muted-foreground">Limit API requests per minute</p>
                </div>
                <Switch defaultChecked />
              </div>
            </div>
          </Card>

          {/* Data Management */}
          <Card className="glass glow-border p-6 mb-6">
            <div className="flex items-center gap-3 mb-6">
              <Database className="w-5 h-5 text-accent" />
              <h2 className="text-lg font-mono font-bold text-accent">DATA MANAGEMENT</h2>
            </div>
            <div className="space-y-6">
              <div>
                <Label className="text-sm font-mono mb-2 block">Data Retention (days)</Label>
                <Input
                  type="number"
                  value={settings.dataRetention}
                  onChange={(e) => setSettings({ ...settings, dataRetention: e.target.value })}
                  className="bg-card/30 border-border/20 text-foreground"
                />
                <p className="text-xs text-muted-foreground mt-1">Keep logs and events for this duration</p>
              </div>
              <div>
                <Label className="text-sm font-mono mb-2 block">Database Backup</Label>
                <div className="flex gap-2">
                  <Button variant="outline" className="text-xs">
                    Backup Now
                  </Button>
                  <Button variant="outline" className="text-xs">
                    Restore
                  </Button>
                </div>
              </div>
            </div>
          </Card>

          {/* Advanced */}
          <Card className="glass glow-border p-6 mb-6">
            <h2 className="text-lg font-mono font-bold text-accent mb-6">ADVANCED</h2>
            <div className="space-y-4">
              <div className="p-3 bg-card/30 rounded border border-border/20">
                <p className="font-mono text-sm mb-2">System Version</p>
                <p className="text-xs font-mono text-muted-foreground">J.A.R.V.I.S. v1.0.0</p>
              </div>
              <div className="p-3 bg-card/30 rounded border border-border/20">
                <p className="font-mono text-sm mb-2">Last Updated</p>
                <p className="text-xs font-mono text-muted-foreground">July 4, 2026 - 14:32 UTC</p>
              </div>
              <div className="p-3 bg-card/30 rounded border border-border/20">
                <p className="font-mono text-sm mb-2">Database Size</p>
                <p className="text-xs font-mono text-muted-foreground">2.4 GB</p>
              </div>
            </div>
          </Card>

          {/* Save Button */}
          <div className="flex gap-3 justify-end">
            <Button variant="outline">Cancel</Button>
            <Button
              onClick={handleSave}
              className="bg-accent hover:bg-accent/90 text-background font-mono gap-2"
            >
              <Save className="w-4 h-4" />
              Save Changes
            </Button>
          </div>
        </div>
      </main>
    </div>
  );
}
