import { useState } from 'react';
import { Plus, Trash2, Check, X, AlertCircle, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import {
  DetectionSystemConfig,
  DetectionSystemType,
  detectionManager,
} from '@/lib/detectionSystems';

/**
 * Detection System Configuration Component
 * Manage Suricata, Zeek, and Splunk connections
 */

export default function DetectionSystemConfigComponent() {
  const [systems, setSystems] = useState<DetectionSystemConfig[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [formData, setFormData] = useState<Partial<DetectionSystemConfig>>({
    type: 'suricata',
    enabled: true,
    ssl: true,
    verifySSL: true,
    timeout: 10000,
  });

  // Load systems from manager
  const loadSystems = () => {
    setSystems(detectionManager.getSystems());
  };

  // Handle form submission
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.name || !formData.endpoint) {
      alert('Please fill in all required fields');
      return;
    }

    const config: DetectionSystemConfig = {
      id: editingId || `system-${Date.now()}`,
      name: formData.name,
      type: formData.type as DetectionSystemType,
      endpoint: formData.endpoint,
      enabled: formData.enabled ?? true,
      apiKey: formData.apiKey,
      username: formData.username,
      password: formData.password,
      port: formData.port,
      ssl: formData.ssl ?? true,
      verifySSL: formData.verifySSL ?? true,
      timeout: formData.timeout ?? 10000,
      status: 'disconnected',
    };

    detectionManager.registerSystem(config);
    loadSystems();
    resetForm();
  };

  // Test connection
  const handleTestConnection = async (id: string) => {
    setTestingId(id);
    try {
      const success = await detectionManager.testConnection(id);
      const system = detectionManager.getSystem(id);
      if (system) {
        system.status = success ? 'connected' : 'error';
        system.lastConnected = new Date().toISOString();
        if (!success) {
          system.errorMessage = 'Connection failed';
        }
        loadSystems();
      }
    } catch (error) {
      console.error('Test connection error:', error);
    } finally {
      setTestingId(null);
    }
  };

  // Delete system
  const handleDelete = (id: string) => {
    if (confirm('Are you sure you want to remove this detection system?')) {
      detectionManager.removeSystem(id);
      loadSystems();
    }
  };

  // Edit system
  const handleEdit = (system: DetectionSystemConfig) => {
    setFormData(system);
    setEditingId(system.id);
    setShowForm(true);
  };

  // Reset form
  const resetForm = () => {
    setFormData({
      type: 'suricata',
      enabled: true,
      ssl: true,
      verifySSL: true,
      timeout: 10000,
    });
    setEditingId(null);
    setShowForm(false);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-accent" />
          <h3 className="text-sm font-mono font-bold text-accent">DETECTION SYSTEMS</h3>
        </div>
        <Button
          size="sm"
          onClick={() => {
            if (showForm) {
              resetForm();
            } else {
              setShowForm(true);
            }
          }}
          className="text-xs"
        >
          <Plus className="w-3 h-3 mr-1" />
          {showForm ? 'Cancel' : 'Add System'}
        </Button>
      </div>

      {/* Add/Edit Form */}
      {showForm && (
        <Card className="glass glow-border p-4 space-y-3">
          <form onSubmit={handleSubmit} className="space-y-3">
            {/* System Type */}
            <div>
              <label className="text-xs text-muted-foreground block mb-1">
                System Type
              </label>
              <select
                value={formData.type}
                onChange={(e) =>
                  setFormData({ ...formData, type: e.target.value as DetectionSystemType })
                }
                className="w-full px-3 py-2 bg-background border border-border/20 rounded text-sm text-foreground"
              >
                <option value="suricata">Suricata IDS/IPS</option>
                <option value="zeek">Zeek NSM</option>
                <option value="splunk">Splunk SIEM</option>
              </select>
            </div>

            {/* Name */}
            <div>
              <label className="text-xs text-muted-foreground block mb-1">
                System Name
              </label>
              <input
                type="text"
                value={formData.name || ''}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="e.g., Production Suricata"
                className="w-full px-3 py-2 bg-background border border-border/20 rounded text-sm text-foreground placeholder-muted-foreground"
              />
            </div>

            {/* Endpoint */}
            <div>
              <label className="text-xs text-muted-foreground block mb-1">
                API Endpoint
              </label>
              <input
                type="text"
                value={formData.endpoint || ''}
                onChange={(e) => setFormData({ ...formData, endpoint: e.target.value })}
                placeholder="https://suricata.example.com"
                className="w-full px-3 py-2 bg-background border border-border/20 rounded text-sm text-foreground placeholder-muted-foreground"
              />
            </div>

            {/* Authentication */}
            {formData.type === 'splunk' ? (
              <>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-xs text-muted-foreground block mb-1">
                      Username
                    </label>
                    <input
                      type="text"
                      value={formData.username || ''}
                      onChange={(e) =>
                        setFormData({ ...formData, username: e.target.value })
                      }
                      placeholder="admin"
                      className="w-full px-3 py-2 bg-background border border-border/20 rounded text-sm text-foreground placeholder-muted-foreground"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground block mb-1">
                      Password
                    </label>
                    <input
                      type="password"
                      value={formData.password || ''}
                      onChange={(e) =>
                        setFormData({ ...formData, password: e.target.value })
                      }
                      placeholder="••••••••"
                      className="w-full px-3 py-2 bg-background border border-border/20 rounded text-sm text-foreground placeholder-muted-foreground"
                    />
                  </div>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">
                    Port
                  </label>
                  <input
                    type="number"
                    value={formData.port || 8089}
                    onChange={(e) =>
                      setFormData({ ...formData, port: parseInt(e.target.value) })
                    }
                    className="w-full px-3 py-2 bg-background border border-border/20 rounded text-sm text-foreground"
                  />
                </div>
              </>
            ) : (
              <div>
                <label className="text-xs text-muted-foreground block mb-1">
                  API Key
                </label>
                <input
                  type="password"
                  value={formData.apiKey || ''}
                  onChange={(e) => setFormData({ ...formData, apiKey: e.target.value })}
                  placeholder="••••••••••••••••"
                  className="w-full px-3 py-2 bg-background border border-border/20 rounded text-sm text-foreground placeholder-muted-foreground"
                />
              </div>
            )}

            {/* Options */}
            <div className="flex items-center gap-3 pt-2">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.enabled ?? true}
                  onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                  className="w-4 h-4"
                />
                <span className="text-xs text-muted-foreground">Enabled</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.ssl ?? true}
                  onChange={(e) => setFormData({ ...formData, ssl: e.target.checked })}
                  className="w-4 h-4"
                />
                <span className="text-xs text-muted-foreground">Use SSL</span>
              </label>
            </div>

            {/* Submit Buttons */}
            <div className="flex gap-2 pt-2">
              <Button type="submit" size="sm" className="text-xs flex-1">
                {editingId ? 'Update' : 'Add'} System
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={resetForm}
                className="text-xs"
              >
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Systems List */}
      <div className="space-y-2">
        {systems.length === 0 ? (
          <div className="p-4 rounded border border-border/20 bg-card/50 text-center text-muted-foreground text-sm">
            <AlertCircle className="w-4 h-4 mx-auto mb-2 opacity-50" />
            <p>No detection systems configured</p>
          </div>
        ) : (
          systems.map((system) => (
            <Card
              key={system.id}
              className="glass glow-border p-3 space-y-2"
            >
              {/* System Header */}
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <p className="font-mono font-bold text-sm text-accent">
                    {system.name}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {system.type.toUpperCase()} • {system.endpoint}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge
                    className={`text-xs border ${
                      system.status === 'connected'
                        ? 'bg-green-500/20 text-green-300 border-green-500/30'
                        : system.status === 'error'
                        ? 'bg-red-500/20 text-red-300 border-red-500/30'
                        : 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30'
                    }`}
                  >
                    {system.status === 'connected' ? '🟢' : system.status === 'error' ? '🔴' : '🟡'}{' '}
                    {system.status}
                  </Badge>
                </div>
              </div>

              {/* Last Connected */}
              {system.lastConnected && (
                <p className="text-xs text-muted-foreground">
                  Last connected: {new Date(system.lastConnected).toLocaleString()}
                </p>
              )}

              {/* Error Message */}
              {system.errorMessage && (
                <p className="text-xs text-red-300 bg-red-500/10 p-2 rounded border border-red-500/20">
                  {system.errorMessage}
                </p>
              )}

              {/* Actions */}
              <div className="flex gap-2 pt-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleTestConnection(system.id)}
                  disabled={testingId === system.id}
                  className="text-xs flex-1"
                >
                  {testingId === system.id ? (
                    <>
                      <span className="animate-spin mr-1">⟳</span>
                      Testing...
                    </>
                  ) : (
                    <>
                      <Check className="w-3 h-3 mr-1" />
                      Test
                    </>
                  )}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleEdit(system)}
                  className="text-xs"
                >
                  Edit
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleDelete(system.id)}
                  className="text-xs text-red-300 hover:text-red-300"
                >
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            </Card>
          ))
        )}
      </div>

      {/* Info Box */}
      <div className="p-3 bg-accent/5 border border-accent/20 rounded text-xs text-muted-foreground space-y-1">
        <p className="font-mono font-bold text-accent mb-2">Configuration Guide:</p>
        <ul className="space-y-1 ml-2">
          <li>• <strong>Suricata:</strong> Requires API key and REST API endpoint</li>
          <li>• <strong>Zeek:</strong> Requires API key and Zeek REST API endpoint</li>
          <li>• <strong>Splunk:</strong> Requires username, password, and management port (8089)</li>
        </ul>
      </div>
    </div>
  );
}
