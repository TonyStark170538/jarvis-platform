import { useState, useEffect } from 'react';
import { AlertTriangle, RefreshCw, Download, Shield, TrendingUp } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { generateMockThreatIndicators } from '@/lib/mockDetectionSystems';
import { ThreatIndicator } from '@/lib/detectionSystems';

/**
 * Threat Intelligence Feed Component
 * Displays threat indicators, IOCs, and malicious artifacts
 * Design: Dark holographic interface with threat severity indicators
 */

interface ThreatIntelligenceFeedProps {
  autoRefresh?: boolean;
  refreshInterval?: number;
}

export default function ThreatIntelligenceFeed({
  autoRefresh = true,
  refreshInterval = 30000,
}: ThreatIntelligenceFeedProps) {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string>(new Date().toISOString());
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  });

  /**
   * Load threat indicators
   */
  const loadIndicators = async () => {
    setIsLoading(true);
    try {
      // In production, this would fetch from real threat intelligence APIs
      // (MISP, AlienVault OTX, Shodan, etc.)
      const mockIndicators = generateMockThreatIndicators(20);
      setIndicators(mockIndicators);
      setLastUpdated(new Date().toISOString());

      // Calculate stats
      const newStats = {
        total: mockIndicators.length,
        critical: mockIndicators.filter((i) => i.severity === 'critical').length,
        high: mockIndicators.filter((i) => i.severity === 'high').length,
        medium: mockIndicators.filter((i) => i.severity === 'medium').length,
        low: mockIndicators.filter((i) => i.severity === 'low').length,
      };
      setStats(newStats);
    } catch (error) {
      console.error('Failed to load threat indicators:', error);
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Set up auto-refresh
   */
  useEffect(() => {
    loadIndicators();

    if (!autoRefresh) return;

    const interval = setInterval(() => {
      loadIndicators();
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [autoRefresh, refreshInterval]);

  /**
   * Filter indicators by type
   */
  const filteredIndicators = selectedType
    ? indicators.filter((i) => i.type === selectedType)
    : indicators;

  /**
   * Get severity color
   */
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'high':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'low':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      default:
        return 'bg-gray-500/20 text-gray-300 border-gray-500/30';
    }
  };

  /**
   * Get severity icon
   */
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return '🔴';
      case 'high':
        return '🟠';
      case 'medium':
        return '🟡';
      case 'low':
        return '🔵';
      default:
        return '⚪';
    }
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-accent" />
          <h3 className="text-sm font-mono font-bold text-accent">THREAT INTELLIGENCE</h3>
        </div>
        <Button
          size="sm"
          onClick={loadIndicators}
          disabled={isLoading}
          className="text-xs"
        >
          <RefreshCw className={`w-3 h-3 mr-1 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-5 gap-2">
        <Card className="glass glow-border p-3 text-center">
          <p className="text-xs text-muted-foreground">Total</p>
          <p className="text-lg font-mono font-bold text-accent">{stats.total}</p>
        </Card>
        <Card className="glass glow-border p-3 text-center">
          <p className="text-xs text-red-300">Critical</p>
          <p className="text-lg font-mono font-bold text-red-300">{stats.critical}</p>
        </Card>
        <Card className="glass glow-border p-3 text-center">
          <p className="text-xs text-orange-300">High</p>
          <p className="text-lg font-mono font-bold text-orange-300">{stats.high}</p>
        </Card>
        <Card className="glass glow-border p-3 text-center">
          <p className="text-xs text-yellow-300">Medium</p>
          <p className="text-lg font-mono font-bold text-yellow-300">{stats.medium}</p>
        </Card>
        <Card className="glass glow-border p-3 text-center">
          <p className="text-xs text-blue-300">Low</p>
          <p className="text-lg font-mono font-bold text-blue-300">{stats.low}</p>
        </Card>
      </div>

      {/* Type Filter */}
      <div className="flex gap-2 flex-wrap">
        <Button
          size="sm"
          variant={selectedType === null ? 'default' : 'outline'}
          onClick={() => setSelectedType(null)}
          className="text-xs"
        >
          All
        </Button>
        {['ip', 'domain', 'hash', 'url', 'email'].map((type) => (
          <Button
            key={type}
            size="sm"
            variant={selectedType === type ? 'default' : 'outline'}
            onClick={() => setSelectedType(type)}
            className="text-xs"
          >
            {type.toUpperCase()}
          </Button>
        ))}
      </div>

      {/* Indicators List */}
      <div className="space-y-2 max-h-96 overflow-y-auto">
        {filteredIndicators.length === 0 ? (
          <div className="p-4 rounded border border-border/20 bg-card/50 text-center text-muted-foreground text-sm">
            <AlertTriangle className="w-4 h-4 mx-auto mb-2 opacity-50" />
            <p>No threat indicators found</p>
          </div>
        ) : (
          filteredIndicators.map((indicator) => (
            <Card
              key={indicator.id}
              className="glass glow-border p-3 space-y-2 hover:bg-card/40 transition-colors"
            >
              {/* Header */}
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge
                      className={`text-xs border ${getSeverityColor(indicator.severity)}`}
                    >
                      {getSeverityIcon(indicator.severity)} {indicator.severity.toUpperCase()}
                    </Badge>
                    <Badge variant="outline" className="text-xs">
                      {indicator.type.toUpperCase()}
                    </Badge>
                  </div>
                  <p className="font-mono text-xs text-foreground break-all">
                    {indicator.value}
                  </p>
                </div>
              </div>

              {/* Details */}
              <p className="text-xs text-muted-foreground">{indicator.description}</p>

              {/* Metadata */}
              <div className="grid grid-cols-3 gap-2 text-xs">
                <div className="p-2 bg-card/30 rounded border border-border/20">
                  <p className="text-muted-foreground">Source</p>
                  <p className="font-mono text-foreground">{indicator.source}</p>
                </div>
                <div className="p-2 bg-card/30 rounded border border-border/20">
                  <p className="text-muted-foreground">Confidence</p>
                  <p className="font-mono text-accent">{indicator.confidence}%</p>
                </div>
                <div className="p-2 bg-card/30 rounded border border-border/20">
                  <p className="text-muted-foreground">Last Seen</p>
                  <p className="font-mono text-foreground">
                    {indicator.lastSeen
                      ? new Date(indicator.lastSeen).toLocaleDateString()
                      : 'N/A'}
                  </p>
                </div>
              </div>

              {/* Tags */}
              {indicator.tags && indicator.tags.length > 0 && (
                <div className="flex gap-1 flex-wrap">
                  {indicator.tags.map((tag) => (
                    <Badge
                      key={tag}
                      variant="outline"
                      className="text-xs bg-accent/10 text-accent border-accent/30"
                    >
                      #{tag}
                    </Badge>
                  ))}
                </div>
              )}

              {/* Actions */}
              <div className="flex gap-2 pt-1">
                <Button size="sm" variant="outline" className="text-xs flex-1">
                  <TrendingUp className="w-3 h-3 mr-1" />
                  Track
                </Button>
                <Button size="sm" variant="outline" className="text-xs">
                  <Download className="w-3 h-3" />
                </Button>
              </div>
            </Card>
          ))
        )}
      </div>

      {/* Last Updated */}
      <p className="text-xs text-muted-foreground text-center">
        Last updated: {new Date(lastUpdated).toLocaleTimeString()}
      </p>

      {/* Info Box */}
      <div className="p-3 bg-accent/5 border border-accent/20 rounded text-xs text-muted-foreground space-y-1">
        <p className="font-mono font-bold text-accent mb-2">Threat Intelligence Sources:</p>
        <ul className="space-y-1 ml-2">
          <li>• MISP - Malware Information Sharing Platform</li>
          <li>• AlienVault OTX - Open Threat Exchange</li>
          <li>• Shodan - Internet search engine for devices</li>
          <li>• Internal Detection Systems (Suricata, Zeek, Splunk)</li>
        </ul>
      </div>
    </div>
  );
}
