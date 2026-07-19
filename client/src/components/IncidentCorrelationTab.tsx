import { AlertCircle, Link2, TrendingUp } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { IncidentThread } from '@/lib/incidentCorrelation';

interface IncidentCorrelationTabProps {
  threads: IncidentThread[];
  currentIncidentId: string;
}

/**
 * Incident Correlation Tab Component
 * Displays incident threads, parent-child relationships, and attack patterns
 */
export default function IncidentCorrelationTab({
  threads,
  currentIncidentId,
}: IncidentCorrelationTabProps) {
  const currentThread = threads.find((t) => t.rootEventId === currentIncidentId);
  const relatedThreads = threads.filter(
    (t) => t.rootEventId !== currentIncidentId && t.correlationStrength > 0.5
  );

  return (
    <div className="space-y-4">
      {/* Current Incident Thread */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Link2 className="w-4 h-4 text-accent" />
          <h3 className="text-sm font-mono font-bold text-accent">INCIDENT THREAD</h3>
        </div>

        {currentThread ? (
          <div className="p-4 rounded border border-accent/30 bg-accent/5 space-y-3">
            {/* Thread Info */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-xs text-muted-foreground">Pattern</p>
                <p className="text-sm font-mono font-bold text-accent mt-1">
                  {currentThread.pattern}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Correlation Strength</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className="flex-1 h-2 bg-background rounded overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-accent to-cyan-400"
                      style={{
                        width: `${Math.round(currentThread.correlationStrength * 100)}%`,
                      }}
                    ></div>
                  </div>
                  <span className="text-xs font-mono">
                    {Math.round(currentThread.correlationStrength * 100)}%
                  </span>
                </div>
              </div>
            </div>

            {/* Attack Techniques */}
            <div>
              <p className="text-xs text-muted-foreground mb-2">MITRE ATT&CK Techniques</p>
              <div className="flex flex-wrap gap-2">
                {currentThread.attackTechniques.length > 0 ? (
                  currentThread.attackTechniques.map((technique) => (
                    <Badge
                      key={technique}
                      className="bg-blue-500/20 text-blue-300 border-blue-500/30 border text-xs"
                    >
                      {technique}
                    </Badge>
                  ))
                ) : (
                  <span className="text-xs text-muted-foreground">No techniques identified</span>
                )}
              </div>
            </div>

            {/* Thread Events */}
            <div>
              <p className="text-xs text-muted-foreground mb-2">
                Events in Thread ({currentThread.events.length})
              </p>
              <div className="space-y-1">
                {currentThread.events.map((eventId, idx) => (
                  <div
                    key={eventId}
                    className="p-2 bg-background/50 rounded border border-border/10 text-xs"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground">
                        {idx === 0 ? '🔴' : '🟡'} Event {idx + 1}
                      </span>
                      <span className="text-muted-foreground">({eventId})</span>
                      {idx === 0 && (
                        <Badge className="ml-auto bg-accent/20 text-accent border-accent/30 border text-xs">
                          ROOT
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="p-4 rounded border border-border/20 bg-card/50 text-center text-muted-foreground text-sm">
            No correlation data available
          </div>
        )}
      </div>

      {/* Related Incidents */}
      {relatedThreads.length > 0 && (
        <div className="space-y-3 pt-4 border-t border-border/20">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-muted-foreground" />
            <h3 className="text-sm font-mono font-bold text-muted-foreground">
              RELATED INCIDENTS ({relatedThreads.length})
            </h3>
          </div>

          <div className="space-y-2">
            {relatedThreads.map((thread) => (
              <div
                key={thread.id}
                className="p-3 rounded border border-border/20 bg-card/50 hover:border-accent/30 transition-colors cursor-pointer group"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <p className="text-sm font-mono font-bold group-hover:text-accent transition-colors">
                      {thread.pattern}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      {thread.events.length} events • Severity: {thread.severity}
                    </p>
                  </div>
                  <Badge
                    className={`text-xs border ${
                      thread.correlationStrength > 0.8
                        ? 'bg-red-500/20 text-red-300 border-red-500/30'
                        : thread.correlationStrength > 0.6
                        ? 'bg-orange-500/20 text-orange-300 border-orange-500/30'
                        : 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30'
                    }`}
                  >
                    {Math.round(thread.correlationStrength * 100)}% Match
                  </Badge>
                </div>

                {/* Correlation Reasons */}
                <div className="text-xs text-muted-foreground space-y-1">
                  <p className="font-mono text-xs mb-1">Why Related:</p>
                  <ul className="space-y-0.5 ml-2">
                    <li>• Same attack pattern detected</li>
                    <li>• Events within temporal window</li>
                    <li>• Similar target infrastructure</li>
                  </ul>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No Correlations */}
      {relatedThreads.length === 0 && (
        <div className="text-center py-4 text-muted-foreground text-xs">
          <AlertCircle className="w-4 h-4 mx-auto mb-2 opacity-50" />
          <p>No related incidents found</p>
        </div>
      )}
    </div>
  );
}
