import { useState } from 'react';
import { Play, RotateCcw, AlertCircle, CheckCircle, Clock, XCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  ResponseAction,
  ActionType,
  ACTION_TEMPLATES,
  createResponseAction,
  executeAction,
  rollbackAction,
  getRecommendedActions,
  formatActionStatus,
  getStatusColor,
} from '@/lib/responseActions';

interface ResponseActionPanelProps {
  incidentType: string;
  incidentSeverity: 'critical' | 'high' | 'medium' | 'low';
  targetIP?: string;
  targetHost?: string;
}

/**
 * Response Action Panel Component
 * Displays recommended actions and execution controls
 */
export default function ResponseActionPanel({
  incidentType,
  incidentSeverity,
  targetIP = '203.0.113.45',
  targetHost = 'prod-server-01',
}: ResponseActionPanelProps) {
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [executingActionId, setExecutingActionId] = useState<string | null>(null);
  const [expandedActionId, setExpandedActionId] = useState<string | null>(null);

  const recommendedActionTypes = getRecommendedActions(incidentType, incidentSeverity);

  // Create and queue an action
  const handleCreateAction = (actionType: ActionType, target: string) => {
    const newAction = createResponseAction(actionType, target, incidentSeverity);
    setActions([...actions, newAction]);
  };

  // Execute an action
  const handleExecuteAction = async (action: ResponseAction) => {
    setExecutingActionId(action.id);

    try {
      const updatedAction = await executeAction(action, (status, details) => {
        // Update action in state
        setActions((prevActions) =>
          prevActions.map((a) =>
            a.id === action.id
              ? { ...a, status, auditLog: [...a.auditLog] }
              : a
          )
        );
      });

      setActions((prevActions) =>
        prevActions.map((a) => (a.id === action.id ? updatedAction : a))
      );
    } finally {
      setExecutingActionId(null);
    }
  };

  // Rollback an action
  const handleRollbackAction = async (action: ResponseAction) => {
    setExecutingActionId(action.id);

    try {
      const updatedAction = await rollbackAction(action, (status, details) => {
        setActions((prevActions) =>
          prevActions.map((a) =>
            a.id === action.id
              ? { ...a, status, auditLog: [...a.auditLog] }
              : a
          )
        );
      });

      setActions((prevActions) =>
        prevActions.map((a) => (a.id === action.id ? updatedAction : a))
      );
    } finally {
      setExecutingActionId(null);
    }
  };

  return (
    <div className="space-y-4">
      {/* Recommended Actions */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 mb-3">
          <AlertCircle className="w-4 h-4 text-accent" />
          <h3 className="text-sm font-mono font-bold text-accent">RECOMMENDED ACTIONS</h3>
        </div>

        <div className="grid grid-cols-1 gap-2">
          {recommendedActionTypes.map((actionType) => {
            const template = ACTION_TEMPLATES[actionType];
            const target = actionType === 'block-ip' ? targetIP : targetHost;

            return (
              <button
                key={actionType}
                onClick={() => handleCreateAction(actionType, target)}
                className="p-3 rounded border border-accent/30 bg-accent/5 hover:bg-accent/10 transition-colors text-left group"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <p className="text-sm font-mono font-bold text-accent group-hover:text-cyan-300 transition-colors">
                      {template.icon} {template.name}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">{template.description}</p>
                    <div className="flex items-center gap-2 mt-2">
                      <Badge className={`text-xs ${
                        template.riskLevel === 'high'
                          ? 'bg-red-500/20 text-red-300 border-red-500/30'
                          : template.riskLevel === 'medium'
                          ? 'bg-orange-500/20 text-orange-300 border-orange-500/30'
                          : 'bg-green-500/20 text-green-300 border-green-500/30'
                      } border`}>
                        {template.riskLevel.toUpperCase()} RISK
                      </Badge>
                      <span className="text-xs text-muted-foreground">
                        ~{template.estimatedDuration}s
                      </span>
                    </div>
                  </div>
                  <Play className="w-4 h-4 text-accent opacity-0 group-hover:opacity-100 transition-opacity mt-1" />
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Queued/Executed Actions */}
      {actions.length > 0 && (
        <div className="space-y-3 pt-4 border-t border-border/20">
          <div className="flex items-center gap-2 mb-3">
            <Clock className="w-4 h-4 text-muted-foreground" />
            <h3 className="text-sm font-mono font-bold text-muted-foreground">
              EXECUTION QUEUE ({actions.length})
            </h3>
          </div>

          <div className="space-y-2 max-h-96 overflow-y-auto">
            {actions.map((action) => (
              <div
                key={action.id}
                className={`p-3 rounded border transition-all ${
                  action.status === 'executing'
                    ? 'border-accent/50 bg-accent/10'
                    : action.status === 'success'
                    ? 'border-green-500/30 bg-green-500/5'
                    : action.status === 'failed'
                    ? 'border-red-500/30 bg-red-500/5'
                    : 'border-border/20 bg-card/50'
                }`}
              >
                {/* Action Header */}
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <p className="text-sm font-mono font-bold">
                      {ACTION_TEMPLATES[action.type].icon} {ACTION_TEMPLATES[action.type].name}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">Target: {action.target}</p>
                  </div>
                  <Badge className={`text-xs border ${getStatusColor(action.status)}`}>
                    {formatActionStatus(action.status)}
                  </Badge>
                </div>

                {/* Action Controls */}
                <div className="flex gap-2 mb-2">
                  {action.status === 'pending' && (
                    <Button
                      size="sm"
                      className="text-xs h-7"
                      onClick={() => handleExecuteAction(action)}
                      disabled={executingActionId === action.id}
                    >
                      {executingActionId === action.id ? (
                        <>
                          <Clock className="w-3 h-3 mr-1 animate-spin" />
                          Executing...
                        </>
                      ) : (
                        <>
                          <Play className="w-3 h-3 mr-1" />
                          Execute
                        </>
                      )}
                    </Button>
                  )}

                  {(action.status === 'success' || action.status === 'failed') &&
                    action.rollbackable && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-xs h-7"
                        onClick={() => handleRollbackAction(action)}
                        disabled={executingActionId === action.id}
                      >
                        {executingActionId === action.id ? (
                          <>
                            <Clock className="w-3 h-3 mr-1 animate-spin" />
                            Rolling back...
                          </>
                        ) : (
                          <>
                            <RotateCcw className="w-3 h-3 mr-1" />
                            Rollback
                          </>
                        )}
                      </Button>
                    )}

                  <button
                    onClick={() =>
                      setExpandedActionId(
                        expandedActionId === action.id ? null : action.id
                      )
                    }
                    className="ml-auto text-xs text-muted-foreground hover:text-accent transition-colors"
                  >
                    {expandedActionId === action.id ? 'Hide' : 'Details'}
                  </button>
                </div>

                {/* Error Message */}
                {action.error && (
                  <div className="mb-2 p-2 bg-red-500/10 border border-red-500/20 rounded text-xs text-red-300">
                    <div className="flex gap-2">
                      <XCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                      <span>{action.error}</span>
                    </div>
                  </div>
                )}

                {/* Expanded Audit Log */}
                {expandedActionId === action.id && (
                  <div className="mt-3 pt-3 border-t border-border/20 space-y-2">
                    <p className="text-xs font-mono text-muted-foreground mb-2">AUDIT LOG:</p>
                    {action.auditLog.map((log, idx) => (
                      <div
                        key={idx}
                        className="p-2 bg-background/50 rounded border border-border/10 text-xs"
                      >
                        <div className="flex items-start gap-2">
                          {log.status === 'success' ? (
                            <CheckCircle className="w-3 h-3 text-green-400 flex-shrink-0 mt-0.5" />
                          ) : log.status === 'failed' ? (
                            <XCircle className="w-3 h-3 text-red-400 flex-shrink-0 mt-0.5" />
                          ) : (
                            <Clock className="w-3 h-3 text-yellow-400 flex-shrink-0 mt-0.5" />
                          )}
                          <div className="flex-1">
                            <p className="font-mono text-muted-foreground">
                              {log.timestamp}
                            </p>
                            <p className="text-muted-foreground mt-1">{log.details}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Empty State */}
      {actions.length === 0 && (
        <div className="text-center py-4 text-muted-foreground text-xs">
          <p>No actions queued. Select a recommended action above to begin.</p>
        </div>
      )}
    </div>
  );
}
