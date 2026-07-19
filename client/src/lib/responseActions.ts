/**
 * Response Action System
 * Manages automated response actions with execution tracking and audit logging
 */

export type ActionType = 'block-ip' | 'isolate-host' | 'kill-process' | 'revoke-credentials' | 'quarantine-file' | 'disable-account';
export type ActionStatus = 'pending' | 'executing' | 'success' | 'failed' | 'rolled-back';

export interface ResponseAction {
  id: string;
  type: ActionType;
  target: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: ActionStatus;
  executedAt?: string;
  completedAt?: string;
  executedBy: string;
  auditLog: AuditLogEntry[];
  rollbackable: boolean;
  rollbackId?: string;
  error?: string;
}

export interface AuditLogEntry {
  timestamp: string;
  action: string;
  status: ActionStatus;
  details: string;
  userId: string;
}

export interface ActionTemplate {
  type: ActionType;
  name: string;
  description: string;
  icon: string;
  riskLevel: 'low' | 'medium' | 'high';
  requiresConfirmation: boolean;
  estimatedDuration: number; // in seconds
}

/**
 * Available response action templates
 */
export const ACTION_TEMPLATES: Record<ActionType, ActionTemplate> = {
  'block-ip': {
    type: 'block-ip',
    name: 'Block IP Address',
    description: 'Add IP to firewall blocklist and revoke existing connections',
    icon: '🚫',
    riskLevel: 'medium',
    requiresConfirmation: true,
    estimatedDuration: 5,
  },
  'isolate-host': {
    type: 'isolate-host',
    name: 'Isolate Host',
    description: 'Disconnect host from network and enable network isolation',
    icon: '🔒',
    riskLevel: 'high',
    requiresConfirmation: true,
    estimatedDuration: 10,
  },
  'kill-process': {
    type: 'kill-process',
    name: 'Terminate Process',
    description: 'Kill suspicious process and prevent restart',
    icon: '⚔️',
    riskLevel: 'medium',
    requiresConfirmation: true,
    estimatedDuration: 3,
  },
  'revoke-credentials': {
    type: 'revoke-credentials',
    name: 'Revoke Credentials',
    description: 'Revoke compromised user credentials and force re-authentication',
    icon: '🔑',
    riskLevel: 'high',
    requiresConfirmation: true,
    estimatedDuration: 8,
  },
  'quarantine-file': {
    type: 'quarantine-file',
    name: 'Quarantine File',
    description: 'Move suspicious file to quarantine and prevent execution',
    icon: '⛔',
    riskLevel: 'low',
    requiresConfirmation: false,
    estimatedDuration: 2,
  },
  'disable-account': {
    type: 'disable-account',
    name: 'Disable Account',
    description: 'Disable user account and revoke all active sessions',
    icon: '🚷',
    riskLevel: 'high',
    requiresConfirmation: true,
    estimatedDuration: 5,
  },
};

/**
 * Create a new response action
 */
export function createResponseAction(
  type: ActionType,
  target: string,
  severity: 'critical' | 'high' | 'medium' | 'low' = 'high'
): ResponseAction {
  const now = new Date().toISOString();
  return {
    id: `action-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    type,
    target,
    description: ACTION_TEMPLATES[type].description,
    severity,
    status: 'pending',
    executedBy: 'Security Team',
    auditLog: [
      {
        timestamp: now,
        action: 'Action Created',
        status: 'pending',
        details: `Response action created: ${ACTION_TEMPLATES[type].name} on ${target}`,
        userId: 'system',
      },
    ],
    rollbackable: true,
  };
}

/**
 * Execute a response action with simulated delay
 */
export async function executeAction(
  action: ResponseAction,
  onStatusChange: (status: ActionStatus, details: string) => void
): Promise<ResponseAction> {
  const updatedAction = { ...action };
  const startTime = new Date().toISOString();

  // Mark as executing
  updatedAction.status = 'executing';
  updatedAction.executedAt = startTime;
  onStatusChange('executing', `Executing ${ACTION_TEMPLATES[action.type].name}...`);

  // Add audit log entry
  updatedAction.auditLog.push({
    timestamp: new Date().toISOString(),
    action: 'Execution Started',
    status: 'executing',
    details: `Started execution of ${ACTION_TEMPLATES[action.type].name} on target: ${action.target}`,
    userId: 'system',
  });

  // Simulate execution with random success/failure
  const duration = ACTION_TEMPLATES[action.type].estimatedDuration * 1000;
  await new Promise((resolve) => setTimeout(resolve, duration));

  // 85% success rate for demo
  const success = Math.random() < 0.85;

  if (success) {
    updatedAction.status = 'success';
    updatedAction.completedAt = new Date().toISOString();
    onStatusChange('success', `Successfully executed ${ACTION_TEMPLATES[action.type].name}`);

    updatedAction.auditLog.push({
      timestamp: new Date().toISOString(),
      action: 'Execution Completed',
      status: 'success',
      details: `Successfully completed ${ACTION_TEMPLATES[action.type].name} on ${action.target}`,
      userId: 'system',
    });
  } else {
    updatedAction.status = 'failed';
    updatedAction.error = `Failed to execute ${ACTION_TEMPLATES[action.type].name}. Network timeout or permission denied.`;
    onStatusChange('failed', updatedAction.error);

    updatedAction.auditLog.push({
      timestamp: new Date().toISOString(),
      action: 'Execution Failed',
      status: 'failed',
      details: updatedAction.error,
      userId: 'system',
    });
  }

  return updatedAction;
}

/**
 * Rollback a response action
 */
export async function rollbackAction(
  action: ResponseAction,
  onStatusChange: (status: ActionStatus, details: string) => void
): Promise<ResponseAction> {
  if (!action.rollbackable || action.status === 'pending') {
    throw new Error('Action cannot be rolled back');
  }

  const updatedAction = { ...action };
  onStatusChange('executing', `Rolling back ${ACTION_TEMPLATES[action.type].name}...`);

  // Simulate rollback
  await new Promise((resolve) => setTimeout(resolve, 3000));

  updatedAction.status = 'rolled-back';
  updatedAction.rollbackId = `rollback-${Date.now()}`;

  updatedAction.auditLog.push({
    timestamp: new Date().toISOString(),
    action: 'Action Rolled Back',
    status: 'rolled-back',
    details: `Rolled back ${ACTION_TEMPLATES[action.type].name} on ${action.target}`,
    userId: 'system',
  });

  onStatusChange('rolled-back', `Rolled back ${ACTION_TEMPLATES[action.type].name}`);

  return updatedAction;
}

/**
 * Get recommended actions for an incident
 */
export function getRecommendedActions(
  incidentType: string,
  severity: 'critical' | 'high' | 'medium' | 'low'
): ActionType[] {
  const recommendations: Record<string, ActionType[]> = {
    'SSH Brute Force Attack': ['block-ip', 'revoke-credentials'],
    'PowerShell-based Lateral Movement': ['kill-process', 'isolate-host'],
    'Data Exfiltration Campaign': ['block-ip', 'isolate-host', 'revoke-credentials'],
    'Privilege Escalation Chain': ['kill-process', 'disable-account'],
    'Malware Infection Chain': ['quarantine-file', 'isolate-host', 'kill-process'],
  };

  const baseActions = recommendations[incidentType] || ['block-ip'];

  // Add more aggressive actions for critical severity
  if (severity === 'critical') {
    if (!baseActions.includes('isolate-host')) {
      baseActions.push('isolate-host');
    }
  }

  return baseActions;
}

/**
 * Format action status for display
 */
export function formatActionStatus(status: ActionStatus): string {
  const statusMap: Record<ActionStatus, string> = {
    pending: '⏳ Pending',
    executing: '⚙️ Executing',
    success: '✅ Success',
    failed: '❌ Failed',
    'rolled-back': '↩️ Rolled Back',
  };
  return statusMap[status];
}

/**
 * Get status color for UI
 */
export function getStatusColor(status: ActionStatus): string {
  const colorMap: Record<ActionStatus, string> = {
    pending: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
    executing: 'bg-blue-500/20 text-blue-300 border-blue-500/30 animate-pulse',
    success: 'bg-green-500/20 text-green-300 border-green-500/30',
    failed: 'bg-red-500/20 text-red-300 border-red-500/30',
    'rolled-back': 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  };
  return colorMap[status];
}
