#!/usr/bin/env node

import os from 'node:os';
import crypto from 'node:crypto';

const API_URL = (process.env.JARVIS_API_URL ?? '').replace(/\/$/, '');
const API_KEY = process.env.JARVIS_AGENT_API_KEY ?? '';
const INTERVAL_MS = Number(process.env.JARVIS_AGENT_INTERVAL_MS ?? 60_000);

if (!API_URL || !API_KEY) {
  console.error('J.A.R.V.I.S. agent requires JARVIS_API_URL and JARVIS_AGENT_API_KEY.');
  process.exit(1);
}

const hostname = os.hostname();
const agentId = process.env.JARVIS_AGENT_ID ?? `${hostname}-${crypto.randomUUID().slice(0, 8)}`;

function makeId() {
  return `endpoint-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
}

async function sendEvent(event) {
  const response = await fetch(`${API_URL}/api/agent/events`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-JARVIS-Agent-Key': API_KEY,
    },
    body: JSON.stringify(event),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`API returned ${response.status}${text ? `: ${text.slice(0, 300)}` : ''}`);
  }

  return response.json();
}

function buildHeartbeat() {
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  const memoryUsedPercent = Math.round(((totalMemory - freeMemory) / totalMemory) * 100);

  return {
    id: makeId(),
    timestamp: new Date().toISOString(),
    type: 'system',
    source: 'endpoint',
    sourceSystem: 'jarvis-endpoint-agent',
    title: 'Endpoint heartbeat',
    description: `Endpoint ${hostname} is reporting telemetry to J.A.R.V.I.S.`,
    severity: 'info',
    hostname,
    metadata: {
      agentId,
      platform: process.platform,
      architecture: process.arch,
      osRelease: os.release(),
      uptimeSeconds: Math.round(os.uptime()),
      cpuCount: os.cpus().length,
      memoryUsedPercent,
      totalMemoryBytes: totalMemory,
      freeMemoryBytes: freeMemory,
      loadAverage: os.loadavg(),
    },
  };
}

async function tick() {
  try {
    const result = await sendEvent(buildHeartbeat());
    const detections = result?.data?.detections?.length ?? 0;
    console.log(`[J.A.R.V.I.S.] heartbeat accepted for ${hostname}; detections=${detections}`);
  } catch (error) {
    console.error(`[J.A.R.V.I.S.] telemetry failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

console.log(`[J.A.R.V.I.S.] endpoint agent started: ${agentId}`);
console.log(`[J.A.R.V.I.S.] host=${hostname} platform=${process.platform}`);

await tick();
setInterval(tick, Math.max(10_000, INTERVAL_MS));
