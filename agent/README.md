# J.A.R.V.I.S. Endpoint Agent — Phase 11

The endpoint agent is the first bridge between a real computer and the J.A.R.V.I.S. security API.

## What it does now

- Registers a stable endpoint identity.
- Sends a synthetic-safe heartbeat generated from real host metadata.
- Reports hostname, platform, architecture, OS release, uptime, CPU count and memory usage.
- Uses `X-JARVIS-Agent-Key` for machine-to-machine authentication.
- Sends telemetry only to the configured J.A.R.V.I.S. API.
- Does **not** execute commands, scan the network, modify files, or collect private document contents.

## Requirements

- Node.js 20+
- A running J.A.R.V.I.S. API
- A `JARVIS_AGENT_API_KEY` configured on the Render API

## Configuration

PowerShell:

```powershell
$env:JARVIS_API_URL="https://YOUR-JARVIS-API.onrender.com"
$env:JARVIS_AGENT_API_KEY="YOUR_AGENT_KEY"
$env:JARVIS_AGENT_ID="my-windows-pc"
node .\agent\jarvis-agent.mjs
```

macOS/Linux:

```bash
export JARVIS_API_URL="https://YOUR-JARVIS-API.onrender.com"
export JARVIS_AGENT_API_KEY="YOUR_AGENT_KEY"
export JARVIS_AGENT_ID="my-computer"
node ./agent/jarvis-agent.mjs
```

The default heartbeat interval is 60 seconds. For local testing it can be shortened with `JARVIS_AGENT_INTERVAL_MS` (minimum 10 seconds).

## API

### Agent health

`GET /api/agent/health`

Header:

`X-JARVIS-Agent-Key: <agent key>`

### Event ingestion

`POST /api/agent/events`

The agent endpoint accepts only `source: "endpoint"` events and validates the payload with Zod before writing it to PostgreSQL and running the server-side detection engine.

## Security boundary

The agent key is a machine credential. Keep it out of Git, browser environment variables, screenshots and public repositories. For production, each endpoint should eventually receive its own revocable credential rather than sharing one global key.

## Next phase

Phase 12 will add OS-specific collectors, starting with Windows Event Log telemetry, plus endpoint registration/revocation and per-agent credentials. The collector will remain allow-listed and read-only.
