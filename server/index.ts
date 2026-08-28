import cors from 'cors';
import express from 'express';
import { createServer } from 'http';
import securityRouter from './security/routes';
import incidentRouter from './security/incidentRoutes';
import agentRouter from './security/agentRoutes';
import authRouter from './authRoutes';
import { requireAuth } from './auth';
import { db, initializeSecurityDatabase } from './security/db';

const app = express();
const server = createServer(app);
app.disable('x-powered-by');

const allowedOrigins = process.env.FRONTEND_ORIGIN?.split(',').map(v => v.trim()).filter(Boolean);
app.use(cors({ origin: allowedOrigins?.length ? allowedOrigins : true, credentials: true }));
app.use(express.json({ limit: '256kb' }));

app.get('/api/health', async (_req, res) => {
  if (!db) return res.status(503).json({ success: false, service: 'jarvis-api', status: 'database_not_configured' });
  try {
    await db.query('SELECT 1');
    return res.json({ success: true, service: 'jarvis-api', status: 'online', database: 'connected' });
  } catch {
    return res.status(503).json({ success: false, service: 'jarvis-api', status: 'database_unavailable' });
  }
});

app.use('/api/auth', authRouter);
app.use('/api/agent', agentRouter);
app.use('/api/security', requireAuth, securityRouter);
app.use('/api/security', requireAuth, incidentRouter);

const port = Number(process.env.PORT ?? 3001);

async function start() {
  await initializeSecurityDatabase();
  server.listen(port, '0.0.0.0', () => console.log(`J.A.R.V.I.S. API running on port ${port}`));
}

start().catch(error => {
  console.error('[J.A.R.V.I.S.] API startup failed:', error);
  process.exit(1);
});
