import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import type { Request, Response, NextFunction } from 'express';
import { requireDb } from './security/db';

const scrypt = promisify(scryptCallback);
const SESSION_COOKIE = 'jarvis_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;

export interface AuthUser { id: string; email: string; name: string; role: string; }

function hashSession(token: string) { return createHash('sha256').update(token).digest('hex'); }

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex');
  const derived = (await scrypt(password, salt, 64)) as Buffer;
  return `scrypt:${salt}:${derived.toString('hex')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [, salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const derived = (await scrypt(password, salt, 64)) as Buffer;
  const expected = Buffer.from(hash, 'hex');
  return expected.length === derived.length && timingSafeEqual(expected, derived);
}

export async function createSession(userId: string): Promise<string> {
  const token = randomBytes(32).toString('base64url');
  const db = requireDb();
  await db.query('INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES ($1,$2,NOW()+INTERVAL \'7 days\')', [hashSession(token), userId]);
  return token;
}

export async function destroySession(token: string | undefined) {
  if (!token) return;
  await requireDb().query('DELETE FROM auth_sessions WHERE token_hash=$1', [hashSession(token)]);
}

export async function getAuthUser(token: string | undefined): Promise<AuthUser | null> {
  if (!token) return null;
  const result = await requireDb().query(
    `SELECT u.id, u.email, u.name, u.role FROM auth_sessions s JOIN auth_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW()`,
    [hashSession(token)]
  );
  return result.rows[0] ?? null;
}

export function setSessionCookie(res: Response, token: string) {
  res.cookie(SESSION_COOKIE, token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: SESSION_TTL_MS, path: '/' });
}

export function clearSessionCookie(res: Response) {
  res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' });
}

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  try {
    const user = await getAuthUser(req.cookies?.[SESSION_COOKIE]);
    if (!user) return res.status(401).json({ success: false, error: 'Authentication required' });
    res.locals.user = user;
    next();
  } catch (error) { next(error); }
}

export const sessionCookieName = SESSION_COOKIE;
