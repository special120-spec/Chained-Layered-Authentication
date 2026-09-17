import type { Database } from "better-sqlite3";
import { randomBytes } from "node:crypto";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { SessionRow } from "./db.js";

/**
 * 30 minutes: long enough to view your own audit log / device list shortly
 * after authenticating without re-proving possession, short enough that a
 * leaked token (e.g. via browser history, a shared machine) has a bounded
 * blast radius. No refresh mechanism in v1 — re-authenticate for a new one.
 */
const SESSION_TTL_MS = 30 * 60 * 1000;

/**
 * Issued after any endpoint that just verified a REAL WebAuthn ceremony
 * completed (register/finish, add/finish, rotate/finish, auth/verify) —
 * this is the `session_token` the spec's endpoint table already mentions
 * but the reference server didn't actually implement (security review
 * H1/H2: without this, there was no way to gate the audit-log/device-list
 * endpoints behind anything other than "knows the account_id").
 */
export function createSession(db: Database, accountId: string, deviceId: string | null): string {
  const token = randomBytes(32).toString("base64url");
  const now = Date.now();
  db.prepare(
    `INSERT INTO sessions (token, account_id, device_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`
  ).run(token, accountId, deviceId, now, now + SESSION_TTL_MS);
  return token;
}

function getSession(db: Database, token: string): SessionRow | null {
  const row = db.prepare(`SELECT * FROM sessions WHERE token = ?`).get(token) as SessionRow | undefined;
  if (!row || Date.now() > row.expires_at) return null;
  return row;
}

/**
 * Server-to-server session introspection (RFC 7662-style `active` shape) —
 * for a RELYING PARTY backend in a different language/process (e.g. a Go
 * platform's own API) that needs to know "is this session_token still
 * valid, and for which account" without re-implementing this reference
 * server's session storage itself. Requires possessing the token to learn
 * anything about it — same trust boundary as using the token directly,
 * just phrased as a lookup instead of an action.
 */
export function introspectSession(
  db: Database,
  token: string
): { accountId: string; deviceId: string | null; expiresAt: number } | null {
  const session = getSession(db, token);
  if (!session) return null;
  return { accountId: session.account_id, deviceId: session.device_id, expiresAt: session.expires_at };
}

function bearerToken(req: Request): string | null {
  const header = req.header("authorization");
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice("Bearer ".length).trim();
  return token.length > 0 ? token : null;
}

/**
 * Gates a route behind a valid, unexpired session belonging to the SAME
 * account the route is about — `resolveTargetAccountId` says how to find
 * that account for a given request (a URL param for `/account/:id/...`, a
 * query string for `/devices?account_id=...`, etc.). A session for account
 * A can never be used to read account B's data even with a valid token.
 */
export function requireSessionForAccount(
  db: Database,
  resolveTargetAccountId: (req: Request) => string | undefined
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = bearerToken(req);
    if (!token) {
      return res.status(401).json({ error: "missing Authorization: Bearer <session_token>" });
    }
    const session = getSession(db, token);
    if (!session) {
      return res.status(401).json({ error: "invalid or expired session" });
    }
    const targetAccountId = resolveTargetAccountId(req);
    if (!targetAccountId || session.account_id !== targetAccountId) {
      // Same response for "no such account" and "wrong account" — a
      // distinguishable error here would let a session holder probe
      // whether some other account_id exists.
      return res.status(403).json({ error: "session does not grant access to this account" });
    }
    next();
  };
}
