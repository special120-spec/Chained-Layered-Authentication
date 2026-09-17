import { Router } from "express";
import type { Database } from "better-sqlite3";
import { asyncHandler } from "../asyncHandler.js";
import { isValidId } from "../validate.js";
import { introspectSession } from "../sessions.js";

/**
 * For a relying-party BACKEND in a different process/language (e.g. a Go
 * platform's own API server) that can't share this reference server's
 * SQLite-backed session store directly. Meant to be called server-to-
 * server, not from a browser — there's nothing here a browser needs that
 * `requireSessionForAccount`-gated endpoints don't already provide.
 *
 * Deliberately unauthenticated beyond "you already hold the token": same
 * trust boundary as using the token directly against any session-gated
 * endpoint, and the general per-IP rate limiter in app.ts already bounds
 * brute-force attempts against 256-bit random tokens.
 */
export function sessionRouter(db: Database): Router {
  const router = Router();

  router.post(
    "/introspect",
    asyncHandler(async (req, res) => {
      const { session_token } = req.body ?? {};
      if (!isValidId(session_token)) {
        return res.status(400).json({ error: "session_token required" });
      }
      const session = introspectSession(db, session_token);
      if (!session) {
        return res.json({ active: false });
      }
      res.json({
        active: true,
        account_id: session.accountId,
        device_id: session.deviceId,
        expires_at: session.expiresAt,
      });
    })
  );

  return router;
}
