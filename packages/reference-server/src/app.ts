import express, { type Express } from "express";
import cors from "cors";
import type { Database } from "better-sqlite3";
import type { KeyObject } from "node:crypto";
import { ChainStore } from "./chainStore.js";
import { loadRpConfig } from "./webauthn.js";
import { devicesRouter } from "./routes/devices.js";
import { authRouter } from "./routes/auth.js";
import { accountRouter } from "./routes/account.js";
import { totpRouter } from "./routes/totp.js";
import { createRateLimiter, byIp } from "./rateLimit.js";

export function createApp(
  db: Database,
  serverPrivateKey: KeyObject,
  serverKeyId: string,
  totpEncryptionKey: Buffer
): Express {
  const app = express();
  app.use(cors({ origin: process.env.CLA_ORIGIN ?? "http://localhost:5173" }));
  app.use(express.json());

  // Blunt, general-purpose defense against raw request flooding (security
  // review H3) — every endpoint-specific limiter below is layered on top
  // of this, not instead of it. 120 req/min/IP is generous for normal use
  // (register/auth/rotate ceremonies each take a few round trips) while
  // still bounding a single source's total request volume.
  //
  // Overridable via CLA_RATE_LIMIT_IP_MAX: an integration test suite that
  // exercises many endpoints from a single client IP (127.0.0.1) should
  // raise this rather than share a production-sized budget across every
  // test in the file — this general limiter is a coarse backstop, not
  // itself the thing most tests are exercising (the per-account limiters
  // in auth.ts/account.ts, and rateLimit.test.ts's direct unit tests, are).
  const ipLimiterMax = Number(process.env.CLA_RATE_LIMIT_IP_MAX ?? 120);
  app.use("/v1", createRateLimiter({ windowMs: 60_000, max: ipLimiterMax, keyFn: byIp, code: "rate_limited" }));

  const chain = new ChainStore(db, serverPrivateKey, serverKeyId);
  const rp = loadRpConfig();

  app.get("/healthz", (_req, res) => res.json({ ok: true }));
  app.use("/v1/devices", devicesRouter(db, chain, rp));
  app.use("/v1/auth", authRouter(db, chain, rp));
  app.use("/v1/account", accountRouter(db, chain, totpEncryptionKey));
  app.use("/v1/totp", totpRouter(db, chain, rp, totpEncryptionKey));

  // Final safety net (security review M3): every route is wrapped in
  // asyncHandler so rejections reach here instead of crashing the process,
  // and any synchronous throw (a malformed body reaching better-sqlite3,
  // say) lands here too via Express's own handling. Never leaks internals.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error("[cla] unhandled route error:", err);
    if (res.headersSent) return;
    res.status(500).json({ error: "internal_error" });
  });

  return app;
}
