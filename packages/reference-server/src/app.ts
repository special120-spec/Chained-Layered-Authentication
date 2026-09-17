import express, { type Express } from "express";
import cors from "cors";
import type { Database } from "better-sqlite3";
import type { KeyObject } from "node:crypto";
import { ChainStore } from "./chainStore.js";
import { loadRpConfig } from "./webauthn.js";
import { devicesRouter } from "./routes/devices.js";
import { authRouter } from "./routes/auth.js";
import { accountRouter } from "./routes/account.js";

export function createApp(db: Database, serverPrivateKey: KeyObject, serverKeyId: string): Express {
  const app = express();
  app.use(cors({ origin: process.env.CLA_ORIGIN ?? "http://localhost:5173" }));
  app.use(express.json());

  const chain = new ChainStore(db, serverPrivateKey, serverKeyId);
  const rp = loadRpConfig();

  app.get("/healthz", (_req, res) => res.json({ ok: true }));
  app.use("/v1/devices", devicesRouter(db, chain, rp));
  app.use("/v1/auth", authRouter(db, chain, rp));
  app.use("/v1/account", accountRouter(db, chain));

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
