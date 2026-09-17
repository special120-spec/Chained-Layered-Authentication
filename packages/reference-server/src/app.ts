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

  return app;
}
