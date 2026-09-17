import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

export interface DeviceRow {
  device_id: string;
  account_id: string;
  credential_id: string;
  public_key: string; // base64
  sign_count: number;
  status: "active" | "revoked";
  created_at: string;
}

export interface ChainEventRow {
  seq: number;
  account_id: string;
  device_id: string | null;
  type: string;
  layer_before: string;
  layer_after: string;
  timestamp: string;
  detail: string | null;
  entry_hash: string;
  server_sig: string;
  server_key_id: string;
}

export interface ChallengeRow {
  challenge: string;
  account_id: string;
  purpose: string;
  created_at: number;
  used: number;
}

export interface RotationTicketRow {
  ticket: string;
  account_id: string;
  old_device_id: string;
  created_at: number;
  used: number;
}

export interface AddTicketRow {
  ticket: string;
  account_id: string;
  authorized_by_device_id: string;
  created_at: number;
  used: number;
}

export interface SessionRow {
  token: string;
  account_id: string;
  device_id: string | null;
  created_at: number;
  expires_at: number;
}

export function openDb(path: string): Database.Database {
  mkdirSync(dirname(path), { recursive: true });
  const db = new Database(path);
  db.pragma("journal_mode = WAL");

  db.exec(`
    CREATE TABLE IF NOT EXISTS devices (
      device_id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL,
      credential_id TEXT NOT NULL UNIQUE,
      public_key TEXT NOT NULL,
      sign_count INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS chain_events (
      seq INTEGER NOT NULL,
      account_id TEXT NOT NULL,
      device_id TEXT,
      type TEXT NOT NULL,
      layer_before TEXT NOT NULL,
      layer_after TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      detail TEXT,
      entry_hash TEXT NOT NULL,
      server_sig TEXT NOT NULL,
      server_key_id TEXT NOT NULL,
      PRIMARY KEY (account_id, seq)
    );

    CREATE TABLE IF NOT EXISTS challenges (
      challenge TEXT PRIMARY KEY,
      account_id TEXT NOT NULL,
      purpose TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS rotation_tickets (
      ticket TEXT PRIMARY KEY,
      account_id TEXT NOT NULL,
      old_device_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS add_tickets (
      ticket TEXT PRIMARY KEY,
      account_id TEXT NOT NULL,
      authorized_by_device_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      account_id TEXT NOT NULL,
      device_id TEXT,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );
  `);

  return db;
}
