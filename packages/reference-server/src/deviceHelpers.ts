import type { Database } from "better-sqlite3";
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import type { RpConfig } from "./webauthn.js";
import type { DeviceRow } from "./db.js";

/**
 * Matches @simplewebauthn/server's WebAuthnCredential shape. Declared
 * locally rather than imported: that type isn't re-exported from the
 * package's public entry point (only from its internal deps module), so
 * pinning our own shape here is more stable across upstream releases.
 */
export interface StoredCredential {
  id: string;
  publicKey: Uint8Array<ArrayBuffer>;
  counter: number;
}

export function getActiveDevice(db: Database, accountId: string): DeviceRow | undefined {
  return db
    .prepare(`SELECT * FROM devices WHERE account_id = ? AND status = 'active'`)
    .get(accountId) as DeviceRow | undefined;
}

export function toCredential(row: DeviceRow): StoredCredential {
  return {
    id: row.credential_id,
    // Uint8Array.from (rather than `new Uint8Array(buffer)`) guarantees a
    // plain ArrayBuffer-backed array, matching @simplewebauthn/server's
    // stricter WebAuthnCredential typing (a Node Buffer's backing store is
    // typed as ArrayBufferLike, which also admits SharedArrayBuffer).
    publicKey: Uint8Array.from(Buffer.from(row.public_key, "base64")),
    counter: row.sign_count,
  };
}

export function recordChallenge(db: Database, accountId: string, purpose: string, challenge: string) {
  db.prepare(
    `INSERT INTO challenges (challenge, account_id, purpose, created_at, used) VALUES (?, ?, ?, ?, 0)`
  ).run(challenge, accountId, purpose, Date.now());
}

/** Consumes a challenge exactly once; rejects unknown, wrong-purpose, reused, or expired (5 min) ones. */
export function consumeChallenge(db: Database, accountId: string, purpose: string, challenge: string): boolean {
  const row = db
    .prepare(`SELECT * FROM challenges WHERE challenge = ? AND account_id = ? AND purpose = ?`)
    .get(challenge, accountId, purpose) as { used: number; created_at: number } | undefined;
  if (!row || row.used || Date.now() - row.created_at > 5 * 60 * 1000) return false;
  db.prepare(`UPDATE challenges SET used = 1 WHERE challenge = ?`).run(challenge);
  return true;
}

export async function issueAuthChallenge(
  db: Database,
  rp: RpConfig,
  accountId: string,
  purpose: string,
  device: DeviceRow
) {
  const options = await generateAuthenticationOptions({
    rpID: rp.rpID,
    allowCredentials: [{ id: device.credential_id }],
    userVerification: "preferred",
  });
  recordChallenge(db, accountId, purpose, options.challenge);
  return options;
}

export function decodeClientData(base64urlJson: string): { challenge: string; [k: string]: unknown } {
  return JSON.parse(Buffer.from(base64urlJson, "base64url").toString("utf8"));
}
