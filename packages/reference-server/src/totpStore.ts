import type { Database } from "better-sqlite3";
import { randomBytes } from "node:crypto";
import { verifyTotp } from "@cla/core";
import { encryptTotpSecret, decryptTotpSecret } from "./totpCrypto.js";
import type { TotpEnrollTicketRow, TotpSecretRow } from "./db.js";

const ENROLL_TICKET_TTL_MS = 5 * 60 * 1000; // matches add_tickets/rotation_tickets

/** Starts enrollment: stores the new secret PENDING (encrypted), tied to a short-lived ticket. Not active until enroll/finish confirms it. */
export function createPendingTotp(
  db: Database,
  key: Buffer,
  accountId: string,
  authorizedByDeviceId: string,
  secret: Uint8Array
): string {
  const ticket = randomBytes(24).toString("base64url");
  db.prepare(
    `INSERT INTO totp_enroll_tickets (ticket, account_id, encrypted_secret, authorized_by_device_id, created_at, used)
     VALUES (?, ?, ?, ?, ?, 0)`
  ).run(ticket, accountId, encryptTotpSecret(secret, key), authorizedByDeviceId, Date.now());
  return ticket;
}

/** Resolves a pending enrollment ticket; rejects unknown, wrong-account, reused, or expired (5 min) ones — same shape as consumeChallenge. */
export function getPendingTotp(db: Database, ticket: string, accountId: string): TotpEnrollTicketRow | undefined {
  const row = db
    .prepare(`SELECT * FROM totp_enroll_tickets WHERE ticket = ? AND account_id = ?`)
    .get(ticket, accountId) as TotpEnrollTicketRow | undefined;
  if (!row || row.used || Date.now() - row.created_at > ENROLL_TICKET_TTL_MS) return undefined;
  return row;
}

/**
 * Confirms a pending secret as the account's active one. `matchedStep` (the
 * step the user's confirmation code matched) seeds `last_consumed_step` so
 * that exact same code can't immediately be replayed as if it were a fresh
 * step-up proof. Overwrites any prior active secret for the account — an
 * account has at most one active TOTP secret at a time.
 */
export function activatePendingTotp(db: Database, pending: TotpEnrollTicketRow, matchedStep: number): void {
  db.prepare(`UPDATE totp_enroll_tickets SET used = 1 WHERE ticket = ?`).run(pending.ticket);
  db.prepare(
    `INSERT INTO totp_secrets (account_id, encrypted_secret, last_consumed_step, created_at)
     VALUES (@account_id, @encrypted_secret, @matched_step, @created_at)
     ON CONFLICT(account_id) DO UPDATE SET
       encrypted_secret = excluded.encrypted_secret,
       last_consumed_step = excluded.last_consumed_step,
       created_at = excluded.created_at`
  ).run({
    account_id: pending.account_id,
    encrypted_secret: pending.encrypted_secret,
    matched_step: matchedStep,
    created_at: new Date().toISOString(),
  });
}

export function getActiveTotp(db: Database, accountId: string): TotpSecretRow | undefined {
  return db.prepare(`SELECT * FROM totp_secrets WHERE account_id = ?`).get(accountId) as TotpSecretRow | undefined;
}

export type TotpVerifyOutcome = "ok" | "not_enrolled" | "bad_code";

/**
 * Checks `code` against the account's active secret AND enforces replay
 * protection: a step at or before `last_consumed_step` is rejected even if
 * it's numerically the right code for that step (see core/totp.ts's doc
 * comment — this bookkeeping is exactly what that module says it doesn't
 * do itself). On success, atomically advances the high-water mark.
 */
export async function verifyAndConsumeTotpCode(
  db: Database,
  key: Buffer,
  accountId: string,
  code: string,
  forTimeMs: number
): Promise<TotpVerifyOutcome> {
  const row = getActiveTotp(db, accountId);
  if (!row) return "not_enrolled";

  const secret = decryptTotpSecret(row.encrypted_secret, key);
  const matchedStep = await verifyTotp(secret, code, forTimeMs, { window: 1 });
  if (matchedStep === null || matchedStep <= row.last_consumed_step) return "bad_code";

  // Only advance if still the same secret we checked against — a
  // vanishingly unlikely but cheap-to-guard race if enrollment/disable ran
  // concurrently with this verification.
  const result = db
    .prepare(
      `UPDATE totp_secrets SET last_consumed_step = ?
       WHERE account_id = ? AND encrypted_secret = ? AND last_consumed_step < ?`
    )
    .run(matchedStep, accountId, row.encrypted_secret, matchedStep);
  return result.changes > 0 ? "ok" : "bad_code";
}

/** Removes TOTP from an account entirely. Returns whether it was actually enrolled. */
export function disableTotp(db: Database, accountId: string): boolean {
  const result = db.prepare(`DELETE FROM totp_secrets WHERE account_id = ?`).run(accountId);
  return result.changes > 0;
}
