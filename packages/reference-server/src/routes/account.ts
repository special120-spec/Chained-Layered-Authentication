import { Router } from "express";
import type { Database } from "better-sqlite3";
import type { ChainStore } from "../chainStore.js";
import { safeEqual } from "../safeCompare.js";
import { asyncHandler } from "../asyncHandler.js";
import { isValidId } from "../validate.js";
import { createRateLimiter, byAccountId, byIp } from "../rateLimit.js";

export function accountRouter(db: Database, chain: ChainStore): Router {
  const router = Router();

  /**
   * User-initiated: "I lost every device." Deliberately requires no
   * signature — that's structurally unavoidable for the one path that has
   * to work when every enrolled key is gone (design doc §I). This is why
   * it's the most socially-attackable part of the whole system, not a bug
   * in this endpoint specifically.
   *
   * Security review H3: since no signature can gate this endpoint by
   * design, a tight per-account rate limit is the only thing standing
   * between "structurally necessary" and "anyone who knows account_id can
   * force RECOVERY on demand, repeatedly, forever." 3/hour is generous for
   * a genuinely locked-out owner, punishing for an attacker automating it.
   */
  router.post(
    "/recovery/start",
    createRateLimiter({ windowMs: 60 * 60_000, max: 3, keyFn: byAccountId, code: "rate_limited" }),
    asyncHandler(async (req, res) => {
      const { account_id } = req.body ?? {};
      if (!isValidId(account_id)) return res.status(400).json({ error: "account_id required" });
      const { receipt } = await chain.recordRecoveryStart(account_id);
      res.json({
        receipt,
        layer: chain.currentLayer(account_id),
        note: "Recovery requested. In v1 this requires human-mediated identity verification before it completes — see SECURITY.md.",
      });
    })
  );

  /**
   * Placeholder for a real support-mediated flow: a shared admin token
   * stands in for "a support agent verified this person's identity
   * out-of-band." Revokes every existing device — if recovery was
   * triggered by device loss/theft, a device that resurfaces afterward
   * must not still work.
   *
   * Rate-limited both per-account and per-IP: M1's constant-time compare
   * stops timing attacks on a single guess, this bounds guess *volume*
   * regardless of which axis an attacker tries to spread attempts across.
   */
  router.post(
    "/recovery/complete",
    createRateLimiter({ windowMs: 60 * 60_000, max: 10, keyFn: byAccountId, code: "rate_limited" }),
    createRateLimiter({ windowMs: 60 * 60_000, max: 10, keyFn: byIp, code: "rate_limited" }),
    asyncHandler(async (req, res) => {
      const { account_id, admin_token } = req.body ?? {};
      if (!isValidId(account_id) || typeof admin_token !== "string" || admin_token.length === 0) {
        return res.status(400).json({ error: "account_id and admin_token required" });
      }
      const expected = process.env.CLA_ADMIN_TOKEN;
      if (!expected || !safeEqual(admin_token, expected)) {
        return res.status(403).json({ error: "invalid admin token" });
      }
      db.prepare(`UPDATE devices SET status = 'revoked' WHERE account_id = ? AND status = 'active'`).run(account_id);
      const { receipt } = await chain.recordRecoveryComplete(account_id);
      res.json({ receipt, layer: chain.currentLayer(account_id) });
    })
  );

  router.get(
    "/:id/audit-log",
    asyncHandler(async (req, res) => {
      const accountId = req.params.id;
      if (!isValidId(accountId)) return res.status(400).json({ error: "account id required" });
      res.json({
        events: chain.getEvents(accountId),
        receipts: chain.getReceipts(accountId),
        layer: chain.currentLayer(accountId),
      });
    })
  );

  return router;
}
