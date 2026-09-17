import { Router } from "express";
import type { Database } from "better-sqlite3";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { ChainStore } from "../chainStore.js";
import type { RpConfig } from "../webauthn.js";
import { asyncHandler } from "../asyncHandler.js";
import { isValidId } from "../validate.js";
import {
  getActiveDevices,
  getActiveDeviceByCredentialId,
  toCredential,
  consumeChallenge,
  issueAuthChallenge,
  decodeClientData,
} from "../deviceHelpers.js";

export function authRouter(db: Database, chain: ChainStore, rp: RpConfig): Router {
  const router = Router();

  router.post(
    "/challenge",
    asyncHandler(async (req, res) => {
      const { account_id, purpose } = req.body ?? {};
      if (!isValidId(account_id)) return res.status(400).json({ error: "account_id required" });
      const devices = getActiveDevices(db, account_id);
      if (devices.length === 0) return res.status(404).json({ error: "no active device for this account" });

      const challengePurpose = purpose === "step_up" ? "step_up" : "auth";
      res.json(await issueAuthChallenge(db, rp, account_id, challengePurpose, devices));
    })
  );

  router.post(
    "/verify",
    asyncHandler(async (req, res) => {
      const { account_id, assertionResponse, purpose } = req.body ?? {};
      if (!isValidId(account_id) || !assertionResponse?.response?.clientDataJSON) {
        return res.status(400).json({ error: "account_id and assertionResponse required" });
      }
      const isStepUp = purpose === "step_up";
      const challengePurpose = isStepUp ? "step_up" : "auth";

      // Cooldown gates only same-kind retries once the ladder has actually
      // engaged — step-up/recovery must always be initiable regardless of
      // cooldown (design doc §H/§I; see canInitiateStepUp in @cla/core).
      // This check costs nothing and doesn't touch the chain either way, so
      // it goes before anything else.
      if (!isStepUp) {
        const retryAfter = chain.cooldownRemainingSeconds(account_id);
        if (retryAfter > 0) {
          res.set("Retry-After", String(Math.ceil(retryAfter)));
          return res.status(429).json({
            error: "cooldown_active",
            retry_after_seconds: Math.ceil(retryAfter),
            layer: chain.currentLayer(account_id),
          });
        }
      }

      // From here down, EVERY rejection must be preceded by spending a valid,
      // unexpired, single-use challenge. A chain FAILURE — and therefore any
      // movement up the lock ladder — must never be recordable without one;
      // see SECURITY.md's explicitly in-scope "forcing an account into
      // RECOVERY or a deep lock layer without any valid signature from an
      // enrolled device." Resolving "which device" and checking the
      // signature both come strictly after this, not before it.
      let clientData: { challenge: string };
      try {
        clientData = decodeClientData(assertionResponse.response.clientDataJSON);
      } catch {
        return res.status(400).json({ error: "malformed clientDataJSON" });
      }
      if (!consumeChallenge(db, account_id, challengePurpose, clientData.challenge)) {
        return res.status(400).json({ error: "invalid, expired, or reused challenge" });
      }

      // Only now — with a spent, valid challenge in hand — do we resolve
      // WHICH active device this assertion claims to be from (with multiple
      // devices, the server can no longer assume "the" device) and record a
      // FAILURE if it doesn't match one.
      const credentialId: string | undefined = assertionResponse.id ?? assertionResponse.rawId;
      const device = credentialId ? getActiveDeviceByCredentialId(db, account_id, credentialId) : undefined;

      if (!device) {
        const { receipt } = await chain.recordFailure(account_id, null, "unrecognized_device");
        return res.status(401).json({ error: "authentication failed", receipt, layer: chain.currentLayer(account_id) });
      }

      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: assertionResponse,
          expectedChallenge: clientData.challenge,
          expectedOrigin: rp.origin,
          expectedRPID: rp.rpID,
          credential: toCredential(device),
        });
      } catch {
        verification = { verified: false } as const;
      }

      if (!verification.verified) {
        const { receipt } = await chain.recordFailure(account_id, device.device_id, "bad_signature");
        return res.status(401).json({ error: "authentication failed", receipt, layer: chain.currentLayer(account_id) });
      }

      // Cloned-authenticator check (WebAuthn L2 §6.1.1): if the authenticator
      // has ever reported a nonzero counter, a new value that isn't strictly
      // greater is a signal of a duplicated credential and must be treated
      // as a failure, not silently accepted. Authenticators that always
      // report 0 (many platform authenticators, incl. Windows Hello) are
      // exempt from this check by spec — they never provide this signal.
      if ("authenticationInfo" in verification) {
        const newCounter = verification.authenticationInfo.newCounter;
        const possibleClone = device.sign_count !== 0 && newCounter !== 0 && newCounter <= device.sign_count;
        if (possibleClone) {
          const { receipt } = await chain.recordFailure(account_id, device.device_id, "possible_cloned_authenticator");
          return res.status(401).json({ error: "authentication failed", receipt, layer: chain.currentLayer(account_id) });
        }
        db.prepare(`UPDATE devices SET sign_count = ? WHERE device_id = ?`).run(newCounter, device.device_id);
      }

      const { receipt } = isStepUp
        ? await chain.recordStepUpOk(account_id, device.device_id)
        : await chain.recordSuccess(account_id, device.device_id);

      res.json({ receipt, layer: chain.currentLayer(account_id), device_id: device.device_id });
    })
  );

  return router;
}
