import { Router } from "express";
import type { Database } from "better-sqlite3";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { generateTotpSecret, base32Encode, buildProvisioningUri, verifyTotp } from "@cla/core";
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
import { decryptTotpSecret } from "../totpCrypto.js";
import { createPendingTotp, getPendingTotp, activatePendingTotp, disableTotp, verifyAndConsumeTotpCode } from "../totpStore.js";

/**
 * TOTP (authenticator-app codes) as an OPT-IN alternate proof of
 * possession — never a replacement for the WebAuthn device that's still
 * required to enroll or disable it, and never usable for ordinary/"purpose:
 * auth" requests (see /verify below). Two roles: (1) a self-service way to
 * complete STEP_UP when a second device isn't available, and (2) an
 * optional gate on /v1/account/recovery/start, which is otherwise the one
 * endpoint in the whole API that accepts no proof at all by design (see
 * docs/security-findings-2026-09-17.md, H3).
 */
export function totpRouter(db: Database, chain: ChainStore, rp: RpConfig, totpKey: Buffer): Router {
  const router = Router();

  // ---- Enroll: same bar as adding a device — proves possession of an
  // EXISTING active device first, then confirms the user actually
  // programmed their authenticator app before the secret becomes active. ----

  router.post(
    "/enroll/challenge",
    asyncHandler(async (req, res) => {
      const { account_id } = req.body ?? {};
      if (!isValidId(account_id)) return res.status(400).json({ error: "account_id required" });
      const devices = getActiveDevices(db, account_id);
      if (devices.length === 0) return res.status(404).json({ error: "no active device; enroll a device first" });
      res.json(await issueAuthChallenge(db, rp, account_id, "totp-enroll-auth", devices));
    })
  );

  router.post(
    "/enroll/start",
    asyncHandler(async (req, res) => {
      const { account_id, assertionResponse } = req.body ?? {};
      if (!isValidId(account_id) || !assertionResponse?.response?.clientDataJSON) {
        return res.status(400).json({ error: "account_id and assertionResponse required" });
      }

      // Same ordering discipline as devices.ts's /add/start: resolving the
      // device before the challenge is safe here specifically because
      // NOTHING is written to the chain on any failure path below — only a
      // fully-verified success reaches chain.recordTotpEnrolled.
      const credentialId: string | undefined = assertionResponse.id ?? assertionResponse.rawId;
      const authorizer = credentialId ? getActiveDeviceByCredentialId(db, account_id, credentialId) : undefined;
      if (!authorizer) return res.status(401).json({ error: "no recognized device signed this request" });

      const clientData = decodeClientData(assertionResponse.response.clientDataJSON);
      if (!consumeChallenge(db, account_id, "totp-enroll-auth", clientData.challenge)) {
        return res.status(400).json({ error: "invalid, expired, or reused challenge" });
      }
      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: assertionResponse,
          expectedChallenge: clientData.challenge,
          expectedOrigin: rp.origin,
          expectedRPID: rp.rpID,
          credential: toCredential(authorizer),
        });
      } catch (err) {
        return res.status(400).json({ error: `totp-enroll auth failed: ${(err as Error).message}` });
      }
      if (!verification.verified) {
        return res.status(400).json({ error: "possession of an existing device not proven" });
      }

      const secret = generateTotpSecret();
      const enrollTicket = createPendingTotp(db, totpKey, account_id, authorizer.device_id, secret);
      res.json({
        enroll_ticket: enrollTicket,
        secret_base32: base32Encode(secret), // manual-entry fallback if the user can't scan a QR code
        provisioning_uri: buildProvisioningUri({ secret, accountLabel: account_id, issuer: rp.rpName }),
        digits: 6,
        period: 30,
      });
    })
  );

  router.post(
    "/enroll/finish",
    asyncHandler(async (req, res) => {
      const { account_id, enroll_ticket, code } = req.body ?? {};
      if (!isValidId(account_id) || !isValidId(enroll_ticket) || typeof code !== "string" || code.length === 0) {
        return res.status(400).json({ error: "account_id, enroll_ticket, and code required" });
      }
      const pending = getPendingTotp(db, enroll_ticket, account_id);
      if (!pending) return res.status(400).json({ error: "invalid, expired, or already-used enroll ticket" });

      const secret = decryptTotpSecret(pending.encrypted_secret, totpKey);
      const matchedStep = await verifyTotp(secret, code, Date.now(), { window: 1 });
      if (matchedStep === null) {
        // Deliberately does NOT consume the ticket or touch the chain: this
        // is the user confirming setup, not a possession-proof attempt — a
        // mistyped code during onboarding shouldn't cost anything.
        return res
          .status(400)
          .json({ error: "code did not match — check your authenticator app's time sync and try again" });
      }

      activatePendingTotp(db, pending, matchedStep);
      const { receipt } = await chain.recordTotpEnrolled(account_id, pending.authorized_by_device_id);
      res.json({ receipt, layer: chain.currentLayer(account_id) });
    })
  );

  // ---- Verify: an alternate way to complete a STEP_UP ceremony once
  // enrolled. Per design doc §H/§I, a valid higher-assurance proof must
  // always be initiable regardless of cooldown — same rule /v1/auth/verify
  // applies to a WebAuthn step-up — so this deliberately never checks
  // chain.cooldownRemainingSeconds. A wrong code still counts as a FAILURE
  // against the SAME ladder/cooldown a wrong WebAuthn signature would. ----

  router.post(
    "/verify",
    asyncHandler(async (req, res) => {
      const { account_id, code, purpose } = req.body ?? {};
      if (!isValidId(account_id) || typeof code !== "string" || code.length === 0) {
        return res.status(400).json({ error: "account_id and code required" });
      }
      if (purpose !== "step_up") {
        return res.status(400).json({ error: "TOTP may only complete a step_up; it is never a primary auth method" });
      }

      const outcome = await verifyAndConsumeTotpCode(db, totpKey, account_id, code, Date.now());
      if (outcome === "not_enrolled") {
        return res.status(404).json({ error: "TOTP is not enrolled for this account" });
      }
      if (outcome === "bad_code") {
        const { receipt } = await chain.recordFailure(account_id, null, "totp_bad_code", { method: "totp" });
        return res.status(401).json({ error: "code did not match", receipt, layer: chain.currentLayer(account_id) });
      }

      const { receipt } = await chain.recordStepUpOk(account_id, null, { method: "totp" });
      res.json({ receipt, layer: chain.currentLayer(account_id) });
    })
  );

  // ---- Disable: requires proving possession of an existing active
  // device, same bar as enrolling. ----

  router.post(
    "/disable/challenge",
    asyncHandler(async (req, res) => {
      const { account_id } = req.body ?? {};
      if (!isValidId(account_id)) return res.status(400).json({ error: "account_id required" });
      const devices = getActiveDevices(db, account_id);
      if (devices.length === 0) return res.status(404).json({ error: "no active device" });
      res.json(await issueAuthChallenge(db, rp, account_id, "totp-disable", devices));
    })
  );

  router.post(
    "/disable",
    asyncHandler(async (req, res) => {
      const { account_id, assertionResponse } = req.body ?? {};
      if (!isValidId(account_id) || !assertionResponse?.response?.clientDataJSON) {
        return res.status(400).json({ error: "account_id and assertionResponse required" });
      }

      const credentialId: string | undefined = assertionResponse.id ?? assertionResponse.rawId;
      const signer = credentialId ? getActiveDeviceByCredentialId(db, account_id, credentialId) : undefined;
      if (!signer) return res.status(401).json({ error: "no recognized device signed this request" });

      const clientData = decodeClientData(assertionResponse.response.clientDataJSON);
      if (!consumeChallenge(db, account_id, "totp-disable", clientData.challenge)) {
        return res.status(400).json({ error: "invalid, expired, or reused challenge" });
      }
      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: assertionResponse,
          expectedChallenge: clientData.challenge,
          expectedOrigin: rp.origin,
          expectedRPID: rp.rpID,
          credential: toCredential(signer),
        });
      } catch (err) {
        return res.status(400).json({ error: `totp-disable auth failed: ${(err as Error).message}` });
      }
      if (!verification.verified) return res.status(400).json({ error: "possession not proven" });

      const removed = disableTotp(db, account_id);
      if (!removed) return res.status(404).json({ error: "TOTP was not enrolled" });

      const { receipt } = await chain.recordTotpDisabled(account_id, signer.device_id);
      res.json({ receipt, layer: chain.currentLayer(account_id) });
    })
  );

  return router;
}
