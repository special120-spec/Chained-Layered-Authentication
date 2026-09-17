import { Router } from "express";
import type { Database } from "better-sqlite3";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { ChainStore } from "../chainStore.js";
import type { RpConfig } from "../webauthn.js";
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

  router.post("/challenge", async (req, res) => {
    const { account_id, purpose } = req.body ?? {};
    if (!account_id) return res.status(400).json({ error: "account_id required" });
    const devices = getActiveDevices(db, account_id);
    if (devices.length === 0) return res.status(404).json({ error: "no active device for this account" });

    const challengePurpose = purpose === "step_up" ? "step_up" : "auth";
    res.json(await issueAuthChallenge(db, rp, account_id, challengePurpose, devices));
  });

  router.post("/verify", async (req, res) => {
    const { account_id, assertionResponse, purpose } = req.body ?? {};
    if (!account_id || !assertionResponse) {
      return res.status(400).json({ error: "account_id and assertionResponse required" });
    }
    const isStepUp = purpose === "step_up";
    const challengePurpose = isStepUp ? "step_up" : "auth";

    // Resolve WHICH active device this assertion claims to be from — with
    // multiple devices, the server can no longer assume "the" device.
    const credentialId: string | undefined = assertionResponse.id ?? assertionResponse.rawId;
    const device = credentialId ? getActiveDeviceByCredentialId(db, account_id, credentialId) : undefined;

    if (!device) {
      const { receipt } = await chain.recordFailure(account_id, null, "unrecognized_device");
      return res.status(401).json({ error: "authentication failed", receipt, layer: chain.currentLayer(account_id) });
    }

    const clientData = decodeClientData(assertionResponse.response.clientDataJSON);
    if (!consumeChallenge(db, account_id, challengePurpose, clientData.challenge)) {
      const { receipt } = await chain.recordFailure(account_id, device.device_id, "invalid_or_reused_challenge");
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

    if ("authenticationInfo" in verification) {
      db.prepare(`UPDATE devices SET sign_count = ? WHERE device_id = ?`).run(
        verification.authenticationInfo.newCounter,
        device.device_id
      );
    }

    const { receipt } = isStepUp
      ? await chain.recordStepUpOk(account_id, device.device_id)
      : await chain.recordSuccess(account_id, device.device_id);

    res.json({ receipt, layer: chain.currentLayer(account_id), device_id: device.device_id });
  });

  return router;
}
