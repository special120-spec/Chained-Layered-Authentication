import { Router } from "express";
import type { Database } from "better-sqlite3";
import { randomUUID, randomBytes } from "node:crypto";
import { generateRegistrationOptions, verifyRegistrationResponse, verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { ChainStore } from "../chainStore.js";
import type { RpConfig } from "../webauthn.js";
import {
  getActiveDevice,
  toCredential,
  recordChallenge,
  consumeChallenge,
  issueAuthChallenge,
  decodeClientData,
} from "../deviceHelpers.js";

export function devicesRouter(db: Database, chain: ChainStore, rp: RpConfig): Router {
  const router = Router();

  router.post("/register/start", async (req, res) => {
    const { account_id } = req.body ?? {};
    if (!account_id) return res.status(400).json({ error: "account_id required" });

    if (getActiveDevice(db, account_id)) {
      return res.status(409).json({ error: "account already has an active device; use /devices/rotate/start" });
    }

    const options = await generateRegistrationOptions({
      rpName: rp.rpName,
      rpID: rp.rpID,
      userName: account_id,
      userID: new TextEncoder().encode(account_id),
      attestationType: "none",
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
    });
    recordChallenge(db, account_id, "register", options.challenge);
    res.json(options);
  });

  router.post("/register/finish", async (req, res) => {
    const { account_id, attestationResponse } = req.body ?? {};
    if (!account_id || !attestationResponse) {
      return res.status(400).json({ error: "account_id and attestationResponse required" });
    }

    const clientData = decodeClientData(attestationResponse.response.clientDataJSON);
    if (!consumeChallenge(db, account_id, "register", clientData.challenge)) {
      return res.status(400).json({ error: "invalid, expired, or reused challenge" });
    }

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: attestationResponse,
        expectedChallenge: clientData.challenge,
        expectedOrigin: rp.origin,
        expectedRPID: rp.rpID,
      });
    } catch (err) {
      return res.status(400).json({ error: `registration verification failed: ${(err as Error).message}` });
    }
    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: "registration not verified" });
    }

    const { credential } = verification.registrationInfo;
    const deviceId = randomUUID();
    db.prepare(
      `INSERT INTO devices (device_id, account_id, credential_id, public_key, sign_count, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'active', ?)`
    ).run(
      deviceId,
      account_id,
      credential.id,
      Buffer.from(credential.publicKey).toString("base64"),
      credential.counter,
      new Date().toISOString()
    );

    const { receipt } = await chain.recordRegister(account_id, deviceId);
    res.json({ device_id: deviceId, receipt, layer: chain.currentLayer(account_id) });
  });

  router.post("/rotate/challenge", async (req, res) => {
    const { account_id } = req.body ?? {};
    const device = getActiveDevice(db, account_id);
    if (!device) return res.status(404).json({ error: "no active device" });
    res.json(await issueAuthChallenge(db, rp, account_id, "rotate-auth", device));
  });

  router.post("/rotate/start", async (req, res) => {
    const { account_id, assertionResponse } = req.body ?? {};
    const device = getActiveDevice(db, account_id);
    if (!device) return res.status(404).json({ error: "no active device to rotate from" });

    const clientData = decodeClientData(assertionResponse.response.clientDataJSON);
    if (!consumeChallenge(db, account_id, "rotate-auth", clientData.challenge)) {
      return res.status(400).json({ error: "invalid, expired, or reused challenge" });
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
    } catch (err) {
      return res.status(400).json({ error: `rotation auth failed: ${(err as Error).message}` });
    }
    if (!verification.verified) return res.status(400).json({ error: "possession of current device not proven" });

    const ticket = randomBytes(24).toString("base64url");
    db.prepare(
      `INSERT INTO rotation_tickets (ticket, account_id, old_device_id, created_at, used) VALUES (?, ?, ?, ?, 0)`
    ).run(ticket, account_id, device.device_id, Date.now());

    const registerOptions = await generateRegistrationOptions({
      rpName: rp.rpName,
      rpID: rp.rpID,
      userName: account_id,
      userID: new TextEncoder().encode(account_id),
      attestationType: "none",
      excludeCredentials: [{ id: device.credential_id }],
    });
    recordChallenge(db, account_id, "rotate-register", registerOptions.challenge);
    res.json({ rotation_ticket: ticket, registerOptions });
  });

  router.post("/rotate/finish", async (req, res) => {
    const { account_id, rotation_ticket, attestationResponse } = req.body ?? {};
    const ticketRow = db
      .prepare(`SELECT * FROM rotation_tickets WHERE ticket = ? AND account_id = ?`)
      .get(rotation_ticket, account_id) as
      | { used: number; created_at: number; old_device_id: string }
      | undefined;
    if (!ticketRow || ticketRow.used || Date.now() - ticketRow.created_at > 5 * 60 * 1000) {
      return res.status(400).json({ error: "invalid, expired, or reused rotation ticket" });
    }

    const clientData = decodeClientData(attestationResponse.response.clientDataJSON);
    if (!consumeChallenge(db, account_id, "rotate-register", clientData.challenge)) {
      return res.status(400).json({ error: "invalid, expired, or reused challenge" });
    }
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: attestationResponse,
        expectedChallenge: clientData.challenge,
        expectedOrigin: rp.origin,
        expectedRPID: rp.rpID,
      });
    } catch (err) {
      return res.status(400).json({ error: `rotation registration failed: ${(err as Error).message}` });
    }
    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: "registration not verified" });
    }

    db.prepare(`UPDATE rotation_tickets SET used = 1 WHERE ticket = ?`).run(rotation_ticket);
    db.prepare(`UPDATE devices SET status = 'revoked' WHERE device_id = ?`).run(ticketRow.old_device_id);

    const { credential } = verification.registrationInfo;
    const deviceId = randomUUID();
    db.prepare(
      `INSERT INTO devices (device_id, account_id, credential_id, public_key, sign_count, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'active', ?)`
    ).run(
      deviceId,
      account_id,
      credential.id,
      Buffer.from(credential.publicKey).toString("base64"),
      credential.counter,
      new Date().toISOString()
    );

    const { receipt } = await chain.recordRotate(account_id, deviceId, ticketRow.old_device_id);
    res.json({ device_id: deviceId, receipt, layer: chain.currentLayer(account_id) });
  });

  router.post("/revoke/challenge", async (req, res) => {
    const { account_id } = req.body ?? {};
    const device = getActiveDevice(db, account_id);
    if (!device) return res.status(404).json({ error: "no active device" });
    res.json(await issueAuthChallenge(db, rp, account_id, "revoke", device));
  });

  router.post("/revoke", async (req, res) => {
    const { account_id, assertionResponse } = req.body ?? {};
    const device = getActiveDevice(db, account_id);
    if (!device) return res.status(404).json({ error: "no active device" });

    const clientData = decodeClientData(assertionResponse.response.clientDataJSON);
    if (!consumeChallenge(db, account_id, "revoke", clientData.challenge)) {
      return res.status(400).json({ error: "invalid, expired, or reused challenge" });
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
    } catch (err) {
      return res.status(400).json({ error: `revoke auth failed: ${(err as Error).message}` });
    }
    if (!verification.verified) return res.status(400).json({ error: "possession not proven" });

    db.prepare(`UPDATE devices SET status = 'revoked' WHERE device_id = ?`).run(device.device_id);
    const { receipt } = await chain.recordRevoke(account_id, device.device_id);
    res.json({ receipt, layer: chain.currentLayer(account_id) });
  });

  return router;
}
