import { Router } from "express";
import type { Database } from "better-sqlite3";
import { randomUUID, randomBytes } from "node:crypto";
import { generateRegistrationOptions, verifyRegistrationResponse, verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { ChainStore } from "../chainStore.js";
import type { RpConfig } from "../webauthn.js";
import type { AddTicketRow, RotationTicketRow } from "../db.js";
import {
  getActiveDevices,
  getActiveDeviceByCredentialId,
  getDeviceById,
  toCredential,
  recordChallenge,
  consumeChallenge,
  issueAuthChallenge,
  decodeClientData,
} from "../deviceHelpers.js";

function insertDevice(
  db: Database,
  accountId: string,
  credentialId: string,
  publicKey: Uint8Array,
  counter: number
): string {
  const deviceId = randomUUID();
  db.prepare(
    `INSERT INTO devices (device_id, account_id, credential_id, public_key, sign_count, status, created_at)
     VALUES (?, ?, ?, ?, ?, 'active', ?)`
  ).run(deviceId, accountId, credentialId, Buffer.from(publicKey).toString("base64"), counter, new Date().toISOString());
  return deviceId;
}

export function devicesRouter(db: Database, chain: ChainStore, rp: RpConfig): Router {
  const router = Router();

  // ---- Bootstrap: the account's very first device. No proof required —
  // there is nothing yet to prove possession of. Rejected once any active
  // device exists; use /add/* after that. ----

  router.post("/register/start", async (req, res) => {
    const { account_id } = req.body ?? {};
    if (!account_id) return res.status(400).json({ error: "account_id required" });

    if (getActiveDevices(db, account_id).length > 0) {
      return res.status(409).json({ error: "account already has an active device; use /devices/add/start" });
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
    const deviceId = insertDevice(db, account_id, credential.id, credential.publicKey, credential.counter);

    const { receipt } = await chain.recordRegister(account_id, deviceId);
    res.json({ device_id: deviceId, receipt, layer: chain.currentLayer(account_id) });
  });

  // ---- Listing ----

  router.get("/", (req, res) => {
    const accountId = req.query.account_id as string | undefined;
    if (!accountId) return res.status(400).json({ error: "account_id query param required" });
    const devices = getActiveDevices(db, accountId).map((d) => ({
      device_id: d.device_id,
      created_at: d.created_at,
      status: d.status,
    }));
    res.json({ devices });
  });

  // ---- Add a device: authorized by an assertion from any EXISTING active
  // device. Does not touch other devices — this is additive, unlike rotate. ----

  router.post("/add/challenge", async (req, res) => {
    const { account_id } = req.body ?? {};
    const devices = getActiveDevices(db, account_id);
    if (devices.length === 0) {
      return res.status(404).json({ error: "no active device yet; use /devices/register/start" });
    }
    res.json(await issueAuthChallenge(db, rp, account_id, "add-auth", devices));
  });

  router.post("/add/start", async (req, res) => {
    const { account_id, assertionResponse } = req.body ?? {};
    const credentialId: string | undefined = assertionResponse?.id ?? assertionResponse?.rawId;
    const authorizer = credentialId ? getActiveDeviceByCredentialId(db, account_id, credentialId) : undefined;
    if (!authorizer) return res.status(401).json({ error: "no recognized device signed this request" });

    const clientData = decodeClientData(assertionResponse.response.clientDataJSON);
    if (!consumeChallenge(db, account_id, "add-auth", clientData.challenge)) {
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
      return res.status(400).json({ error: `add-device auth failed: ${(err as Error).message}` });
    }
    if (!verification.verified) return res.status(400).json({ error: "possession of an existing device not proven" });

    const ticket = randomBytes(24).toString("base64url");
    db.prepare(
      `INSERT INTO add_tickets (ticket, account_id, authorized_by_device_id, created_at, used) VALUES (?, ?, ?, ?, 0)`
    ).run(ticket, account_id, authorizer.device_id, Date.now());

    const existing = getActiveDevices(db, account_id);
    const registerOptions = await generateRegistrationOptions({
      rpName: rp.rpName,
      rpID: rp.rpID,
      userName: account_id,
      userID: new TextEncoder().encode(account_id),
      attestationType: "none",
      excludeCredentials: existing.map((d) => ({ id: d.credential_id })),
    });
    recordChallenge(db, account_id, "add-register", registerOptions.challenge);
    res.json({ add_ticket: ticket, registerOptions });
  });

  router.post("/add/finish", async (req, res) => {
    const { account_id, add_ticket, attestationResponse } = req.body ?? {};
    const ticketRow = db
      .prepare(`SELECT * FROM add_tickets WHERE ticket = ? AND account_id = ?`)
      .get(add_ticket, account_id) as AddTicketRow | undefined;
    if (!ticketRow || ticketRow.used || Date.now() - ticketRow.created_at > 5 * 60 * 1000) {
      return res.status(400).json({ error: "invalid, expired, or reused add ticket" });
    }

    const clientData = decodeClientData(attestationResponse.response.clientDataJSON);
    if (!consumeChallenge(db, account_id, "add-register", clientData.challenge)) {
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
      return res.status(400).json({ error: `add-device registration failed: ${(err as Error).message}` });
    }
    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: "registration not verified" });
    }

    db.prepare(`UPDATE add_tickets SET used = 1 WHERE ticket = ?`).run(add_ticket);

    const { credential } = verification.registrationInfo;
    const deviceId = insertDevice(db, account_id, credential.id, credential.publicKey, credential.counter);

    const { receipt } = await chain.recordDeviceAdd(account_id, deviceId, ticketRow.authorized_by_device_id);
    res.json({ device_id: deviceId, receipt, layer: chain.currentLayer(account_id) });
  });

  // ---- Rotate: a device proves possession of ITSELF, then is replaced
  // 1:1 by a new credential. Every other device on the account is untouched. ----

  router.post("/rotate/challenge", async (req, res) => {
    const { account_id, device_id } = req.body ?? {};
    const device = getDeviceById(db, account_id, device_id);
    if (!device || device.status !== "active") return res.status(404).json({ error: "no such active device" });
    res.json(await issueAuthChallenge(db, rp, account_id, "rotate-auth", [device]));
  });

  router.post("/rotate/start", async (req, res) => {
    const { account_id, device_id, assertionResponse } = req.body ?? {};
    const device = getDeviceById(db, account_id, device_id);
    if (!device || device.status !== "active") return res.status(404).json({ error: "no such active device" });

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

    const existing = getActiveDevices(db, account_id);
    const registerOptions = await generateRegistrationOptions({
      rpName: rp.rpName,
      rpID: rp.rpID,
      userName: account_id,
      userID: new TextEncoder().encode(account_id),
      attestationType: "none",
      excludeCredentials: existing.map((d) => ({ id: d.credential_id })),
    });
    recordChallenge(db, account_id, "rotate-register", registerOptions.challenge);
    res.json({ rotation_ticket: ticket, registerOptions });
  });

  router.post("/rotate/finish", async (req, res) => {
    const { account_id, rotation_ticket, attestationResponse } = req.body ?? {};
    const ticketRow = db
      .prepare(`SELECT * FROM rotation_tickets WHERE ticket = ? AND account_id = ?`)
      .get(rotation_ticket, account_id) as RotationTicketRow | undefined;
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
    const deviceId = insertDevice(db, account_id, credential.id, credential.publicKey, credential.counter);

    const { receipt } = await chain.recordRotate(account_id, deviceId, ticketRow.old_device_id);
    res.json({ device_id: deviceId, receipt, layer: chain.currentLayer(account_id) });
  });

  // ---- Revoke: ANY active device may authorize revoking ANY device on the
  // account (including itself) — "use my laptop to kill my lost phone." ----

  router.post("/revoke/challenge", async (req, res) => {
    const { account_id } = req.body ?? {};
    const devices = getActiveDevices(db, account_id);
    if (devices.length === 0) return res.status(404).json({ error: "no active device" });
    res.json(await issueAuthChallenge(db, rp, account_id, "revoke", devices));
  });

  router.post("/revoke", async (req, res) => {
    const { account_id, device_id, assertionResponse } = req.body ?? {};
    if (!device_id) return res.status(400).json({ error: "device_id (the target to revoke) required" });

    const credentialId: string | undefined = assertionResponse?.id ?? assertionResponse?.rawId;
    const signer = credentialId ? getActiveDeviceByCredentialId(db, account_id, credentialId) : undefined;
    if (!signer) return res.status(401).json({ error: "no recognized device signed this request" });

    const target = getDeviceById(db, account_id, device_id);
    if (!target || target.status !== "active") {
      return res.status(404).json({ error: "no such active device to revoke" });
    }

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
        credential: toCredential(signer),
      });
    } catch (err) {
      return res.status(400).json({ error: `revoke auth failed: ${(err as Error).message}` });
    }
    if (!verification.verified) return res.status(400).json({ error: "possession not proven" });

    db.prepare(`UPDATE devices SET status = 'revoked' WHERE device_id = ?`).run(target.device_id);
    const { receipt } = await chain.recordRevoke(account_id, target.device_id, signer.device_id);
    res.json({ receipt, layer: chain.currentLayer(account_id) });
  });

  return router;
}
