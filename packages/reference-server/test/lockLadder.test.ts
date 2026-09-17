import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import { verifyChain, type ChainEvent, type Receipt } from "@cla/core";

// We mock @simplewebauthn/server entirely: this test exercises OUR chain +
// lock-ladder + multi-device route wiring, not WebAuthn's own cryptography
// (which has its own, much larger, test suite upstream). Real end-to-end
// WebAuthn needs an actual platform authenticator and can't be scripted
// headlessly. The mock echoes back whatever credential id the "client"
// fixture claims (`response.id`), so tests can control which device a
// given ceremony claims to be — exactly what a real browser's WebAuthn
// implementation does by tracking credential ids itself.
let authShouldVerify = true;

vi.mock("@simplewebauthn/server", () => ({
  generateRegistrationOptions: vi.fn(async () => ({
    challenge: `reg-${randomUUID()}`,
    rp: { name: "test", id: "localhost" },
    user: { id: "u", name: "u", displayName: "u" },
    pubKeyCredParams: [],
  })),
  generateAuthenticationOptions: vi.fn(async ({ allowCredentials }: { allowCredentials?: { id: string }[] }) => ({
    challenge: `auth-${randomUUID()}`,
    allowCredentials,
  })),
  verifyRegistrationResponse: vi.fn(async ({ response }: { response: { id?: string } }) => ({
    verified: true,
    registrationInfo: {
      credential: { id: response.id ?? `cred-${randomUUID()}`, publicKey: new Uint8Array([1, 2, 3]), counter: 0 },
    },
  })),
  verifyAuthenticationResponse: vi.fn(async () => ({
    verified: authShouldVerify,
    authenticationInfo: { newCounter: 1 },
  })),
}));

const { openDb } = await import("../src/db.js");
const { createApp } = await import("../src/app.js");

function clientDataJSON(challenge: string, type: string): string {
  return Buffer.from(JSON.stringify({ challenge, type, origin: "http://localhost:5173" })).toString("base64url");
}

function fakeAttestation(challenge: string, credentialId: string) {
  return { id: credentialId, rawId: credentialId, response: { clientDataJSON: clientDataJSON(challenge, "webauthn.create") } };
}

function fakeAssertion(challenge: string, credentialId: string) {
  return { id: credentialId, rawId: credentialId, response: { clientDataJSON: clientDataJSON(challenge, "webauthn.get") } };
}

describe("CLA reference server", () => {
  let baseUrl: string;
  let close: () => void;

  beforeAll(() => {
    process.env.CLA_ADMIN_TOKEN = "test-admin-token";
    const db = openDb(":memory:");
    const { privateKey } = generateKeyPairSync("ed25519");
    const app = createApp(db, privateKey, "test-key");
    const server = app.listen(0);
    const { port } = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${port}`;
    close = () => server.close();
  });

  afterAll(() => close());

  async function post(path: string, body: unknown) {
    const res = await fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async function get(path: string) {
    const res = await fetch(`${baseUrl}${path}`);
    return { status: res.status, body: await res.json() };
  }

  describe("full lock-ladder lifecycle (single device)", () => {
    const accountId = `acct_${randomUUID()}`;
    const credId = `cred-${randomUUID()}`;

    it("registers the first device with no proof required", async () => {
      const start = await post("/v1/devices/register/start", { account_id: accountId });
      expect(start.status).toBe(200);

      const finish = await post("/v1/devices/register/finish", {
        account_id: accountId,
        attestationResponse: fakeAttestation(start.body.challenge, credId),
      });
      expect(finish.status).toBe(200);
      expect(finish.body.layer).toBe("NORMAL");
    });

    it("a second bootstrap registration is rejected once a device is active", async () => {
      const start = await post("/v1/devices/register/start", { account_id: accountId });
      expect(start.status).toBe(409);
      expect(start.body.error).toMatch(/add\/start/);
    });

    it("walks NORMAL -> LOCK -> STEP_UP -> RECOVERY purely from failed attempts", async () => {
      authShouldVerify = false;
      const expectedLayerAfterFailure = [
        // thresholds: NORMAL:3, LOCK:5, STEP_UP:3 (see DEFAULT_POLICY)
        "NORMAL", "NORMAL", "LOCK", // 3 failures -> LOCK
        "LOCK", "LOCK", "LOCK", "LOCK", "STEP_UP", // 5 more -> STEP_UP
        "STEP_UP", "STEP_UP", "RECOVERY", // 3 more -> RECOVERY
      ];

      for (const expected of expectedLayerAfterFailure) {
        const challengeRes = await post("/v1/auth/challenge", { account_id: accountId });
        const verifyRes = await post("/v1/auth/verify", {
          account_id: accountId,
          assertionResponse: fakeAssertion(challengeRes.body.challenge, credId),
        });
        expect(verifyRes.status).toBe(401);
        expect(verifyRes.body.layer).toBe(expected);
      }
    });

    it("the resulting chain is internally consistent and hash-verifiable end to end", async () => {
      const audit = (await get(`/v1/account/${accountId}/audit-log`)).body as {
        events: ChainEvent[];
        receipts: Receipt[];
        layer: string;
      };
      expect(audit.layer).toBe("RECOVERY");

      const result = await verifyChain(audit.events, audit.receipts);
      expect(result.valid).toBe(true);
      // one REGISTER + eleven FAILURE events
      expect(audit.events.length).toBe(12);
    });

    it("a still-valid device signature can always initiate a step-up, even from RECOVERY", async () => {
      authShouldVerify = true;
      const challengeRes = await post("/v1/auth/challenge", { account_id: accountId, purpose: "step_up" });
      expect(challengeRes.status).toBe(200); // never blocked by layer, per design doc §H/§I

      const verifyRes = await post("/v1/auth/verify", {
        account_id: accountId,
        assertionResponse: fakeAssertion(challengeRes.body.challenge, credId),
        purpose: "step_up",
      });
      expect(verifyRes.status).toBe(200);
      expect(verifyRes.body.layer).toBe("STEP_UP"); // one step down from RECOVERY, not straight to NORMAL
    });

    it("human-mediated recovery/complete brings the account back to NORMAL and revokes old devices", async () => {
      const start = await post("/v1/account/recovery/start", { account_id: accountId });
      expect(start.body.layer).toBe("RECOVERY"); // user-initiated recovery jumps straight there

      const badToken = await post("/v1/account/recovery/complete", { account_id: accountId, admin_token: "wrong" });
      expect(badToken.status).toBe(403);

      const complete = await post("/v1/account/recovery/complete", {
        account_id: accountId,
        admin_token: "test-admin-token",
      });
      expect(complete.status).toBe(200);
      expect(complete.body.layer).toBe("NORMAL");

      // old device is revoked; a fresh bootstrap registration is allowed again
      const reRegister = await post("/v1/devices/register/start", { account_id: accountId });
      expect(reRegister.status).toBe(200);
    });
  });

  describe("multi-device", () => {
    const accountId = `acct_${randomUUID()}`;
    const deviceACred = `cred-a-${randomUUID()}`;
    const deviceBCred = `cred-b-${randomUUID()}`;
    let deviceAId: string;
    let deviceBId: string;

    beforeAll(async () => {
      authShouldVerify = true;
      const start = await post("/v1/devices/register/start", { account_id: accountId });
      const finish = await post("/v1/devices/register/finish", {
        account_id: accountId,
        attestationResponse: fakeAttestation(start.body.challenge, deviceACred),
      });
      deviceAId = finish.body.device_id;
    });

    it("adding a second device requires proof from the first, and does not revoke it", async () => {
      const challenge = await post("/v1/devices/add/challenge", { account_id: accountId });
      expect(challenge.status).toBe(200);
      // allowCredentials should list every active device (just device A so far)
      expect(challenge.body.allowCredentials?.map((c: { id: string }) => c.id)).toEqual([deviceACred]);

      const start = await post("/v1/devices/add/start", {
        account_id: accountId,
        assertionResponse: fakeAssertion(challenge.body.challenge, deviceACred),
      });
      expect(start.status).toBe(200);

      const finish = await post("/v1/devices/add/finish", {
        account_id: accountId,
        add_ticket: start.body.add_ticket,
        attestationResponse: fakeAttestation(start.body.registerOptions.challenge, deviceBCred),
      });
      expect(finish.status).toBe(200);
      deviceBId = finish.body.device_id;
      expect(deviceBId).not.toBe(deviceAId);

      const list = await get(`/v1/devices?account_id=${accountId}`);
      expect(list.body.devices.map((d: { device_id: string }) => d.device_id).sort()).toEqual(
        [deviceAId, deviceBId].sort()
      );
    });

    it("either device can authenticate, and the server reports which one signed", async () => {
      const challenge = await post("/v1/auth/challenge", { account_id: accountId });
      expect(challenge.body.allowCredentials.map((c: { id: string }) => c.id).sort()).toEqual(
        [deviceACred, deviceBCred].sort()
      );

      const verifyA = await post("/v1/auth/verify", {
        account_id: accountId,
        assertionResponse: fakeAssertion(challenge.body.challenge, deviceACred),
      });
      expect(verifyA.status).toBe(200);
      expect(verifyA.body.device_id).toBe(deviceAId);

      const challenge2 = await post("/v1/auth/challenge", { account_id: accountId });
      const verifyB = await post("/v1/auth/verify", {
        account_id: accountId,
        assertionResponse: fakeAssertion(challenge2.body.challenge, deviceBCred),
      });
      expect(verifyB.status).toBe(200);
      expect(verifyB.body.device_id).toBe(deviceBId);
    });

    it("device A can revoke device B — 'use my laptop to kill my lost phone'", async () => {
      const challenge = await post("/v1/devices/revoke/challenge", { account_id: accountId });
      const revoke = await post("/v1/devices/revoke", {
        account_id: accountId,
        device_id: deviceBId,
        assertionResponse: fakeAssertion(challenge.body.challenge, deviceACred),
      });
      expect(revoke.status).toBe(200);

      const list = await get(`/v1/devices?account_id=${accountId}`);
      expect(list.body.devices.map((d: { device_id: string }) => d.device_id)).toEqual([deviceAId]);

      // device B can no longer authenticate
      const authChallenge = await post("/v1/auth/challenge", { account_id: accountId });
      expect(authChallenge.body.allowCredentials.map((c: { id: string }) => c.id)).toEqual([deviceACred]);
    });

    it("an unrecognized credential id fails cleanly and still advances the ladder", async () => {
      const challenge = await post("/v1/auth/challenge", { account_id: accountId });
      const verify = await post("/v1/auth/verify", {
        account_id: accountId,
        assertionResponse: fakeAssertion(challenge.body.challenge, "never-registered-cred"),
      });
      expect(verify.status).toBe(401);
      expect(verify.body.layer).toBe("NORMAL"); // first failure, threshold not yet met
    });
  });
});
