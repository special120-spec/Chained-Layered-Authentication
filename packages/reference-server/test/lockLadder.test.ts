import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import Database from "better-sqlite3";
import { verifyChain, type ChainEvent, type Receipt } from "@cla/core";

// We mock @simplewebauthn/server entirely: this test exercises OUR chain +
// lock-ladder + route wiring, not WebAuthn's own cryptography (which has
// its own, much larger, test suite upstream). Real end-to-end WebAuthn
// needs an actual platform authenticator and can't be scripted headlessly.
let authShouldVerify = true;

vi.mock("@simplewebauthn/server", () => ({
  generateRegistrationOptions: vi.fn(async () => ({
    challenge: `reg-${randomUUID()}`,
    rp: { name: "test", id: "localhost" },
    user: { id: "u", name: "u", displayName: "u" },
    pubKeyCredParams: [],
  })),
  generateAuthenticationOptions: vi.fn(async () => ({
    challenge: `auth-${randomUUID()}`,
  })),
  verifyRegistrationResponse: vi.fn(async () => ({
    verified: true,
    registrationInfo: {
      credential: { id: `cred-${randomUUID()}`, publicKey: new Uint8Array([1, 2, 3]), counter: 0 },
    },
  })),
  verifyAuthenticationResponse: vi.fn(async () => ({
    verified: authShouldVerify,
    authenticationInfo: { newCounter: 1 },
  })),
}));

const { openDb } = await import("../src/db.js");
const { createApp } = await import("../src/app.js");

function fakeClientDataJSON(challenge: string, type: string): string {
  return Buffer.from(JSON.stringify({ challenge, type, origin: "http://localhost:5173" })).toString(
    "base64url"
  );
}

describe("CLA reference server: full lock-ladder lifecycle", () => {
  let baseUrl: string;
  let close: () => void;
  const accountId = `acct_${randomUUID()}`;

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

  it("registers a device", async () => {
    const start = await post("/v1/devices/register/start", { account_id: accountId });
    expect(start.status).toBe(200);

    const attestationResponse = { response: { clientDataJSON: fakeClientDataJSON(start.body.challenge, "webauthn.create") } };
    const finish = await post("/v1/devices/register/finish", { account_id: accountId, attestationResponse });
    expect(finish.status).toBe(200);
    expect(finish.body.layer).toBe("NORMAL");
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
      const assertionResponse = {
        response: { clientDataJSON: fakeClientDataJSON(challengeRes.body.challenge, "webauthn.get") },
      };
      const verifyRes = await post("/v1/auth/verify", { account_id: accountId, assertionResponse });
      expect(verifyRes.status).toBe(401);
      expect(verifyRes.body.layer).toBe(expected);
    }
  });

  it("the resulting chain is internally consistent and hash-verifiable end to end", async () => {
    const auditRes = await fetch(`${baseUrl}/v1/account/${accountId}/audit-log`);
    const audit = (await auditRes.json()) as { events: ChainEvent[]; receipts: Receipt[]; layer: string };
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

    const assertionResponse = {
      response: { clientDataJSON: fakeClientDataJSON(challengeRes.body.challenge, "webauthn.get") },
    };
    const verifyRes = await post("/v1/auth/verify", {
      account_id: accountId,
      assertionResponse,
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

    // old device is revoked; a fresh registration is now allowed
    const reRegister = await post("/v1/devices/register/start", { account_id: accountId });
    expect(reRegister.status).toBe(200);
  });
});
