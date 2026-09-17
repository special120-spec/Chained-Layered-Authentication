import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import type Database from "better-sqlite3";
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
let mockNewCounter = 1;

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
    authenticationInfo: { newCounter: mockNewCounter },
  })),
}));

const { openDb } = await import("../src/db.js");
const { createApp } = await import("../src/app.js");

function clientDataJSON(challenge: string, type: string): string {
  return Buffer.from(JSON.stringify({ challenge, type, origin: "http://localhost:5173" })).toString("base64url");
}

/**
 * Advances the mocked wall clock so `cooldownRemainingSeconds` reads the
 * previous attempt as expired. Deliberately does NOT rewrite any already-
 * stored `timestamp` — that field is part of what's hashed into
 * `entry_hash` (spec §3), so editing history after the fact breaks the
 * chain, exactly as the tamper-evidence design intends. Only `Date` is
 * faked (not setTimeout/setInterval), so the real HTTP server, sockets,
 * and `fetch` calls this suite makes are unaffected.
 */
function advanceClockSeconds(seconds: number) {
  vi.setSystemTime(new Date(Date.now() + seconds * 1000));
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
  let db: Database.Database;

  beforeAll(() => {
    process.env.CLA_ADMIN_TOKEN = "test-admin-token";
    // This suite exercises many endpoints from one client IP across many
    // tests — raise the general IP backstop so it doesn't interfere with
    // tests that aren't about it. The limiter itself is unit-tested
    // directly in rateLimit.test.ts.
    process.env.CLA_RATE_LIMIT_IP_MAX = "100000";
    db = openDb(":memory:");
    const { privateKey } = generateKeyPairSync("ed25519");
    const app = createApp(db, privateKey, "test-key");
    const server = app.listen(0);
    const { port } = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${port}`;
    close = () => server.close();
    // Only Date is faked (never setTimeout/setInterval), so the real
    // server/socket/fetch machinery this suite depends on is untouched —
    // this exists purely so advanceClockSeconds can simulate elapsed time
    // for cooldown checks without rewriting stored history.
    vi.useFakeTimers({ toFake: ["Date"] });
  });

  afterAll(() => {
    vi.useRealTimers();
    close();
  });

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
        // Advance past any cooldown from the previous iteration first: this
        // test is exercising ladder progression across many failures, not
        // the cooldown gate itself (that's covered separately below), and a
        // real deployment would naturally have this much time between
        // distinct attempts anyway. 120s clears any cooldown this sequence
        // produces (max 64s) while staying well inside the 15-minute
        // rolling failure-count window, which is a separate mechanism.
        advanceClockSeconds(120);
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

  describe("/v1/auth/verify hardening", () => {
    it("a request with no valid, previously-issued challenge is rejected WITHOUT touching the chain at all", async () => {
      // Regression test for the finding: an attacker who never called
      // /v1/auth/challenge, and supplies a garbage credential id, must not
      // be able to record a FAILURE or move the lock ladder — not even a
      // little. Deliberately skips /challenge entirely.
      const accountId = `acct_${randomUUID()}`;
      const credId = `cred-${randomUUID()}`;
      const start = await post("/v1/devices/register/start", { account_id: accountId });
      await post("/v1/devices/register/finish", {
        account_id: accountId,
        attestationResponse: fakeAttestation(start.body.challenge, credId),
      });

      const before = await get(`/v1/account/${accountId}/audit-log`);
      expect(before.body.events.length).toBe(1); // just REGISTER

      for (let i = 0; i < 5; i++) {
        const verify = await post("/v1/auth/verify", {
          account_id: accountId,
          assertionResponse: fakeAssertion("never-issued-challenge", "never-registered-cred"),
        });
        expect(verify.status).toBe(400);
        expect(verify.body.error).toMatch(/challenge/);
      }

      const after = await get(`/v1/account/${accountId}/audit-log`);
      expect(after.body.events.length).toBe(1); // still just REGISTER — no FAILUREs were ever recorded
      expect(after.body.layer).toBe("NORMAL");
    });

    it("cooldown blocks an immediate repeat auth attempt once the ladder has engaged, but never blocks step-up", async () => {
      const accountId = `acct_${randomUUID()}`;
      const credId = `cred-${randomUUID()}`;
      const start = await post("/v1/devices/register/start", { account_id: accountId });
      await post("/v1/devices/register/finish", {
        account_id: accountId,
        attestationResponse: fakeAttestation(start.body.challenge, credId),
      });

      authShouldVerify = false;
      for (let i = 0; i < 3; i++) {
        advanceClockSeconds(120); // isolate ladder progression from the cooldown under test
        const challenge = await post("/v1/auth/challenge", { account_id: accountId });
        await post("/v1/auth/verify", {
          account_id: accountId,
          assertionResponse: fakeAssertion(challenge.body.challenge, credId),
        });
      }
      const engaged = await get(`/v1/account/${accountId}/audit-log`);
      expect(engaged.body.layer).toBe("LOCK"); // 3 failures -> LOCK, per DEFAULT_POLICY

      // Immediately (no expireCooldown call) try another ordinary auth attempt.
      const challenge = await post("/v1/auth/challenge", { account_id: accountId });
      const blocked = await post("/v1/auth/verify", {
        account_id: accountId,
        assertionResponse: fakeAssertion(challenge.body.challenge, credId),
      });
      expect(blocked.status).toBe(429);
      expect(blocked.body.error).toBe("cooldown_active");
      expect(blocked.body.retry_after_seconds).toBeGreaterThan(0);

      // The blocked attempt must not itself have been recorded as another
      // FAILURE or moved the ladder any further.
      const stillLocked = await get(`/v1/account/${accountId}/audit-log`);
      expect(stillLocked.body.layer).toBe("LOCK");
      expect(stillLocked.body.events.length).toBe(engaged.body.events.length);

      // But a step-up, immediately, with no cooldown expiry, must go through.
      authShouldVerify = true;
      const stepUpChallenge = await post("/v1/auth/challenge", { account_id: accountId, purpose: "step_up" });
      expect(stepUpChallenge.status).toBe(200);
      const stepUp = await post("/v1/auth/verify", {
        account_id: accountId,
        assertionResponse: fakeAssertion(stepUpChallenge.body.challenge, credId),
        purpose: "step_up",
      });
      expect(stepUp.status).toBe(200);
      expect(stepUp.body.layer).toBe("NORMAL"); // one step down from LOCK
    });
  });

  describe("hardening: M1-M4", () => {
    it("M3: a malformed body (account_id as an object) is rejected with 400, not a crash", async () => {
      // Regression for the crash scenario security review M3 describes:
      // this used to reach better-sqlite3's .get()/.run() with a non-string
      // bind parameter and throw synchronously inside an async handler,
      // which Express 4 does not catch. asyncHandler + isValidId close it.
      const res = await post("/v1/devices/register/start", { account_id: { evil: true } });
      expect(res.status).toBe(400);

      const res2 = await post("/v1/auth/verify", { account_id: ["a", "b"], assertionResponse: {} });
      expect(res2.status).toBe(400);

      // The server must still be alive and serving other requests after both.
      const health = await fetch(`${baseUrl}/healthz`);
      expect(health.status).toBe(200);
    });

    it("M4: concurrent failed attempts against the same account never corrupt the chain", async () => {
      // Regression for the race in chainStore.append: before the fix,
      // nextSeq()/lastHash() were read, then an `await computeEntryHash`
      // yielded to the event loop before the INSERT — a real window for
      // another concurrent request to read the same stale tip. Fired
      // concurrently on purpose; a correct implementation serializes them
      // (or fails outright) rather than corrupting the sequence or the hash
      // links, since chainStore.append is now synchronous end to end.
      const accountId = `acct_${randomUUID()}`;
      const credId = `cred-${randomUUID()}`;
      const start = await post("/v1/devices/register/start", { account_id: accountId });
      await post("/v1/devices/register/finish", {
        account_id: accountId,
        attestationResponse: fakeAttestation(start.body.challenge, credId),
      });

      authShouldVerify = false;
      const N = 8;
      const challenges = await Promise.all(
        Array.from({ length: N }, () => post("/v1/auth/challenge", { account_id: accountId }))
      );
      const results = await Promise.all(
        challenges.map((c) =>
          post("/v1/auth/verify", { account_id: accountId, assertionResponse: fakeAssertion(c.body.challenge, credId) })
        )
      );
      // Every concurrent request must get a clean response either way —
      // never a 500, never a hang.
      for (const r of results) expect([401, 429]).toContain(r.status);

      const audit = (await get(`/v1/account/${accountId}/audit-log`)).body as {
        events: ChainEvent[];
        receipts: Receipt[];
      };
      const seqs = audit.events.map((e) => e.seq);
      expect(seqs).toEqual([...seqs].sort((a, b) => a - b)); // strictly ordered
      expect(new Set(seqs).size).toBe(seqs.length); // no duplicate seq — the actual failure mode a race would cause
      const result = await verifyChain(audit.events, audit.receipts);
      expect(result.valid).toBe(true); // the hash chain itself is still internally consistent
    });

    it("cloned-authenticator detection: a signature counter that doesn't advance is rejected once the authenticator has reported a nonzero count", async () => {
      const accountId = `acct_${randomUUID()}`;
      const credId = `cred-${randomUUID()}`;
      const start = await post("/v1/devices/register/start", { account_id: accountId });
      await post("/v1/devices/register/finish", {
        account_id: accountId,
        attestationResponse: fakeAttestation(start.body.challenge, credId),
      });

      authShouldVerify = true;
      mockNewCounter = 5; // first real auth: counter advances from 0 (registration) to 5
      const challenge1 = await post("/v1/auth/challenge", { account_id: accountId });
      const first = await post("/v1/auth/verify", {
        account_id: accountId,
        assertionResponse: fakeAssertion(challenge1.body.challenge, credId),
      });
      expect(first.status).toBe(200);

      // A second assertion reporting the SAME (non-advancing) counter is the
      // WebAuthn-spec signal of a cloned authenticator — must be rejected,
      // not silently accepted.
      mockNewCounter = 5;
      const challenge2 = await post("/v1/auth/challenge", { account_id: accountId });
      const second = await post("/v1/auth/verify", {
        account_id: accountId,
        assertionResponse: fakeAssertion(challenge2.body.challenge, credId),
      });
      expect(second.status).toBe(401);

      const audit = await get(`/v1/account/${accountId}/audit-log`);
      const lastEvent = audit.body.events[audit.body.events.length - 1];
      expect(lastEvent.type).toBe("FAILURE");
      expect(lastEvent.detail.reason).toBe("possible_cloned_authenticator");

      mockNewCounter = 1; // restore default for any later test
    });
  });

  describe("hardening: H3 rate limiting (wiring only — createRateLimiter's own logic is unit-tested in rateLimit.test.ts)", () => {
    it("/v1/account/recovery/start is capped at 3/hour per account", async () => {
      const accountId = `acct_${randomUUID()}`;
      for (let i = 0; i < 3; i++) {
        const res = await post("/v1/account/recovery/start", { account_id: accountId });
        expect(res.status).toBe(200);
      }
      const fourth = await post("/v1/account/recovery/start", { account_id: accountId });
      expect(fourth.status).toBe(429);
      expect(fourth.body.error).toBe("rate_limited");
      expect(fourth.body.retry_after_seconds).toBeGreaterThan(0);

      // A different account is entirely unaffected — this is a per-account
      // limit, not a global one.
      const otherAccount = `acct_${randomUUID()}`;
      const otherRes = await post("/v1/account/recovery/start", { account_id: otherAccount });
      expect(otherRes.status).toBe(200);
    });
  });
});
