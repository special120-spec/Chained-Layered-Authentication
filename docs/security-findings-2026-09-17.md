# CLA Security Review — Findings

Reviewed at commit `478d826` (`main`), scope per the review brief: `packages/reference-server` → `packages/core` → `packages/sdk-js` → `examples/demo`, in that priority order. Spec: `spec/cla-protocol-v1.md`. Known-limitations baseline: `SECURITY.md`.

Status legend: 🔴 open · 🟢 fixed in this pass (applied directly to `chainStore.ts` / `routes/auth.ts` / `test/lockLadder.test.ts`, commit follows this file in the same push)

---

## Critical

### C1 — 🟢 FIXED: Unauthenticated lockout-ladder DoS via `/v1/auth/verify`
**File:** `packages/reference-server/src/routes/auth.ts`

`SECURITY.md` explicitly lists *"forcing an account into RECOVERY or a deep lock layer without any valid signature from an enrolled device"* as in-scope — a real bug if found. It was present.

The `/verify` handler resolved the device from the assertion's credential id **before** touching the challenge or the WebAuthn signature:

```ts
const device = credentialId ? getActiveDeviceByCredentialId(db, account_id, credentialId) : undefined;
if (!device) {
  const { receipt } = await chain.recordFailure(account_id, null, "unrecognized_device");
  return res.status(401).json({ ... });
}
// challenge decoding/consumption and signature verification happened only below this point
```

Any caller who knew (or guessed) an `account_id` could POST:

```
POST /v1/auth/verify {"account_id":"victim","assertionResponse":{"id":"x"}}
```

eleven times and walk the account `NORMAL → LOCK → STEP_UP → RECOVERY` with **zero** proof of possession — no prior call to `/challenge`, no valid `clientDataJSON`, no signature. No rate limiting existed anywhere in `app.ts` to slow this down. The test suite documented the credential-mismatch behavior as intentional without noticing the same code path skipped challenge/signature validation entirely.

**Fix applied:** reordered `/verify` so a valid, unexpired, single-use challenge must be consumed *before* any device resolution, signature check, or `FAILURE` write. A request with no real challenge is now rejected with `400` and **never touches the chain**.

**Verification:** new test *"a request with no valid, previously-issued challenge is rejected WITHOUT touching the chain at all"* — asserts the audit log is unchanged (still just `REGISTER`) after 5 such requests.

### C2 — 🟢 FIXED: Cooldown was computed but never enforced
**File:** `packages/reference-server/src/chainStore.ts`, `routes/auth.ts`

`chainStore.ts` computed `cooldown_seconds` on every `FAILURE` and stored it in `detail`, but no route ever read it back. Per spec §5, cooldown is supposed to gate *when a same-kind attempt is accepted* (step-up must remain unconditionally initiable — that part was correctly implemented in `canInitiateStepUp`). In practice nothing throttled ordinary retries at all, compounding C1 and leaving wrong-signature brute-forcing unthrottled server-side.

**Fix applied:** added `ChainStore.cooldownRemainingSeconds()` and a check in `/verify` that returns `429` with `Retry-After` for non-step-up purposes while cooldown is active. Step-up/recovery remain unconditionally initiable, matching design doc §H/§I.

**Verification:** new test *"cooldown blocks an immediate repeat auth attempt once the ladder has engaged, but never blocks step-up"*.

---

## High — access control gaps (open)

### H1 — 🔴 `GET /v1/account/:id/audit-log` is unauthenticated
**File:** `packages/reference-server/src/routes/account.ts`

Anyone who knows an `account_id` can read the full event history: device adds/revokes, failure reasons, timestamps of every attempt. `core/types.ts` documents the chain as "meant to be exportable to the account owner," but the route exports it to anyone.

**Recommendation:** gate behind a real session. Note the reference server never actually issues the `session_token` the spec's endpoint table mentions for `/auth/verify` — that needs implementing before this can be fixed properly. At minimum, require a step-up-equivalent proof for this specific endpoint, since it's the most information-dense one in the API.

### H2 — 🔴 `GET /v1/devices?account_id=...` is unauthenticated
**File:** `packages/reference-server/src/routes/devices.ts`

Lower sensitivity than H1 (returns only `device_id`, `created_at`, `status`), but still lets anyone enumerate an account's device count/history without proof.

**Recommendation:** same session/step-up gate as H1, or accept as a documented trade-off if device metadata is considered non-sensitive for your deployment — but decide explicitly rather than by omission.

### H3 — 🟡 PARTIALLY FIXED: `/v1/account/recovery/start` had no rate limiting or owner notification
**File:** `packages/reference-server/src/routes/account.ts`, new `src/rateLimit.ts`

Requiring no signature here is a documented, structurally necessary trade-off (§7 of the design doc) — that part was never the finding. The finding was that nothing else bounded it.

**Fix applied (the rate-limiting half):** a new in-memory `createRateLimiter` (fixed-window, per-key) is now wired in at three layers: a general 120/min/IP backstop across all of `/v1/*`; a 30/min-per-account limiter on `/v1/auth/challenge` and `/v1/auth/verify` (defense-in-depth for the residual gap noted in the C1 fix — calling `/challenge` first is still free, this bounds how fast that path can be exercised); and endpoint-specific limits on `/v1/account/recovery/start` (3/hour/account) and `/recovery/complete` (10/hour, both per-account and per-IP). Unit-tested directly (`test/rateLimit.test.ts`) plus one integration test confirming the real wiring (`recovery/start`'s cap trips on the 4th call, a different account is unaffected).

**Still open (the notification half):** nothing fires a signal to the account's registered contact when recovery is requested. This needs an actual notification channel (email/push) that doesn't exist anywhere in this reference server yet — out of scope for an in-process fix, flagged here so it isn't lost.

Also still open, same root cause as H1/H2 below: this reference server is in-memory/single-process, so the rate limiter (and everything else) resets on restart and doesn't share state across multiple instances — fine for the reference implementation, not for a horizontally-scaled deployment (would need a shared store, e.g. Redis).

---

## Medium — implementation hygiene

### M1 — 🟢 FIXED: Timing side-channel on the admin token
**File:** `packages/reference-server/src/routes/account.ts`, new `src/safeCompare.ts`

Was a plain `!==` comparison. **Fix applied:** `safeEqual()` hashes both sides (SHA-256) before `crypto.timingSafeEqual` — normalizes length so the constant-time comparison can run at all without a length-mismatch throw, and avoids leaking the secret's length via that throw.

### M2 — 🟢 FIXED: Server signing key written world-readable
**File:** `packages/reference-server/src/keys.ts`

**Fix applied:** `writeFileSync(path, data, { mode: 0o600 })`.

### M3 — 🟢 FIXED (crash risk): Unhandled promise rejections could crash the whole server
**Files:** `packages/reference-server/src/asyncHandler.ts`, `src/validate.ts`, `app.ts`, every route file

**Fix applied:** every route now goes through a new `asyncHandler` wrapper (`Promise.resolve(fn(...)).catch(next)`), plus a final error-handling middleware in `app.ts` that returns a clean `500` instead of the process crashing. Also added `isValidId` guards on every `account_id`/`device_id`/ticket field pulled from a request body or query string, closing the concrete example given (an object/array where a string id was expected). New test: a request with `account_id` as an object gets a clean `400`, and the server is confirmed still serving `/healthz` afterward.

Not done in this pass, still a worthwhile follow-up: a general request-body *schema* validator (e.g. zod) — `isValidId` is narrowly scoped to id-shaped strings, not a full replacement for one.

### M4 — 🟢 FIXED: `chainStore.append`'s read-then-write wasn't safe under concurrency
**File:** `packages/reference-server/src/chainStore.ts`, `packages/core/src/serverSigning.ts`

Root cause was more specific than "no transaction": `append` read `nextSeq()`/`lastHash()`, then did `await computeEntryHash(...)` — a genuine yield to the event loop — before the `INSERT`. That `await` was the actual race window; wrapping it in a `better-sqlite3` `.transaction()` wasn't a viable fix as originally suggested, since that API only supports synchronous callbacks and `computeEntryHash` (Web Crypto, for browser-safety) is inherently async.

**Fix applied:** added `computeEntryHashSync` (`node:crypto`, identical output) for server-internal use, and made `ChainStore.append` fully synchronous end to end — no `await` between reading the chain's tip and writing the new row, which is sufficient on a single-threaded, single-connection better-sqlite3 setup (no other code can interleave mid-synchronous-function). The browser SDK keeps using the original async `computeEntryHash` unchanged. New test: 8 concurrent `/v1/auth/verify` calls against the same account produce a strictly-ordered, no-duplicate-seq, hash-valid chain, run 5x to check for flakiness.

---

## Additional finding beyond this review's scope (fixed)

### Cloned-authenticator detection was missing entirely
**File:** `packages/reference-server/src/routes/auth.ts`

Not in the original findings list — flagged separately while first reading the codebase, fixed in the same pass as M1-M4 since it touches the same file. WebAuthn's signature counter exists specifically to detect a duplicated/cloned credential: if an authenticator has ever reported a nonzero counter, a later assertion reporting a counter that isn't strictly greater is that signal. The server previously just overwrote `sign_count` with whatever was reported, with no check. **Fix applied:** a same-or-lower nonzero counter is now rejected as `possible_cloned_authenticator` (recorded as a real chain `FAILURE`, same as any other failed attempt) instead of silently accepted. Authenticators that always report `0` (common for platform authenticators, confirmed in this project's own manual testing with Windows Hello) are correctly exempt, per spec.

---

## Low / hardening (open, non-urgent)

### L1 — Account enumeration
`/auth/challenge` 404s on no-device, `/register/start` 409s on existing-device — both leak account existence. This is largely inherent to WebAuthn's `allowCredentials` model and not unique to CLA. If you want to reduce it: return a plausible dummy challenge with fabricated `allowCredentials` on the no-device path instead of an explicit 404, and rate-limit enumeration attempts generally.

### L2 — Browser SDK never verifies `server_sig`
`packages/sdk-js/src/index.ts`'s `verifyAuditLog` relies solely on hash recomputation against a cached receipt, which is sufficient for the tamper-evidence guarantee as specified — this is not a hole in that guarantee. But `verifyEntryHashSignature` (`@cla/core/server-signing`) is Node-only (`node:crypto`), so the browser SDK has no path to check it even as defense-in-depth. If server-signature verification is meant to matter for browser clients (e.g., handing a receipt to a third party without a live trusted connection), a WebCrypto Ed25519 verify path is needed — `Ed25519` support in `SubtleCrypto` is recent and not universal, so this needs feature detection/polyfill.

### L3 — CORS default
`app.ts` defaults `CLA_ORIGIN` to `http://localhost:5173` if unset. This fails safe (blocks prod traffic rather than opening up) — just ensure deployment configs always set it explicitly.

---

## What's solid

- Chain hashing and canonicalization (`core/chain.ts`) and lock-state derivation (`core/lockState.ts`) correctly implement the spec and match their test coverage.
- Multi-device resolution by credential id, ticket-based add/rotate flows, and the "any active device can revoke any device" model are implemented consistently with `spec/cla-protocol-v1.md` §2/§6.
- Every device-management route (`add`, `rotate`, `revoke`) correctly sequences challenge-consumption before/with signature verification — the broken ordering (C1) was isolated to `/v1/auth/verify`, making it a contained fix rather than a systemic pattern.
- The hash chain's tamper-evidence property held up under direct testing: an attempt to backdate a stored event's `timestamp` (during test-writing, to simulate elapsed time) broke `verifyChain` immediately, exactly as the design intends — `timestamp` is part of what's hashed into `entry_hash`, so rewriting history after the fact is self-defeating.

---

## Suggested next steps, in order

1. ~~Fix M1–M4~~ 🟢 done, plus the cloned-authenticator gap found along the way. 36 tests passing across all packages; the M4 concurrency regression test run 5x clean.
2. ~~Add per-account and per-IP rate limiting~~ 🟡 done (H3's rate-limiting half; owner notification on recovery-start is still open — needs an actual email/push channel this reference server doesn't have). 42 tests passing.
3. Implement session issuance for `/v1/auth/verify` (`session_token` is in the spec's endpoint table but not implemented), then gate H1/H2 behind it. Next up.
4. A basic fuzz pass on request bodies (oversized payloads, deeply nested objects, unicode edge cases) beyond the type-confusion case M3's fix specifically targets — `isValidId` is narrow by design, not a full schema validator.
5. Recovery owner-notification (the open half of H3) and a shared rate-limit store for multi-instance deployments (the open half of both H3 and the in-memory limitation noted in H1/H2 below).
