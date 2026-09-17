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

### H3 — 🔴 `/v1/account/recovery/start` has no rate limiting or owner notification
**File:** `packages/reference-server/src/routes/account.ts`

Requiring no signature here is a documented, structurally necessary trade-off (§7 of the design doc) — that part is not the finding. The finding is that nothing else bounds it: anyone who knows `account_id` can force `RECOVERY` on demand, repeatedly, forever, with no side channel warning the real owner.

**Recommendation:** rate-limit per `account_id` and per source IP; fire a notification (email/push) to the account's registered contact whenever recovery is requested, so the legitimate owner has a chance to notice and react to unsolicited attempts.

---

## Medium — implementation hygiene (open)

### M1 — 🔴 Timing side-channel on the admin token
**File:** `packages/reference-server/src/routes/account.ts`

```ts
if (admin_token !== process.env.CLA_ADMIN_TOKEN) { ... }
```

Non-constant-time string comparison. **Fix:** use `crypto.timingSafeEqual` on fixed-length buffers (hash or pad both sides first, since it requires equal-length inputs).

### M2 — 🔴 Server signing key written world-readable
**File:** `packages/reference-server/src/keys.ts`

`writeFileSync(path, ...)` sets no explicit file mode, so the Ed25519 private key lands at the process umask default (commonly `0644`). **Fix:** `writeFileSync(path, data, { mode: 0o600 })`.

### M3 — 🔴 Unhandled promise rejections can crash the whole server
**Files:** all of `packages/reference-server/src/routes/*.ts`, `app.ts`

Every route is `async (req, res) => {...}` with no wrapping try/catch outside the WebAuthn calls. A malformed request body (e.g. `account_id` as an object/array) throws synchronously inside `better-sqlite3`'s `.run()`/`.get()`. Express 4 does **not** catch rejections thrown from async handlers, and Node has terminated on unhandled rejections by default since v15 — one malformed request can take down every account's auth.

**Fix:** upgrade to Express 5 (catches these natively), or wrap every handler in an `asyncHandler` helper that forwards to `next(err)` plus a real error-handling middleware in `app.ts`; add request body schema validation (e.g. zod) so malformed types never reach the DB layer.

### M4 — 🔴 `chainStore.append`'s read-then-write isn't transactional
**File:** `packages/reference-server/src/chainStore.ts`

`nextSeq()` and `lastHash()` are read, then an `INSERT` happens, with no transaction wrapping the sequence. Two concurrent requests for the same account can both read the same `maxSeq`/last hash; the `(account_id, seq)` primary key will reject the second `INSERT`, but there's no retry — the caller just gets an unhandled 500 (see M3).

**Fix:** wrap `append` in a `better-sqlite3` transaction (`db.transaction(...)`).

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

1. Implement session issuance for `/v1/auth/verify` (`session_token` is in the spec's endpoint table but not implemented), then gate H1/H2 behind it.
2. Add per-account and per-IP rate limiting at the app level (H3, and defense-in-depth for C1/C2).
3. Fix M1–M4 (small, independent, low-risk changes).
4. Re-run the full test suite plus a basic fuzz pass on request bodies (malformed types, missing fields, oversized payloads) to confirm M3 is actually closed before considering this production-ready.
