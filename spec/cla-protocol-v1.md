# CLA Protocol v1

Status: draft. This is the versioned, implementable subset of the design doc.
Changes to this file should go through review distinct from ordinary SDK/server
bug fixes (see the repo's `README.md` on governance).

**v1.1**: adds multi-device support (§2, §6). No breaking changes to the
chain format or lock-state derivation — existing v1 chains remain valid;
`REGISTER` is now emitted only for an account's first device, with
subsequent devices emitting `DEVICE_ADD` (§3).

**v1.2**: session issuance and rate limiting (§6, §6a), closing findings
H1-H3 from a security review — `session_token` is now actually issued
(previously specced but not implemented) and required on the two
read endpoints that expose per-account data. No chain/event-format
changes.

**v1.3**: optional TOTP (authenticator-app codes) as a second factor
(§6b) — never a replacement for a WebAuthn device, which is still
required to enroll or remove it. Two new chain event types,
`TOTP_ENROLLED`/`TOTP_DISABLED` (§3). TOTP can complete a `step_up`
and can optionally gate `/v1/account/recovery/start` for accounts that
enroll it, narrowing H3 further for those accounts; it changes nothing
for accounts that don't enroll.

## 1. Scope

This spec defines: the device identity model, the challenge-response
ceremony (delegated to WebAuthn), the chain event format and hashing rule,
the client receipt format, and the lock-state derivation function. It does
**not** define a wire format for threshold signatures or external chain
anchoring — those are out of scope for v1 (see design doc §D.2, §F).

## 2. Identity

- Each device holds one WebAuthn credential (Ed25519 or ES256, per platform
  authenticator support). The server stores `{device_id, account_id,
  public_key, sign_count, status, created_at}`. `status` is one of
  `active | revoked`.
- An account may have **any number of active devices** simultaneously, plus
  zero or more `revoked` devices kept for audit history. The *first* device
  an account registers requires no proof (that's the bootstrap case — there's
  nothing yet to prove possession of); every device added after that must be
  authorized by an assertion from an *existing* active device (§6,
  `/v1/devices/add/*`) — never by re-running the bootstrap flow.
- Any active device may authorize revoking any other device on the same
  account (§6, `/v1/devices/revoke`) — "use my laptop to kill my lost phone."
  A device may also revoke itself. Revoking the last remaining active device
  is allowed and is exactly the state recovery (§7 of the design doc) exists
  to recover from.
- Auth and step-up challenges list every active device as an allowed
  credential (`allowCredentials`); the platform picks which one the user
  actually signs with, and the server resolves *which* device authenticated
  from the credential id in the assertion response — it no longer assumes
  there is only one possible signer.

## 3. Chain events

Every event is a JSON object, canonicalized (JCS-style: sorted object keys,
no insignificant whitespace) before hashing:

```ts
type ChainEvent = {
  seq: number;            // 0-indexed, strictly increasing per account
  account_id: string;
  device_id: string | null;   // null for account-level events (e.g. RECOVERY_START)
  type: "REGISTER" | "DEVICE_ADD" | "SUCCESS" | "FAILURE" | "LOCK" | "UNLOCK"
      | "STEP_UP_OK" | "REVOKE" | "ROTATE" | "RECOVERY_START" | "RECOVERY_COMPLETE"
      | "TOTP_ENROLLED" | "TOTP_DISABLED";
  layer_before: Layer;
  layer_after: Layer;
  timestamp: string;       // ISO 8601 UTC
  detail?: Record<string, unknown>; // e.g. { reason: "bad_signature" }, or { method: "totp" } on a TOTP-based SUCCESS/FAILURE/STEP_UP_OK
};

type Layer = "NORMAL" | "LOCK" | "STEP_UP" | "RECOVERY";
```

Hash chain:

```
entry_hash[0]   = SHA256(canonical(event[0]))
entry_hash[n]   = SHA256(entry_hash[n-1] || canonical(event[n]))
```

The server additionally signs `entry_hash[n]` with its own Ed25519 key
(`server_sig[n]`), binding the server to that position in the chain.

## 4. Client receipts

After every request that appends an event, the server returns:

```ts
type Receipt = {
  seq: number;
  entry_hash: string;   // hex
  server_sig: string;   // hex, over entry_hash
  server_key_id: string;
};
```

The client SDK caches the receipt with the *highest `seq` it has seen* per
account. Before trusting a fetched audit log, the SDK recomputes the chain
forward from any point and confirms it passes through every receipt it has
cached. A chain that doesn't reproduce a previously cached `(seq, entry_hash)`
has been tampered with since that receipt was issued — this is the entire
tamper-evidence property this protocol provides, and it only holds for
clients that keep their receipts (design doc §F).

## 5. Lock-state derivation

The current layer is **never** stored directly — it's computed by replaying
an account's events:

```
layer(events) = fold over events, starting at NORMAL, applying:
  SUCCESS while layer == NORMAL        -> NORMAL
  FAILURE                              -> layer.next() capped at RECOVERY,
                                           subject to the policy window (below)
  UNLOCK / STEP_UP_OK                  -> layer.prev() (one step, never to
                                           below NORMAL, never skips STEP_UP
                                           on the way down from RECOVERY)
  RECOVERY_COMPLETE                    -> NORMAL
  RECOVERY_START                       -> RECOVERY (user-initiated, does not
                                           require prior failures)
```

Policy window (v1 default, configurable): `NORMAL -> LOCK` after 3 failures
in 15 minutes; `LOCK -> STEP_UP` after 5 more failures while in `LOCK`;
`STEP_UP -> RECOVERY` after 3 more failures while in `STEP_UP`. A `LOCK`
event carries an exponential cooldown (`detail.cooldown_seconds`) that gates
*when* a new attempt is accepted, but never blocks a structurally different
proof (a step-up attempt) from being *initiated* — see design doc §H/§I on
why an unconditional block is a denial-of-service vector.

## 6. Endpoints

See design doc §L for the full surface and rationale. Request/response
bodies are JSON; all mutating endpoints return the resulting `Receipt` and
current `layer`.

**Sessions.** Every endpoint that just verified a real WebAuthn ceremony
(`register/finish`, `add/finish`, `rotate/finish`, `auth/verify`) returns a
`session_token`: a short-lived (30 min), server-issued opaque token scoped
to the account that just proved possession. `GET /v1/devices` and
`GET /v1/account/:id/audit-log` require it as `Authorization: Bearer
<session_token>` — a token only grants access to the account it was issued
for, checked server-side; presenting one for a different account gets
`403`, not the other account's data (security review H1/H2). There is no
refresh mechanism in v1: re-authenticate for a new one once one expires.

```
POST /v1/devices/register/start      { account_id }                      // bootstrap only: 409 if the
                                      -> { challenge, rp, user, pubKeyCredParams }   // account already has an active device
POST /v1/devices/register/finish     { account_id, attestationResponse }
                                      -> { device_id, receipt, layer, session_token }

POST /v1/devices/add/challenge       { account_id }                      // 404 if no active device exists yet
                                      -> { challenge, allowCredentials }          // (use register/start instead)
POST /v1/devices/add/start           { account_id, assertionResponse }   // proves possession of an existing device
                                      -> { add_ticket, registerOptions }
POST /v1/devices/add/finish          { account_id, add_ticket, attestationResponse }
                                      -> { device_id, receipt, layer, session_token }  // old device(s) stay active

GET  /v1/devices                     ?account_id=...                     // requires Authorization: Bearer <session_token>
                                      -> { devices: [{ device_id, created_at, status }] }

POST /v1/auth/challenge              { account_id, purpose? }            // allowCredentials = every active device
                                      -> { challenge, allowCredentials }
POST /v1/auth/verify                 { account_id, assertionResponse, purpose? }
                                      -> { session_token, receipt, layer, device_id }   // signer resolved from the assertion's credential id

POST /v1/devices/rotate/challenge    { account_id, device_id }           // rotate is still self-rotation:
                                      -> { challenge }                          // the device being replaced proves itself
POST /v1/devices/rotate/start        { account_id, device_id, assertionResponse }
                                      -> { rotation_ticket, registerOptions }
POST /v1/devices/rotate/finish       { account_id, rotation_ticket, attestationResponse }
                                      -> { device_id, receipt, layer, session_token }

POST /v1/devices/revoke/challenge    { account_id }                      // any active device may sign this
                                      -> { challenge }
POST /v1/devices/revoke              { account_id, device_id, assertionResponse } // device_id = the TARGET to revoke;
                                      -> { receipt, layer }                        // the signer may be a different device

POST /v1/account/recovery/start      { account_id }                      // rate-limited: 3/hour/account
                                      -> { receipt, layer }               // human-mediated from here (v1)
POST /v1/account/recovery/complete   { account_id, admin_token }          // placeholder for support flow; rate-limited:
                                      -> { receipt, layer }               // 10/hour/account and 10/hour/IP
GET  /v1/account/:id/audit-log       // requires Authorization: Bearer <session_token>
                                      -> { events: ChainEvent[], receipts: Receipt[] }
```

## 6a. Rate limiting

Layered, not a single global rule (security review H3):

- A general 120/min/IP backstop across all of `/v1/*`.
- 30/min/account on `/v1/auth/challenge` and `/v1/auth/verify` — defense in
  depth for the fact that calling `/challenge` is, by necessity, free and
  unauthenticated; this bounds how fast the two-round-trip path to a
  `FAILURE` can be walked regardless of source IP.
- `/v1/account/recovery/start`: 3/hour/account.
- `/v1/account/recovery/complete`: 10/hour/account and 10/hour/IP.

The reference server's limiter is in-memory and per-process — correct for
a single instance, not sufficient on its own for a horizontally-scaled
deployment (which would need a shared store).

## 6b. TOTP (optional second factor)

Standard RFC 4226/6238 (HOTP/TOTP), SHA-1, 6 digits, 30s step, ±1 step
clock-skew window — the parameters every authenticator app assumes.
Strictly opt-in and strictly secondary:

- **Enrolling or disabling TOTP requires proving possession of an
  existing active device first** — the same bar as `/v1/devices/add`.
  TOTP can never bootstrap an account; it can only be attached to one
  that already has a working WebAuthn device.
- **TOTP can only complete a `purpose: "step_up"` request, never
  `"auth"`.** Enforced server-side, not just documented.
- **A wrong TOTP code counts as a chain `FAILURE`**, against the exact
  same lock ladder and cooldown a wrong WebAuthn signature would — no
  parallel failure-counting mechanism to dodge.
- **The shared secret is encrypted at rest** (AES-256-GCM, its own key
  file separate from the Ed25519 signing key — see design doc §J on why
  a confidentiality key and an authenticity key shouldn't share a blast
  radius).
- **Replay is prevented**: each account's active secret tracks the
  highest time-step ever accepted; a numerically-correct code for an
  already-consumed step is rejected.

```
POST /v1/totp/enroll/challenge   { account_id }
                                  -> { challenge, allowCredentials }        // proves an existing device first
POST /v1/totp/enroll/start       { account_id, assertionResponse }
                                  -> { enroll_ticket, secret_base32, provisioning_uri, digits, period }
POST /v1/totp/enroll/finish      { account_id, enroll_ticket, code }       // confirms the user's app is actually programmed
                                  -> { receipt, layer }                     // emits TOTP_ENROLLED

POST /v1/totp/verify             { account_id, code, purpose: "step_up" }  // "auth" is rejected with 400
                                  -> { receipt, layer }

POST /v1/totp/disable/challenge  { account_id }
                                  -> { challenge, allowCredentials }
POST /v1/totp/disable            { account_id, assertionResponse }
                                  -> { receipt, layer }                     // emits TOTP_DISABLED
```

**Optional recovery gate**: if an account has TOTP enrolled,
`POST /v1/account/recovery/start` additionally requires a valid `code`
in the request body — a wrong or missing code is a `400`/`401` (and a
real code failure counts as a chain `FAILURE`, throttled the same as
everything else). Accounts that never enroll TOTP see no change to
`recovery/start`'s existing zero-friction, rate-limited-only behavior —
this narrows H3 for accounts that opt in, it does not change the
baseline for accounts that don't (see design doc §I on why the
zero-proof path is structurally necessary, not a bug).

## 6c. Session introspection (for a relying-party backend)

```
POST /v1/session/introspect   { session_token }
                               -> { active: true, account_id, device_id, expires_at }
                               -> { active: false }   // unknown, malformed, or expired token — same response for all three
```

RFC 7662-style (`active` boolean), server-to-server only — nothing a
browser needs beyond what the `Authorization: Bearer` gate on
`GET /v1/devices` and `GET /v1/account/:id/audit-log` already provides.
Exists specifically for a relying-party backend written in a different
language/process than this reference server (e.g. a platform's own API
in Go, Python, etc.) that needs to know "is this session still valid,
and for which account" without sharing this server's session store
directly. Requires possessing the token to learn anything about it —
same trust boundary as using the token, just phrased as a lookup.

## 7. Non-goals for v1.1

Threshold/M-of-N signing, external transparency-log anchoring, self-service
recovery keys, the six-layer ladder. (Multi-device shipped in v1.1 — see the
changelog note at the top of this file.) See design doc §K.
