# CLA Protocol v1

Status: draft. This is the versioned, implementable subset of the design doc.
Changes to this file should go through review distinct from ordinary SDK/server
bug fixes (see the repo's `README.md` on governance).

**v1.1**: adds multi-device support (§2, §6). No breaking changes to the
chain format or lock-state derivation — existing v1 chains remain valid;
`REGISTER` is now emitted only for an account's first device, with
subsequent devices emitting `DEVICE_ADD` (§3).

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
      | "STEP_UP_OK" | "REVOKE" | "ROTATE" | "RECOVERY_START" | "RECOVERY_COMPLETE";
  layer_before: Layer;
  layer_after: Layer;
  timestamp: string;       // ISO 8601 UTC
  detail?: Record<string, unknown>; // e.g. { reason: "bad_signature" }
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

```
POST /v1/devices/register/start      { account_id }                      // bootstrap only: 409 if the
                                      -> { challenge, rp, user, pubKeyCredParams }   // account already has an active device
POST /v1/devices/register/finish     { account_id, attestationResponse }
                                      -> { device_id, receipt, layer }

POST /v1/devices/add/challenge       { account_id }                      // 404 if no active device exists yet
                                      -> { challenge, allowCredentials }          // (use register/start instead)
POST /v1/devices/add/start           { account_id, assertionResponse }   // proves possession of an existing device
                                      -> { add_ticket, registerOptions }
POST /v1/devices/add/finish          { account_id, add_ticket, attestationResponse }
                                      -> { device_id, receipt, layer }          // old device(s) stay active

GET  /v1/devices                     ?account_id=...
                                      -> { devices: [{ device_id, created_at, status }] }

POST /v1/auth/challenge              { account_id, purpose? }            // allowCredentials = every active device
                                      -> { challenge, allowCredentials }
POST /v1/auth/verify                 { account_id, assertionResponse, purpose? }
                                      -> { session_token?, receipt, layer }   // signer resolved from the assertion's credential id

POST /v1/devices/rotate/challenge    { account_id, device_id }           // rotate is still self-rotation:
                                      -> { challenge }                          // the device being replaced proves itself
POST /v1/devices/rotate/start        { account_id, device_id, assertionResponse }
                                      -> { rotation_ticket, registerOptions }
POST /v1/devices/rotate/finish       { account_id, rotation_ticket, attestationResponse }
                                      -> { device_id, receipt, layer }

POST /v1/devices/revoke/challenge    { account_id }                      // any active device may sign this
                                      -> { challenge }
POST /v1/devices/revoke              { account_id, device_id, assertionResponse } // device_id = the TARGET to revoke;
                                      -> { receipt, layer }                        // the signer may be a different device

POST /v1/account/recovery/start      { account_id }
                                      -> { receipt, layer }               // human-mediated from here (v1)
POST /v1/account/recovery/complete   { account_id, admin_token }          // placeholder for support flow
                                      -> { receipt, layer }
GET  /v1/account/:id/audit-log       -> { events: ChainEvent[], receipts: Receipt[] }
```

## 7. Non-goals for v1.1

Threshold/M-of-N signing, external transparency-log anchoring, self-service
recovery keys, the six-layer ladder. (Multi-device shipped in v1.1 — see the
changelog note at the top of this file.) See design doc §K.
