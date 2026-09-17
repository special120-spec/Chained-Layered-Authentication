# CLA Protocol v1

Status: draft. This is the versioned, implementable subset of the design doc.
Changes to this file should go through review distinct from ordinary SDK/server
bug fixes (see the repo's `README.md` on governance).

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
- v1 supports exactly one *active* device per account at a time, plus zero or
  more `revoked` devices kept for audit history. Multi-device is out of scope
  for v1 (design doc §K).

## 3. Chain events

Every event is a JSON object, canonicalized (JCS-style: sorted object keys,
no insignificant whitespace) before hashing:

```ts
type ChainEvent = {
  seq: number;            // 0-indexed, strictly increasing per account
  account_id: string;
  device_id: string | null;   // null for account-level events (e.g. RECOVERY_START)
  type: "REGISTER" | "SUCCESS" | "FAILURE" | "LOCK" | "UNLOCK"
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
POST /v1/devices/register/start      { account_id }
                                      -> { challenge, rp, user, pubKeyCredParams }
POST /v1/devices/register/finish     { account_id, attestationResponse }
                                      -> { device_id, receipt, layer }
POST /v1/auth/challenge              { account_id }
                                      -> { challenge }
POST /v1/auth/verify                 { account_id, assertionResponse }
                                      -> { session_token?, receipt, layer }
POST /v1/devices/rotate/start        { account_id, assertionResponse }   // proves possession of old device
                                      -> { rotation_ticket, registerChallenge }
POST /v1/devices/rotate/finish       { account_id, rotation_ticket, attestationResponse }
                                      -> { device_id, receipt, layer }
POST /v1/devices/revoke              { account_id, assertionResponse }
                                      -> { receipt, layer }
POST /v1/account/recovery/start      { account_id }
                                      -> { receipt, layer }               // human-mediated from here (v1)
POST /v1/account/recovery/complete   { account_id, admin_token }          // placeholder for support flow
                                      -> { receipt, layer }
GET  /v1/account/:id/audit-log       -> { events: ChainEvent[], receipts: Receipt[] }
```

## 7. Non-goals for v1

Threshold/M-of-N signing, multi-device, external transparency-log anchoring,
self-service recovery keys, the six-layer ladder. See design doc §K.
