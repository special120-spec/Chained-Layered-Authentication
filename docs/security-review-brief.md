# CLA security review brief

For whoever (or whatever AI reviewer) is reassessing this codebase. Written by
the person/model that built it — treat the "already known" section as a
starting hypothesis to verify, not as settled fact.

## 1. What this is

Chained Layered Authentication (CLA): WebAuthn-based possession auth, a
hash-chained/server-signed audit log with client-held receipts, and a
`NORMAL -> LOCK -> STEP_UP -> RECOVERY` lockout ladder derived by replaying
that log. Full design rationale: `spec/cla-protocol-v1.md` (implementable
spec) — read this first, it defines what each mechanism is supposed to
guarantee and, just as importantly, what it explicitly does *not* guarantee.

## 2. Scope

Review these, in priority order:

1. `packages/reference-server/src/**` — the security-critical surface. Every
   endpoint, every DB query, every WebAuthn verification call.
2. `packages/core/src/**` — chain hashing, lock-state transitions, policy
   engine. Pure logic, no I/O, but the correctness of the whole tamper-
   evidence claim rests here.
3. `packages/sdk-js/src/**` — lower priority. Client-side convenience only;
   nothing here is a trust boundary (a malicious client can already do
   anything a modified SDK could do).
4. `examples/demo/**` — lowest priority, demo-only code, not meant to be
   deployed as-is.

Current state: commit `478d826` on `main`
(https://github.com/special120-spec/Chained-Layered-Authentication),
branch pushed, 31 automated tests passing. Not yet independently reviewed —
this would be the first pass.

## 3. Threat model (assume these attacker capabilities)

See `spec` / design doc §B for the full version; summarized:

- **Network attacker**: can observe/inject/replay traffic, no endpoint access.
- **Malicious or compromised server operator**: full DB read/write, control
  of server logic. Can fabricate events that don't require a client
  signature (documented as a known limitation — see §4).
- **Stolen/compromised device**: has one enrolled device's key material.
- **Credential-stuffing / brute-force attacker**: only has the public API.
- **Social engineer**: targets the human-mediated recovery path.

## 4. Already acknowledged — verify, don't just re-report

These are documented in `SECURITY.md` with stated rationale. Useful findings
here are ones that show the rationale is *wrong*, not ones that restate it:

- A fully compromised server operator can fabricate `FAILURE` events and
  drive an account into `RECOVERY` (no external chain anchoring in v1).
- Recovery is human/support-mediated; `admin_token` is an explicit
  placeholder for "a support agent verified this identity out of band," not
  a real identity-verification system.
- The server's Ed25519 signing key sits in a plaintext file
  (`.data/server-key.json`), fine for local dev, not for production key
  custody.

## 5. Priority areas to actually probe

Not yet documented as known issues — treat these as open questions, not
confirmed bugs, except #1 and #2 which I'm fairly confident are real:

1. **Signature-counter clone/replay detection** — `routes/auth.ts`,
   the `sign_count` update after a successful assertion. WebAuthn's counter
   exists to detect cloned authenticators (if the reported counter isn't
   strictly greater than what's stored, that's a signal of duplication).
   Check whether this is enforced anywhere. (I believe it currently is not.)
2. **Admin-token brute-force / timing** — `routes/account.ts`,
   `/recovery/complete`. Check: (a) is the comparison constant-time, (b) is
   there any rate limit or lockout on repeated wrong tokens, independent of
   the account's own lock ladder (which only gates `/v1/auth/verify`).
3. **Cross-account credential confusion** — can a credential/assertion
   crafted around one account's device ever be accepted against a
   *different* account_id? Check every query that resolves a device by
   credential id for correct account scoping (`deviceHelpers.ts`).
4. **Ticket/challenge lifecycle** — rotation tickets, add-device tickets,
   and WebAuthn challenges are all single-use with a 5-minute expiry
   (`consumeChallenge`, `rotation_tickets`, `add_tickets` tables). Verify the
   consume-then-check isn't racy (concurrent requests reusing one challenge
   before it's marked used) and that expiry is enforced consistently.
5. **CORS / origin configuration** — `app.ts` and `webauthn.ts`; confirm the
   `expectedOrigin`/`expectedRPID` values can't be satisfied by an
   attacker-controlled origin in any deployment-realistic misconfiguration.
6. **Rate limiting (or the total lack of it)** — nothing throttles raw
   request volume at the network layer; only the per-account lock ladder
   exists. Assess realistic DoS/resource-exhaustion exposure, and whether
   the lock ladder itself remains attacker-usable as a DoS tool against a
   specific known account_id (design intent is that it shouldn't fully seal
   out a legitimate owner, but confirm no path lets it be used to hurt one).
7. **SQL injection / input validation** — all queries use `better-sqlite3`
   prepared statements; confirm there's no string concatenation anywhere,
   and that unbounded `account_id`/`device_id` input can't cause resource
   issues (no length/charset validation currently exists).
8. **Information leakage via error responses** — check that failure
   responses across all endpoints don't distinguish "account doesn't exist"
   from "wrong device" from "bad signature" in ways that enable account
   enumeration.
9. **Chain/receipt verification correctness** — `packages/core/src/chain.ts`
   and the SDK's `verifyAuditLog`. Confirm the tamper-evidence property
   actually holds under test: a modified historical event should be
   undetectable by `verifyChain` alone but detectable once a prior receipt
   is supplied (there's already a test for this — try to break it further,
   e.g. can an attacker forge a *receipt* itself, not just chain data?).
10. **WebAuthn library usage correctness** — `@simplewebauthn/server` v14 is
    pinned; confirm `attestationType: "none"`, `userVerification: "preferred"`
    and the lack of attestation checking are acceptable for the stated
    threat model, not accidental weakenings.

## 6. Out of scope for this pass

- `@simplewebauthn/server` and `@simplewebauthn/browser` internals — treat
  as trusted, already-audited upstream dependencies (report only misuse of
  their API, not their own cryptography).
- Node.js / npm dependency supply-chain audit — separate exercise
  (`npm audit` currently shows unresolved moderate-severity dev-tooling
  findings in vite/vitest; not shipped to production, tracked separately).
- Anything under `examples/demo` being "insecure by design" for demo
  convenience (e.g. the `simulateFailures` bypass) — that's intentional and
  documented in-code, not a finding.

## 7. Reporting format

Please structure findings as: **what's exploitable, exact preconditions,
concrete impact, and which file/line**. Sort by exploitability against the
threat model in §3, not by theoretical severity — a real gap that only
matters if the server operator is already malicious is real but lower
priority than one exploitable by an anonymous network attacker.
