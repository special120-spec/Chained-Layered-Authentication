# Chained Layered Authentication (CLA)

WebAuthn-grade, possession-based authentication with a tamper-evident audit
chain and an honest, non-DoS-able progressive lockout ladder — built entirely
on established primitives (WebAuthn/FIDO2, Ed25519, SHA-256). No new
cryptography. See [`spec/cla-protocol-v1.md`](spec/cla-protocol-v1.md) for the
protocol and the full design rationale.

**Status: MVP / pre-1.0. Not yet independently security-reviewed. Do not use
in production.** See [`SECURITY.md`](SECURITY.md).

## What this is

Three separable pieces, on purpose (mixing them up is the most common way
systems like this end up over-claiming their own strength):

1. **Identity** — WebAuthn challenge-response. A device's private key never
   leaves it; the server only ever sees signatures and public keys.
2. **Chain** — every auth attempt (success or failure) appends a hash-chained,
   server-signed event, and the *client* caches a signed receipt after each
   one. This gives auditability and lets a client detect a server that
   rewrites its own history — it is **not** what makes forgery hard (the
   signature scheme is), and it does **not** protect against a fully
   compromised server unless externally anchored. See spec §5.
3. **Lock ladder** — `NORMAL → LOCK → STEP_UP → RECOVERY`, derived by
   replaying the chain rather than stored as a mutable counter. Any valid
   device signature can always *start* a step-up from any layer — the ladder
   adds friction, it must never fully seal out the legitimate owner (that
   would turn the lockout itself into a denial-of-service tool).

Optional: TOTP (authenticator-app codes) as a second factor — never a
replacement for a WebAuthn device, which is still required to enroll or
remove it. Can complete a step-up, and can optionally gate account recovery
for accounts that enroll it. See spec §6b.

## Packages

| Package | What it is |
|---|---|
| [`packages/core`](packages/core) | The chain, the lock-state machine, and the policy engine. Pure TypeScript, no I/O, most heavily tested. |
| [`packages/reference-server`](packages/reference-server) | Express + SQLite reference implementation of the protocol endpoints. |
| [`packages/sdk-js`](packages/sdk-js) | Browser client: wraps `@simplewebauthn/browser`, caches and verifies chain receipts, exposes a small async API. |
| [`examples/demo`](examples/demo) | A runnable page to register a device, authenticate, trip the lock ladder, and inspect the audit chain. |

## Quick start

```bash
npm install
npm run build
npm run dev:server   # reference server on http://localhost:8787
npm run dev:demo     # demo UI on http://localhost:5173
```

The demo needs a real platform authenticator (Windows Hello, Touch ID, a
security key) — WebAuthn ceremonies can't be faked from a script.

## Design doc

The full first-principles design — threat model, cryptographic architecture,
alternative designs considered, risk analysis, and what's novel vs.
standards-reliant — lives in the project's design doc, not in this repo (link
shared separately). `spec/cla-protocol-v1.md` is the versioned, implementable
subset of it.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
