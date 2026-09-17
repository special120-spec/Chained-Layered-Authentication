# Security policy

## Status

This project is a pre-1.0 MVP and **has not had an independent security
review**. Treat everything here as a design in progress, not a hardened
system. Do not deploy it for real accounts.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Instead,
email the maintainers privately (address to be added before public release)
with:

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- Which component it affects (`core`, `reference-server`, `sdk-js`).

We'll acknowledge within 5 business days.

## What is explicitly in scope

- Forging a valid authentication without a legitimate device's private key.
- Bypassing revocation (a revoked device's signature still being accepted).
- Replaying a previously-used challenge.
- Tampering with the chain undetected **by a client holding a valid prior
  receipt** (this is the property the chain is supposed to guarantee — a
  break here is a real bug).
- Forcing an account into `RECOVERY` or a deep lock layer without any valid
  signature from an enrolled device (the lockout-as-DoS failure mode).

## What is a known, documented limitation — not a new finding

- **A fully compromised reference-server operator can fabricate `FAILURE`
  events and drive a legitimate account into `RECOVERY`.** The chain proves
  order and completeness of recorded history to a client holding an external
  anchor or prior receipt; it does not prove the *truth* of a server-authored
  event that requires no client signature. Closing this needs external
  transparency-log anchoring, which is explicitly out of scope for the MVP.
  See the design doc, §F and §H.
- **Recovery is human/support-mediated in the MVP** and is therefore only as
  strong as that process — this is a known, structural weak point common to
  every possession-based auth system, not specific to this implementation.
- Reports of either of the above as if they were novel findings will be
  answered by pointing back to this file, not treated as new disclosures —
  but a concrete way to actually exploit either against a *client that has a
  valid receipt/anchor* is still very much wanted.
