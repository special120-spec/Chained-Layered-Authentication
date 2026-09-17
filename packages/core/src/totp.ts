/**
 * RFC 4226 (HOTP) / RFC 6238 (TOTP), implemented against the Web Crypto API
 * for the same reason chain.ts is: this file has to stay usable in a
 * browser bundle (no `Buffer`, no `node:crypto`) even though today only the
 * reference server actually calls it — a deployment that wants to compute
 * or verify codes client-side shouldn't need a second implementation.
 *
 * PURE LOGIC ONLY. This module has no opinion about how a secret is stored,
 * encrypted at rest, or how replay of an already-used code is prevented —
 * those are I/O concerns and belong in the reference server (see
 * reference-server/src/totpStore.ts). Concretely: `verifyTotp` returns the
 * matched time-step number rather than a bare boolean specifically so a
 * caller can enforce "never accept a step at or before the last one we
 * accepted" — without that bookkeeping, a code sniffed once stays valid for
 * its whole acceptance window and can be replayed.
 */

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Encodes raw bytes as unpadded RFC 4648 base32 — the format authenticator apps expect for manual entry. */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/** Decodes RFC 4648 base32 back to raw bytes. Case-insensitive; ignores '=' padding and stray characters. */
export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, "");
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

/** A cryptographically random shared secret, 20 bytes (160 bits) by default per RFC 4226 §4's recommendation. */
export function generateTotpSecret(byteLength = 20): Uint8Array {
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/** 8-byte big-endian counter per RFC 4226 §5.2. Safe for any realistic TOTP usage (30s steps don't exhaust this for ~10^9 years). */
function counterToBytes(counter: number): Uint8Array<ArrayBuffer> {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  const high = Math.floor(counter / 2 ** 32);
  const low = counter >>> 0;
  view.setUint32(0, high);
  view.setUint32(4, low);
  // Uint8Array.from (rather than `new Uint8Array(buf)`) guarantees a plain
  // ArrayBuffer-backed array — Web Crypto's BufferSource type wants
  // ArrayBufferView<ArrayBuffer> specifically, not the wider ArrayBufferLike
  // that a view over `buf` alone can carry under TS's DOM lib typings.
  return Uint8Array.from(new Uint8Array(buf));
}

/** RFC 4226 HOTP: HMAC-SHA1 over the counter, dynamically truncated to `digits` decimal digits. */
export async function hotp(secret: Uint8Array, counter: number, digits = 6): Promise<string> {
  const keyBytes: Uint8Array<ArrayBuffer> = Uint8Array.from(secret);
  const key = await globalThis.crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, [
    "sign",
  ]);
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, counterToBytes(counter)));
  const offset = mac[mac.length - 1] & 0x0f;
  const binCode =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return (binCode % 10 ** digits).toString().padStart(digits, "0");
}

export interface TotpParams {
  stepSeconds?: number;
  digits?: number;
}

function timeStepFor(forTimeMs: number, stepSeconds: number): number {
  return Math.floor(forTimeMs / 1000 / stepSeconds);
}

/** RFC 6238 TOTP: HOTP keyed by the current time step. */
export async function totp(secret: Uint8Array, forTimeMs: number, params: TotpParams = {}): Promise<string> {
  const { stepSeconds = 30, digits = 6 } = params;
  return hotp(secret, timeStepFor(forTimeMs, stepSeconds), digits);
}

/** Best-effort constant-time string comparison — mitigates the obvious early-exit timing leak of `===`, not a cryptographic guarantee against a JS engine's own optimizations. */
function timingSafeEqualStrings(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Checks `code` against a small window of adjacent time steps (default ±1,
 * i.e. ~30s of clock skew each way) and returns the MATCHED STEP NUMBER on
 * success, or `null` on failure. See the module doc comment: callers MUST
 * track the highest step ever accepted per secret and reject any step
 * <= that value themselves — this function does not, since that's I/O.
 */
export async function verifyTotp(
  secret: Uint8Array,
  code: string,
  forTimeMs: number,
  params: TotpParams & { window?: number } = {}
): Promise<number | null> {
  const { stepSeconds = 30, digits = 6, window = 1 } = params;
  const normalizedCode = code.trim();
  if (!/^\d+$/.test(normalizedCode) || normalizedCode.length !== digits) return null;

  const currentStep = timeStepFor(forTimeMs, stepSeconds);
  for (let delta = -window; delta <= window; delta++) {
    const step = currentStep + delta;
    if (step < 0) continue;
    const candidate = await hotp(secret, step, digits);
    if (timingSafeEqualStrings(candidate, normalizedCode)) return step;
  }
  return null;
}

/** Builds an `otpauth://` provisioning URI for QR-code enrollment in an authenticator app (Google Authenticator, 1Password, Authy, etc). */
export function buildProvisioningUri(params: {
  secret: Uint8Array;
  accountLabel: string;
  issuer: string;
  digits?: number;
  stepSeconds?: number;
}): string {
  const { secret, accountLabel, issuer, digits = 6, stepSeconds = 30 } = params;
  const label = encodeURIComponent(`${issuer}:${accountLabel}`);
  const query = new URLSearchParams({
    secret: base32Encode(secret),
    issuer,
    algorithm: "SHA1",
    digits: String(digits),
    period: String(stepSeconds),
  });
  return `otpauth://totp/${label}?${query.toString()}`;
}
