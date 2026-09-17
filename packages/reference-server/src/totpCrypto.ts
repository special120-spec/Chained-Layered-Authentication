import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * A symmetric AES-256-GCM key used ONLY to encrypt TOTP shared secrets at
 * rest. Deliberately a separate file/key from keys.ts's Ed25519 signing
 * key: that key's job is authenticity (signing hashes, safe to have its
 * public half known to everyone), this key's job is confidentiality. A
 * TOTP secret is a genuine shared secret — unlike a WebAuthn public key,
 * anyone who reads it can mint valid codes forever, so it must never be
 * stored in the clear, and the key that protects it deserves its own
 * blast radius if either key is ever compromised.
 */
export function loadOrCreateTotpEncryptionKey(path: string): Buffer {
  mkdirSync(dirname(path), { recursive: true });

  if (existsSync(path)) {
    const stored = JSON.parse(readFileSync(path, "utf8")) as { keyBase64: string };
    return Buffer.from(stored.keyBase64, "base64");
  }

  const key = randomBytes(32); // AES-256
  // mode 0o600 — same reasoning as keys.ts: a secret-key file must never be
  // left at the process umask default.
  writeFileSync(path, JSON.stringify({ keyBase64: key.toString("base64") }, null, 2), { mode: 0o600 });
  return key;
}

const IV_LENGTH = 12; // GCM's recommended nonce length
const TAG_LENGTH = 16;

/** Encrypts a TOTP secret for storage. Output encoding: base64(iv || authTag || ciphertext). */
export function encryptTotpSecret(secret: Uint8Array, key: Buffer): string {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString("base64");
}

/** Inverse of encryptTotpSecret. Throws if `key` is wrong or `stored` was tampered with (GCM's auth tag check fails closed). */
export function decryptTotpSecret(stored: string, key: Buffer): Uint8Array {
  const raw = Buffer.from(stored, "base64");
  const iv = raw.subarray(0, IV_LENGTH);
  const tag = raw.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ciphertext = raw.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
}
