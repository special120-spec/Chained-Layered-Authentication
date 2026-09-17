import { generateKeyPairSync, createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export interface ServerKeys {
  keyId: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

/**
 * Loads the server's Ed25519 signing key from disk, generating one on first
 * run. This key signs every chain entry hash (spec §3/§4) — losing it means
 * old receipts can no longer be verified, and rotating it should mint a new
 * `keyId` rather than overwrite silently.
 */
export function loadOrCreateServerKeys(path: string): ServerKeys {
  mkdirSync(dirname(path), { recursive: true });

  if (existsSync(path)) {
    const stored = JSON.parse(readFileSync(path, "utf8")) as { keyId: string; privateKeyPem: string };
    const privateKey = createPrivateKey(stored.privateKeyPem);
    const publicKey = createPublicKey(privateKey);
    return { keyId: stored.keyId, privateKey, publicKey };
  }

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const keyId = `k_${Date.now().toString(36)}`;
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  writeFileSync(path, JSON.stringify({ keyId, privateKeyPem }, null, 2));
  return { keyId, privateKey, publicKey };
}
