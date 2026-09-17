import { sign as cryptoSign, verify as cryptoVerify, type KeyObject } from "node:crypto";

/**
 * Node-only: signs/verifies the server's Ed25519 signature over a chain
 * entry hash. Deliberately kept out of the main `@cla/core` barrel (see
 * chain.ts) so importing `@cla/core` from a browser bundle never pulls in
 * `node:crypto`. Import this from `@cla/core/server-signing` — only the
 * reference server (or another server-side implementation) should need it.
 */
export function signEntryHash(entryHash: string, serverPrivateKey: KeyObject): string {
  return cryptoSign(null, Buffer.from(entryHash, "hex"), serverPrivateKey).toString("hex");
}

export function verifyEntryHashSignature(
  entryHash: string,
  signatureHex: string,
  serverPublicKey: KeyObject
): boolean {
  try {
    return cryptoVerify(
      null,
      Buffer.from(entryHash, "hex"),
      serverPublicKey,
      Buffer.from(signatureHex, "hex")
    );
  } catch {
    return false;
  }
}
