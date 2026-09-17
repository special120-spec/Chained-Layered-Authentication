import { createHash, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { canonicalize } from "./chain.js";
import type { ChainEvent } from "./types.js";

/**
 * Node-only: signs/verifies the server's Ed25519 signature over a chain
 * entry hash. Deliberately kept out of the main `@cla/core` barrel (see
 * chain.ts) so importing `@cla/core` from a browser bundle never pulls in
 * `node:crypto`. Import this from `@cla/core/server-signing` — only the
 * reference server (or another server-side implementation) should need it.
 */

/**
 * Synchronous twin of chain.ts's `computeEntryHash` — identical output
 * (same canonicalization, same SHA-256 bytes), computed via `node:crypto`'s
 * synchronous digest instead of the async Web Crypto call the browser-safe
 * version uses. Exists specifically so a server's own append-to-the-chain
 * critical section (read current tip -> hash -> write) contains no `await`
 * between the read and the write: on a single-threaded, single-connection
 * better-sqlite3 setup, that absence of a yield point is what actually
 * makes two concurrent requests for the same account safe, without needing
 * locks or a transaction wrapped around async work (security review M4 —
 * see ChainStore.append for the call site and the full reasoning).
 */
export function computeEntryHashSync(prevHash: string | null, event: ChainEvent): string {
  return createHash("sha256")
    .update((prevHash ?? "") + canonicalize(event), "utf8")
    .digest("hex");
}
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
