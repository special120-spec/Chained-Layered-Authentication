import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Constant-time string comparison for secrets (M1 in the security review).
 * `crypto.timingSafeEqual` itself requires equal-length buffers and throws
 * otherwise — hashing both sides first normalizes length AND avoids
 * leaking the secret's length via an early throw, so this is safe to call
 * directly on attacker-controlled input of any length.
 */
export function safeEqual(a: string, b: string): boolean {
  const hashA = createHash("sha256").update(a, "utf8").digest();
  const hashB = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(hashA, hashB);
}
