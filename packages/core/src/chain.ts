import type { ChainEvent, Receipt } from "./types.js";

/**
 * Deterministic, JCS-style canonicalization: object keys sorted
 * recursively, arrays left in order, no insignificant whitespace. Both the
 * server and every client MUST hash the exact same bytes, or the chain
 * "breaks" on a formatting difference instead of a real tamper.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Uses the Web Crypto API (`globalThis.crypto.subtle`) rather than Node's
 * `node:crypto`, deliberately: this module is imported by both the
 * reference server AND the browser SDK (a client has to independently
 * recompute the chain to check a server's claims — see verifyChain below).
 * Web Crypto is available in every modern browser and, since Node 19, in
 * Node itself, so one implementation serves both without bundler hacks.
 */
async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return bufferToHex(digest);
}

/** No `Buffer` here on purpose — this file must stay usable in a browser bundle. */
function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * The chain rule: entry_hash[n] = SHA256(entry_hash[n-1] || canonical(event[n])),
 * with entry_hash[-1] treated as the empty string for the first event.
 *
 * This proves ORDER and COMPLETENESS of what got recorded — it does not,
 * on its own, prove any of it is true, and it provides zero resistance to
 * whoever can rewrite every input to every hash (e.g. an operator with raw
 * database write access). See spec §5 / design doc §F before assuming this
 * function is "the security." What actually stops forgery is the WebAuthn
 * signature verified before an event is ever appended, and the server's
 * signature over each hash (see server-signing.ts, Node-only).
 */
export async function computeEntryHash(prevHash: string | null, event: ChainEvent): Promise<string> {
  return sha256Hex((prevHash ?? "") + canonicalize(event));
}

/**
 * Replays a full ordered event list and confirms internal consistency:
 * sequential `seq`, and every entry_hash reproduces from its predecessor.
 * This alone does NOT detect a server that rewrote history consistently —
 * for that, the caller must also pass `knownReceipts`: hashes/seqs the
 * verifier already trusted from a prior session. A chain that is
 * internally consistent but silently diverges from a known receipt has
 * been tampered with since that receipt was issued.
 */
export async function verifyChain(
  events: ChainEvent[],
  knownReceipts: Receipt[] = []
): Promise<{ valid: boolean; reason?: string; hashesBySeq: Map<number, string> }> {
  const hashesBySeq = new Map<number, string>();
  let prevHash: string | null = null;

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    if (event.seq !== i) {
      return { valid: false, reason: `expected seq ${i}, got ${event.seq}`, hashesBySeq };
    }
    const entryHash = await computeEntryHash(prevHash, event);
    hashesBySeq.set(event.seq, entryHash);
    prevHash = entryHash;
  }

  for (const receipt of knownReceipts) {
    const recomputed = hashesBySeq.get(receipt.seq);
    if (recomputed !== receipt.entry_hash) {
      return {
        valid: false,
        reason: `chain diverges from a previously-issued receipt at seq ${receipt.seq}`,
        hashesBySeq,
      };
    }
  }

  return { valid: true, hashesBySeq };
}
