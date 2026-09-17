import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { computeEntryHash, verifyChain } from "../src/chain.js";
import { signEntryHash, verifyEntryHashSignature } from "../src/serverSigning.js";
import type { ChainEvent, Receipt } from "../src/types.js";

function makeEvent(seq: number, overrides: Partial<ChainEvent> = {}): ChainEvent {
  return {
    seq,
    account_id: "acct_1",
    device_id: "dev_1",
    type: "SUCCESS",
    layer_before: "NORMAL",
    layer_after: "NORMAL",
    timestamp: `2026-01-01T00:00:0${seq}Z`,
    ...overrides,
  };
}

describe("canonical hashing", () => {
  it("is stable regardless of key order in the source object", async () => {
    const a = await computeEntryHash(null, makeEvent(0));
    const shuffled = { ...makeEvent(0) };
    // Rebuild with keys inserted in a different order.
    const reordered: ChainEvent = {
      timestamp: shuffled.timestamp,
      type: shuffled.type,
      seq: shuffled.seq,
      account_id: shuffled.account_id,
      device_id: shuffled.device_id,
      layer_after: shuffled.layer_after,
      layer_before: shuffled.layer_before,
    };
    const b = await computeEntryHash(null, reordered);
    expect(a).toBe(b);
  });

  it("changes if any field changes", async () => {
    const a = await computeEntryHash(null, makeEvent(0));
    const b = await computeEntryHash(null, makeEvent(0, { type: "FAILURE" }));
    expect(a).not.toBe(b);
  });
});

describe("verifyChain", () => {
  it("accepts a correctly linked chain", async () => {
    const events = [makeEvent(0), makeEvent(1), makeEvent(2)];
    const result = await verifyChain(events);
    expect(result.valid).toBe(true);
    expect(result.hashesBySeq.size).toBe(3);
  });

  it("rejects an out-of-order or missing seq", async () => {
    const events = [makeEvent(0), makeEvent(2)];
    const result = await verifyChain(events);
    expect(result.valid).toBe(false);
  });

  it("detects a mutated historical event even if the chain is internally re-linked", async () => {
    // Simulate an attacker who edits event 1 and recomputes every hash
    // forward, i.e. a full, self-consistent rewrite by whoever controls
    // the storage. Internal verification alone must NOT catch this —
    // that's the point being tested (design doc §F): a bare hash chain
    // is consistent by construction under a full rewrite.
    const original = [makeEvent(0), makeEvent(1), makeEvent(2)];
    const originalCheck = await verifyChain(original);
    expect(originalCheck.valid).toBe(true);
    const knownReceipt: Receipt = {
      seq: 1,
      entry_hash: originalCheck.hashesBySeq.get(1)!,
      server_sig: "irrelevant-for-this-test",
      server_key_id: "k1",
    };

    const tampered = [makeEvent(0), makeEvent(1, { type: "FAILURE" }), makeEvent(2)];
    const tamperedAlone = await verifyChain(tampered);
    expect(tamperedAlone.valid).toBe(true); // internally consistent, still tampered!

    // But a verifier holding the ORIGINAL client receipt catches it:
    const tamperedWithReceipt = await verifyChain(tampered, [knownReceipt]);
    expect(tamperedWithReceipt.valid).toBe(false);
    expect(tamperedWithReceipt.reason).toMatch(/diverges/);
  });
});

describe("server signature over an entry hash", () => {
  it("verifies with the matching key and fails with a different key", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const { publicKey: otherPublicKey } = generateKeyPairSync("ed25519");
    const hash = await computeEntryHash(null, makeEvent(0));
    const sig = signEntryHash(hash, privateKey);

    expect(verifyEntryHashSignature(hash, sig, publicKey)).toBe(true);
    expect(verifyEntryHashSignature(hash, sig, otherPublicKey)).toBe(false);
  });
});
