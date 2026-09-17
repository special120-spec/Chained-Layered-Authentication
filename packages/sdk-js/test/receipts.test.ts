import { describe, it, expect } from "vitest";
import { ReceiptStore } from "../src/receipts.js";
import type { Receipt } from "@cla/core";

/** Minimal in-memory Storage, so this test doesn't need a DOM environment. */
class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  get length() {
    return this.map.size;
  }
  clear(): void {
    this.map.clear();
  }
  getItem(key: string): string | null {
    return this.map.has(key) ? this.map.get(key)! : null;
  }
  key(index: number): string | null {
    return Array.from(this.map.keys())[index] ?? null;
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
  setItem(key: string, value: string): void {
    this.map.set(key, value);
  }
}

function receipt(seq: number): Receipt {
  return { seq, entry_hash: `hash-${seq}`, server_sig: `sig-${seq}`, server_key_id: "k1" };
}

describe("ReceiptStore", () => {
  it("returns null when nothing is cached", () => {
    const store = new ReceiptStore("acct1", new MemoryStorage());
    expect(store.get()).toBeNull();
  });

  it("saves and retrieves a receipt", () => {
    const store = new ReceiptStore("acct1", new MemoryStorage());
    store.save(receipt(0));
    expect(store.get()).toEqual(receipt(0));
  });

  it("only moves forward — a lower seq never overwrites a higher one already cached", () => {
    const store = new ReceiptStore("acct1", new MemoryStorage());
    store.save(receipt(5));
    store.save(receipt(2)); // stale/out-of-order write, e.g. a slow duplicate request
    expect(store.get()).toEqual(receipt(5));
    store.save(receipt(7));
    expect(store.get()).toEqual(receipt(7));
  });

  it("keeps separate accounts isolated", () => {
    const storage = new MemoryStorage();
    const a = new ReceiptStore("acct-a", storage);
    const b = new ReceiptStore("acct-b", storage);
    a.save(receipt(1));
    expect(b.get()).toBeNull();
  });

  it("clear() removes the cached receipt", () => {
    const store = new ReceiptStore("acct1", new MemoryStorage());
    store.save(receipt(0));
    store.clear();
    expect(store.get()).toBeNull();
  });
});
