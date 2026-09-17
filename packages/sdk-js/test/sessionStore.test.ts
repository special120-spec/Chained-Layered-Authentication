import { describe, it, expect } from "vitest";
import { SessionStore } from "../src/sessionStore.js";

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

describe("SessionStore", () => {
  it("returns null when nothing is cached", () => {
    expect(new SessionStore("acct1", new MemoryStorage()).get()).toBeNull();
  });

  it("remembers the most recently set token", () => {
    const store = new SessionStore("acct1", new MemoryStorage());
    store.set("token-1");
    expect(store.get()).toBe("token-1");
    store.set("token-2"); // e.g. a later authenticate() call replaces it
    expect(store.get()).toBe("token-2");
  });

  it("keeps separate accounts isolated", () => {
    const storage = new MemoryStorage();
    new SessionStore("acct-a", storage).set("token-a");
    expect(new SessionStore("acct-b", storage).get()).toBeNull();
  });

  it("clear() removes the cached token", () => {
    const store = new SessionStore("acct1", new MemoryStorage());
    store.set("token-1");
    store.clear();
    expect(store.get()).toBeNull();
  });
});
