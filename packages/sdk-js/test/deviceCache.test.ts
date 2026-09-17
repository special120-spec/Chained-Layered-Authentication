import { describe, it, expect } from "vitest";
import { DeviceIdCache } from "../src/deviceCache.js";

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

describe("DeviceIdCache", () => {
  it("returns null when nothing is cached", () => {
    expect(new DeviceIdCache("acct1", new MemoryStorage()).get()).toBeNull();
  });

  it("remembers the most recently set device id", () => {
    const cache = new DeviceIdCache("acct1", new MemoryStorage());
    cache.set("device-1");
    expect(cache.get()).toBe("device-1");
    cache.set("device-2"); // e.g. after rotateKey() replaces it
    expect(cache.get()).toBe("device-2");
  });

  it("keeps separate accounts isolated", () => {
    const storage = new MemoryStorage();
    new DeviceIdCache("acct-a", storage).set("device-a");
    expect(new DeviceIdCache("acct-b", storage).get()).toBeNull();
  });

  it("clear() removes the cached id", () => {
    const cache = new DeviceIdCache("acct1", new MemoryStorage());
    cache.set("device-1");
    cache.clear();
    expect(cache.get()).toBeNull();
  });
});
