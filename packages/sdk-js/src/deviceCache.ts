const STORAGE_PREFIX = "cla:device:";

/**
 * Remembers which device id this browser/platform most recently used
 * successfully, purely as a UX convenience so `rotateKey()` and
 * `revokeDevice()` can default to "this device" without the caller having
 * to track WebAuthn credential ids themselves. Never treated as a security
 * boundary — every server-side check still requires a fresh signature.
 */
export class DeviceIdCache {
  constructor(private readonly accountId: string, private readonly storage: Storage = window.localStorage) {}

  private get key(): string {
    return `${STORAGE_PREFIX}${this.accountId}`;
  }

  get(): string | null {
    return this.storage.getItem(this.key);
  }

  set(deviceId: string): void {
    this.storage.setItem(this.key, deviceId);
  }

  clear(): void {
    this.storage.removeItem(this.key);
  }
}
