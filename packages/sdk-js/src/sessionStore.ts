const STORAGE_PREFIX = "cla:session:";

/**
 * Caches the session token issued after a real WebAuthn ceremony completes
 * (register/add/rotate/authenticate — see reference-server's sessions.ts),
 * so `fetchAuditLog()`/`listDevices()` can attach it automatically instead
 * of making every caller thread a token through by hand. Purely a client
 * convenience cache, same as ReceiptStore/DeviceIdCache — the server is the
 * actual source of truth on whether a token is still valid.
 */
export class SessionStore {
  constructor(private readonly accountId: string, private readonly storage: Storage = window.localStorage) {}

  private get key(): string {
    return `${STORAGE_PREFIX}${this.accountId}`;
  }

  get(): string | null {
    return this.storage.getItem(this.key);
  }

  set(token: string): void {
    this.storage.setItem(this.key, token);
  }

  clear(): void {
    this.storage.removeItem(this.key);
  }
}
