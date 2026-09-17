import type { Receipt } from "@cla/core";

const STORAGE_PREFIX = "cla:receipt:";

/**
 * Caches only the highest-seq receipt per account — that's all that's
 * needed. Verifying a later chain against it proves nothing before that
 * point was rewritten (design doc §F / spec §4). This is the ONE piece of
 * client-side state that gives the chain any teeth against a compromised
 * server; losing it (a cleared browser profile, a new device with no
 * history) silently drops back to "audit trail among honest servers only,"
 * which is why receipts should also be exportable, not just cached.
 */
export class ReceiptStore {
  constructor(private readonly accountId: string, private readonly storage: Storage = window.localStorage) {}

  private get key(): string {
    return `${STORAGE_PREFIX}${this.accountId}`;
  }

  get(): Receipt | null {
    const raw = this.storage.getItem(this.key);
    return raw ? (JSON.parse(raw) as Receipt) : null;
  }

  /** Only ever moves forward — a receipt with a lower `seq` than what's cached is ignored, never regresses trust. */
  save(receipt: Receipt): void {
    const current = this.get();
    if (!current || receipt.seq > current.seq) {
      this.storage.setItem(this.key, JSON.stringify(receipt));
    }
  }

  clear(): void {
    this.storage.removeItem(this.key);
  }
}
