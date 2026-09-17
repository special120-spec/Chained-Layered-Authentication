import type { Database } from "better-sqlite3";
import type { KeyObject } from "node:crypto";
import {
  stepUpOnFailure,
  stepDown,
  cooldownSeconds,
  DEFAULT_POLICY,
  type ChainEvent,
  type ChainEventType,
  type Layer,
  type Receipt,
} from "@cla/core";
import { signEntryHash, computeEntryHashSync } from "@cla/core/server-signing";
import type { ChainEventRow } from "./db.js";

export class ChainStore {
  constructor(
    private readonly db: Database,
    private readonly serverPrivateKey: KeyObject,
    private readonly serverKeyId: string
  ) {}

  private rowToEvent(row: ChainEventRow): ChainEvent {
    return {
      seq: row.seq,
      account_id: row.account_id,
      device_id: row.device_id,
      type: row.type as ChainEventType,
      layer_before: row.layer_before as Layer,
      layer_after: row.layer_after as Layer,
      timestamp: row.timestamp,
      detail: row.detail ? JSON.parse(row.detail) : undefined,
    };
  }

  getEvents(accountId: string): ChainEvent[] {
    const rows = this.db
      .prepare(`SELECT * FROM chain_events WHERE account_id = ? ORDER BY seq ASC`)
      .all(accountId) as ChainEventRow[];
    return rows.map((r) => this.rowToEvent(r));
  }

  getReceipts(accountId: string): Receipt[] {
    const rows = this.db
      .prepare(`SELECT * FROM chain_events WHERE account_id = ? ORDER BY seq ASC`)
      .all(accountId) as ChainEventRow[];
    return rows.map((r) => ({
      seq: r.seq,
      entry_hash: r.entry_hash,
      server_sig: r.server_sig,
      server_key_id: r.server_key_id,
    }));
  }

  /** Current layer, derived by replay — never stored as an independent mutable field. */
  currentLayer(accountId: string): Layer {
    const events = this.getEvents(accountId);
    return events.length === 0 ? "NORMAL" : events[events.length - 1].layer_after;
  }

  /**
   * Seconds remaining before a same-kind (non-step-up) attempt may be
   * accepted again, per spec §5's cooldown rule. Gates only once the ladder
   * has actually engaged (layer_after !== NORMAL) — a single mistaken
   * attempt at NORMAL should never make a legitimate user wait. Step-up and
   * recovery are never gated by this (see canInitiateStepUp in @cla/core);
   * callers must not call this for purpose === "step_up".
   */
  cooldownRemainingSeconds(accountId: string): number {
    const events = this.getEvents(accountId);
    if (events.length === 0) return 0;
    const last = events[events.length - 1];
    if (last.layer_after === "NORMAL" || last.type !== "FAILURE") return 0;

    const raw = last.detail?.cooldown_seconds;
    const cooldown = typeof raw === "number" ? raw : 0;
    if (cooldown <= 0) return 0;

    const elapsedSeconds = (Date.now() - new Date(last.timestamp).getTime()) / 1000;
    const remaining = cooldown - elapsedSeconds;
    return remaining > 0 ? remaining : 0;
  }

  /** Seq of the most recent event that actually changed the layer (a "transition"). */
  private lastLayerChangeSeq(accountId: string): number {
    const events = this.getEvents(accountId);
    for (let i = events.length - 1; i >= 0; i--) {
      if (events[i].layer_before !== events[i].layer_after) return events[i].seq;
    }
    return -1;
  }

  private countFailuresSinceWithinWindow(
    accountId: string,
    sinceSeqExclusive: number,
    windowMs: number
  ): number {
    const cutoff = new Date(Date.now() - windowMs).toISOString();
    const row = this.db
      .prepare(
        `SELECT COUNT(*) as n FROM chain_events
         WHERE account_id = ? AND seq > ? AND type = 'FAILURE' AND timestamp >= ?`
      )
      .get(accountId, sinceSeqExclusive, cutoff) as { n: number };
    return row.n;
  }

  private nextSeq(accountId: string): number {
    const row = this.db
      .prepare(`SELECT COALESCE(MAX(seq), -1) as maxSeq FROM chain_events WHERE account_id = ?`)
      .get(accountId) as { maxSeq: number };
    return row.maxSeq + 1;
  }

  private lastHash(accountId: string): string | null {
    const row = this.db
      .prepare(
        `SELECT entry_hash FROM chain_events WHERE account_id = ? ORDER BY seq DESC LIMIT 1`
      )
      .get(accountId) as { entry_hash: string } | undefined;
    return row?.entry_hash ?? null;
  }

  /**
   * Appends one event, computing its hash/signature, and persists it.
   *
   * Deliberately synchronous, start to finish (security review M4): the
   * only way two concurrent requests for the same account could corrupt
   * the chain is if something here yielded to the event loop between
   * reading the current tip (nextSeq/lastHash) and writing the new row —
   * that's the actual window a race needs, not the lack of a `BEGIN`/
   * `COMMIT`. better-sqlite3 is itself synchronous and single-connection,
   * so a method with zero `await`s in it cannot be interleaved with
   * another request's handler; Node's single-threaded event loop already
   * gives that for free. This is why chainStore uses the synchronous
   * `computeEntryHashSync` (node:crypto) here rather than the browser-safe
   * async `computeEntryHash` (Web Crypto) that @cla/core exports for
   * clients — reintroducing that `await` would reopen the race.
   */
  private append(
    accountId: string,
    deviceId: string | null,
    type: ChainEventType,
    layerBefore: Layer,
    layerAfter: Layer,
    detail?: Record<string, unknown>
  ): { event: ChainEvent; receipt: Receipt } {
    const event: ChainEvent = {
      seq: this.nextSeq(accountId),
      account_id: accountId,
      device_id: deviceId,
      type,
      layer_before: layerBefore,
      layer_after: layerAfter,
      timestamp: new Date().toISOString(),
      detail,
    };
    const prevHash = this.lastHash(accountId);
    const entryHash = computeEntryHashSync(prevHash, event);
    const serverSig = signEntryHash(entryHash, this.serverPrivateKey);

    this.db
      .prepare(
        `INSERT INTO chain_events
         (seq, account_id, device_id, type, layer_before, layer_after, timestamp, detail, entry_hash, server_sig, server_key_id)
         VALUES (@seq, @account_id, @device_id, @type, @layer_before, @layer_after, @timestamp, @detail, @entry_hash, @server_sig, @server_key_id)`
      )
      .run({
        ...event,
        detail: event.detail ? JSON.stringify(event.detail) : null,
        entry_hash: entryHash,
        server_sig: serverSig,
        server_key_id: this.serverKeyId,
      });

    return {
      event,
      receipt: { seq: event.seq, entry_hash: entryHash, server_sig: serverSig, server_key_id: this.serverKeyId },
    };
  }

  /** Emitted only for an account's very first device — the one bootstrap case with no proof requirement. */
  async recordRegister(accountId: string, deviceId: string) {
    const layer = this.currentLayer(accountId);
    return this.append(accountId, deviceId, "REGISTER", layer, layer);
  }

  /** Every device after the first: always authorized by an assertion from an existing active device. */
  async recordDeviceAdd(accountId: string, deviceId: string, authorizedByDeviceId: string) {
    const layer = this.currentLayer(accountId);
    return this.append(accountId, deviceId, "DEVICE_ADD", layer, layer, {
      authorized_by_device_id: authorizedByDeviceId,
    });
  }

  /** Ordinary successful assertion. Does not step an elevated layer down — only an explicit step-up does. */
  async recordSuccess(accountId: string, deviceId: string) {
    const layer = this.currentLayer(accountId);
    return this.append(accountId, deviceId, "SUCCESS", layer, layer);
  }

  async recordFailure(accountId: string, deviceId: string | null, reason: string) {
    const layer = this.currentLayer(accountId);
    const sinceSeq = this.lastLayerChangeSeq(accountId);
    const priorFailures = this.countFailuresSinceWithinWindow(accountId, sinceSeq, DEFAULT_POLICY.windowMs);
    const nextLayer = stepUpOnFailure(layer, priorFailures + 1, DEFAULT_POLICY);
    const cooldown = cooldownSeconds(priorFailures + 1, DEFAULT_POLICY);
    return this.append(accountId, deviceId, "FAILURE", layer, nextLayer, {
      reason,
      cooldown_seconds: cooldown,
    });
  }

  /** A dedicated, explicit step-up ceremony succeeded: steps the ladder down exactly one layer. */
  async recordStepUpOk(accountId: string, deviceId: string) {
    const layer = this.currentLayer(accountId);
    const nextLayer = stepDown(layer);
    return this.append(accountId, deviceId, "STEP_UP_OK", layer, nextLayer);
  }

  /** `deviceId` is the TARGET being revoked; `authorizedByDeviceId` is whichever active device signed for it (may be the same device, self-revoking). */
  async recordRevoke(accountId: string, deviceId: string, authorizedByDeviceId: string) {
    const layer = this.currentLayer(accountId);
    return this.append(accountId, deviceId, "REVOKE", layer, layer, {
      authorized_by_device_id: authorizedByDeviceId,
    });
  }

  async recordRotate(accountId: string, newDeviceId: string, oldDeviceId: string) {
    const layer = this.currentLayer(accountId);
    return this.append(accountId, newDeviceId, "ROTATE", layer, layer, { old_device_id: oldDeviceId });
  }

  /** User-initiated: "I lost every device." Jumps straight to RECOVERY regardless of prior failures. */
  async recordRecoveryStart(accountId: string) {
    const layer = this.currentLayer(accountId);
    return this.append(accountId, null, "RECOVERY_START", layer, "RECOVERY");
  }

  /** Human/support-mediated in v1 — the one path with no device-signature requirement by design. */
  async recordRecoveryComplete(accountId: string) {
    const layer = this.currentLayer(accountId);
    return this.append(accountId, null, "RECOVERY_COMPLETE", layer, "NORMAL");
  }
}
