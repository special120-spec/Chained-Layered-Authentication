export const LAYER_ORDER = ["NORMAL", "LOCK", "STEP_UP", "RECOVERY"] as const;
export type Layer = (typeof LAYER_ORDER)[number];

export const EVENT_TYPES = [
  "REGISTER",
  "SUCCESS",
  "FAILURE",
  "LOCK",
  "UNLOCK",
  "STEP_UP_OK",
  "REVOKE",
  "ROTATE",
  "RECOVERY_START",
  "RECOVERY_COMPLETE",
] as const;
export type ChainEventType = (typeof EVENT_TYPES)[number];

/**
 * One entry in an account's append-only chain. `seq` is 0-indexed and must
 * be strictly increasing per account. `detail` is free-form, non-security-
 * bearing context (e.g. { reason: "bad_signature" }) — never put anything
 * that must remain secret in an event, since the chain is meant to be
 * exportable to the account owner for audit.
 */
export interface ChainEvent {
  seq: number;
  account_id: string;
  device_id: string | null;
  type: ChainEventType;
  layer_before: Layer;
  layer_after: Layer;
  timestamp: string;
  detail?: Record<string, unknown>;
}

export interface Receipt {
  seq: number;
  entry_hash: string;
  server_sig: string;
  server_key_id: string;
}

/** A chain event plus the hash/signature produced when it was appended. */
export interface AppendedEvent {
  event: ChainEvent;
  entry_hash: string;
}
