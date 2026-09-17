import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import { verifyChain, type ChainEvent, type Layer, type Receipt } from "@cla/core";
import { ReceiptStore } from "./receipts.js";

export type { Layer, ChainEvent, Receipt };

export interface ClaOptions {
  serverUrl: string;
  accountId: string;
}

export interface AuditLog {
  events: ChainEvent[];
  receipts: Receipt[];
  layer: Layer;
}

type LockStateListener = (layer: Layer) => void;

/**
 * The whole point of this SDK: a developer integrates authentication
 * without ever touching a hash, a signature object, or a WebAuthn
 * ceremony directly. Everything cryptographic happens inside these
 * methods or inside the platform's own WebAuthn implementation.
 */
export class CLA {
  private readonly receipts: ReceiptStore;
  private listeners: LockStateListener[] = [];

  constructor(private readonly options: ClaOptions) {
    this.receipts = new ReceiptStore(options.accountId);
  }

  onLockStateChange(listener: LockStateListener): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  private notify(layer: Layer) {
    for (const listener of this.listeners) listener(layer);
  }

  private async postJson<T>(path: string, body: unknown): Promise<{ status: number; body: T }> {
    const res = await fetch(`${this.options.serverUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  private track(result: { receipt?: Receipt; layer?: Layer }) {
    if (result.receipt) this.receipts.save(result.receipt);
    if (result.layer) this.notify(result.layer);
  }

  /** Registers this device. Fails with 409 if the account already has an active device — use `rotateKey()` instead. */
  async register(): Promise<{ deviceId: string; layer: Layer }> {
    const { accountId } = this.options;
    const start = await this.postJson<any>("/v1/devices/register/start", { account_id: accountId });
    if (start.status !== 200) throw new Error(start.body.error ?? "registration start failed");

    const attestationResponse = await startRegistration({ optionsJSON: start.body });
    const finish = await this.postJson<any>("/v1/devices/register/finish", {
      account_id: accountId,
      attestationResponse,
    });
    if (finish.status !== 200) throw new Error(finish.body.error ?? "registration failed");
    this.track(finish.body);
    return { deviceId: finish.body.device_id, layer: finish.body.layer };
  }

  /** Ordinary sign-in. On failure, the layer may have escalated — check the thrown error's `.layer`. */
  async authenticate(): Promise<{ layer: Layer }> {
    return this.performAssertion("auth");
  }

  /**
   * A dedicated, explicit re-proof of possession. This is what steps an
   * elevated layer back down one notch — a plain `authenticate()` while
   * elevated deliberately does NOT do this (design doc §E: deeper layers
   * should require a qualitatively different proof, not just "try again").
   * Always callable, regardless of current layer or cooldown — see
   * `canInitiateStepUp` in @cla/core.
   */
  async stepUp(): Promise<{ layer: Layer }> {
    return this.performAssertion("step_up");
  }

  private async performAssertion(purpose: "auth" | "step_up"): Promise<{ layer: Layer }> {
    const { accountId } = this.options;
    const challengeRes = await this.postJson<any>("/v1/auth/challenge", { account_id: accountId, purpose });
    if (challengeRes.status !== 200) throw new Error(challengeRes.body.error ?? "no device to authenticate");

    const assertionResponse = await startAuthentication({ optionsJSON: challengeRes.body });
    const verifyRes = await this.postJson<any>("/v1/auth/verify", {
      account_id: accountId,
      assertionResponse,
      purpose,
    });
    this.track(verifyRes.body);
    if (verifyRes.status !== 200) {
      const err = new Error(verifyRes.body.error ?? "authentication failed") as Error & { layer?: Layer };
      err.layer = verifyRes.body.layer;
      throw err;
    }
    return { layer: verifyRes.body.layer };
  }

  async revokeDevice(): Promise<{ layer: Layer }> {
    const { accountId } = this.options;
    const challengeRes = await this.postJson<any>("/v1/devices/revoke/challenge", { account_id: accountId });
    if (challengeRes.status !== 200) throw new Error(challengeRes.body.error);
    const assertionResponse = await startAuthentication({ optionsJSON: challengeRes.body });
    const res = await this.postJson<any>("/v1/devices/revoke", { account_id: accountId, assertionResponse });
    if (res.status !== 200) throw new Error(res.body.error);
    this.track(res.body);
    return { layer: res.body.layer };
  }

  /** Proves possession of the current device, then registers a new one and revokes the old — self-certifying rotation, no server-side identity re-check. */
  async rotateKey(): Promise<{ deviceId: string; layer: Layer }> {
    const { accountId } = this.options;
    const challengeRes = await this.postJson<any>("/v1/devices/rotate/challenge", { account_id: accountId });
    if (challengeRes.status !== 200) throw new Error(challengeRes.body.error);
    const assertionResponse = await startAuthentication({ optionsJSON: challengeRes.body });
    const start = await this.postJson<any>("/v1/devices/rotate/start", { account_id: accountId, assertionResponse });
    if (start.status !== 200) throw new Error(start.body.error);

    const attestationResponse = await startRegistration({ optionsJSON: start.body.registerOptions });
    const finish = await this.postJson<any>("/v1/devices/rotate/finish", {
      account_id: accountId,
      rotation_ticket: start.body.rotation_ticket,
      attestationResponse,
    });
    if (finish.status !== 200) throw new Error(finish.body.error);
    this.track(finish.body);
    return { deviceId: finish.body.device_id, layer: finish.body.layer };
  }

  /** No signature required — this is the one path that has to work when every device is gone. See spec §7 / design doc §I. */
  async startRecovery(): Promise<{ layer: Layer }> {
    const res = await this.postJson<any>("/v1/account/recovery/start", { account_id: this.options.accountId });
    this.track(res.body);
    return { layer: res.body.layer };
  }

  async fetchAuditLog(): Promise<AuditLog> {
    const res = await fetch(`${this.options.serverUrl}/v1/account/${this.options.accountId}/audit-log`);
    return res.json();
  }

  /**
   * The client-side half of the chain's tamper-evidence claim (design doc
   * §F). Recomputes the chain over whatever the server just returned and
   * confirms it still passes through the highest-seq receipt this SDK has
   * cached locally. If this ever returns `valid: false`, the server has
   * shown this client a history inconsistent with one it already vouched
   * for — treat that as a live incident, not a retry-able error.
   */
  async verifyAuditLog(log: AuditLog): ReturnType<typeof verifyChain> {
    const cached = this.receipts.get();
    return verifyChain(log.events, cached ? [cached] : []);
  }
}
