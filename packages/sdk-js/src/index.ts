import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import { verifyChain, type ChainEvent, type Layer, type Receipt } from "@cla/core";
import { ReceiptStore } from "./receipts.js";
import { DeviceIdCache } from "./deviceCache.js";
import { SessionStore } from "./sessionStore.js";

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

export interface DeviceInfo {
  device_id: string;
  created_at: string;
  status: "active" | "revoked";
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
  private readonly deviceCache: DeviceIdCache;
  private readonly sessionStore: SessionStore;
  private listeners: LockStateListener[] = [];

  constructor(private readonly options: ClaOptions) {
    this.receipts = new ReceiptStore(options.accountId);
    this.deviceCache = new DeviceIdCache(options.accountId);
    this.sessionStore = new SessionStore(options.accountId);
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

  private track(result: { receipt?: Receipt; layer?: Layer; session_token?: string }) {
    if (result.receipt) this.receipts.save(result.receipt);
    if (result.layer) this.notify(result.layer);
    if (result.session_token) this.sessionStore.set(result.session_token);
  }

  /** Registers this account's very first device. Fails with 409 once one is already active — use `addDevice()` from then on. */
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
    this.deviceCache.set(finish.body.device_id);
    return { deviceId: finish.body.device_id, layer: finish.body.layer };
  }

  /**
   * Adds another device to an account that already has one, authorized by
   * an assertion from any existing active device — never by re-running the
   * bootstrap flow. Every other device on the account is left untouched
   * (unlike `rotateKey`, which replaces one device with another).
   */
  async addDevice(): Promise<{ deviceId: string; layer: Layer }> {
    const { accountId } = this.options;
    const challengeRes = await this.postJson<any>("/v1/devices/add/challenge", { account_id: accountId });
    if (challengeRes.status !== 200) throw new Error(challengeRes.body.error);
    const assertionResponse = await startAuthentication({ optionsJSON: challengeRes.body });
    const start = await this.postJson<any>("/v1/devices/add/start", { account_id: accountId, assertionResponse });
    if (start.status !== 200) throw new Error(start.body.error);

    const attestationResponse = await startRegistration({ optionsJSON: start.body.registerOptions });
    const finish = await this.postJson<any>("/v1/devices/add/finish", {
      account_id: accountId,
      add_ticket: start.body.add_ticket,
      attestationResponse,
    });
    if (finish.status !== 200) throw new Error(finish.body.error);
    this.track(finish.body);
    this.deviceCache.set(finish.body.device_id);
    return { deviceId: finish.body.device_id, layer: finish.body.layer };
  }

  /**
   * Every active device on the account, most-recently-added last. Requires
   * a session from a prior register()/addDevice()/rotateKey()/authenticate()
   * call in this SDK instance (or a shared localStorage origin) — throws if
   * none is cached, since the server will reject the request anyway.
   */
  async listDevices(): Promise<DeviceInfo[]> {
    const res = await this.getWithSession(`/v1/devices?account_id=${encodeURIComponent(this.options.accountId)}`);
    if (res.status !== 200) throw new Error(res.body.error ?? "failed to list devices");
    return res.body.devices;
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
    if (verifyRes.body.device_id) this.deviceCache.set(verifyRes.body.device_id);
    return { layer: verifyRes.body.layer };
  }

  /**
   * Revokes `deviceId` — defaults to whichever device this SDK instance
   * last used successfully (self-revoke), but any active device can
   * authorize revoking any other: pass an id from `listDevices()` to kill
   * a different one, e.g. "use my laptop to revoke my lost phone."
   */
  async revokeDevice(deviceId?: string): Promise<{ layer: Layer }> {
    const { accountId } = this.options;
    const target = deviceId ?? this.deviceCache.get();
    if (!target) throw new Error("no device id known — pass one explicitly, or call listDevices() first");

    const challengeRes = await this.postJson<any>("/v1/devices/revoke/challenge", { account_id: accountId });
    if (challengeRes.status !== 200) throw new Error(challengeRes.body.error);
    const assertionResponse = await startAuthentication({ optionsJSON: challengeRes.body });
    const res = await this.postJson<any>("/v1/devices/revoke", { account_id: accountId, device_id: target, assertionResponse });
    if (res.status !== 200) throw new Error(res.body.error);
    this.track(res.body);
    return { layer: res.body.layer };
  }

  /**
   * Proves possession of `deviceId` (defaults to this SDK's last-known
   * device), then registers a new credential in its place and revokes the
   * old one — self-certifying rotation, no server-side identity re-check.
   * Every other device on the account is untouched.
   */
  async rotateKey(deviceId?: string): Promise<{ deviceId: string; layer: Layer }> {
    const { accountId } = this.options;
    const target = deviceId ?? this.deviceCache.get();
    if (!target) throw new Error("no device id known — pass one explicitly, or call listDevices() first");

    const challengeRes = await this.postJson<any>("/v1/devices/rotate/challenge", { account_id: accountId, device_id: target });
    if (challengeRes.status !== 200) throw new Error(challengeRes.body.error);
    const assertionResponse = await startAuthentication({ optionsJSON: challengeRes.body });
    const start = await this.postJson<any>("/v1/devices/rotate/start", {
      account_id: accountId,
      device_id: target,
      assertionResponse,
    });
    if (start.status !== 200) throw new Error(start.body.error);

    const attestationResponse = await startRegistration({ optionsJSON: start.body.registerOptions });
    const finish = await this.postJson<any>("/v1/devices/rotate/finish", {
      account_id: accountId,
      rotation_ticket: start.body.rotation_ticket,
      attestationResponse,
    });
    if (finish.status !== 200) throw new Error(finish.body.error);
    this.track(finish.body);
    this.deviceCache.set(finish.body.device_id);
    return { deviceId: finish.body.device_id, layer: finish.body.layer };
  }

  /** No signature required — this is the one path that has to work when every device is gone. See spec §7 / design doc §I. */
  async startRecovery(): Promise<{ layer: Layer }> {
    const res = await this.postJson<any>("/v1/account/recovery/start", { account_id: this.options.accountId });
    this.track(res.body);
    return { layer: res.body.layer };
  }

  /**
   * Requires a session from a prior register()/addDevice()/rotateKey()/
   * authenticate() call — this endpoint is the most information-dense in
   * the API (every device add/revoke, every failure reason, every
   * timestamp) and is gated server-side accordingly.
   */
  async fetchAuditLog(): Promise<AuditLog> {
    const res = await this.getWithSession(`/v1/account/${this.options.accountId}/audit-log`);
    if (res.status !== 200) throw new Error(res.body.error ?? "failed to fetch audit log");
    return res.body;
  }

  private async getWithSession(path: string): Promise<{ status: number; body: any }> {
    const token = this.sessionStore.get();
    if (!token) throw new Error("no session — call register(), addDevice(), rotateKey(), or authenticate() first");
    const res = await fetch(`${this.options.serverUrl}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
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
