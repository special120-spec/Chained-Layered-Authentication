import { CLA, type Layer } from "@cla/sdk-js";

const SERVER_URL = "http://localhost:8787";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const accountInput = $<HTMLInputElement>("accountId");
const layerEl = $<HTMLSpanElement>("layer");
const logEl = $<HTMLDivElement>("log");

let client = new CLA({ serverUrl: SERVER_URL, accountId: accountInput.value });
client.onLockStateChange(setLayer);

accountInput.addEventListener("change", () => {
  client = new CLA({ serverUrl: SERVER_URL, accountId: accountInput.value });
  client.onLockStateChange(setLayer);
});

function setLayer(layer: Layer) {
  layerEl.textContent = layer;
  layerEl.className = `layer layer-${layer}`;
}

function log(label: string, data: unknown) {
  logEl.textContent = `${label}\n${JSON.stringify(data, null, 2)}\n\n${logEl.textContent}`;
}

function base64UrlEncode(obj: unknown): string {
  return btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

$("register").addEventListener("click", async () => {
  try {
    const result = await client.register();
    log("register", result);
  } catch (err) {
    log("register error", String(err));
  }
});

$("authenticate").addEventListener("click", async () => {
  try {
    const result = await client.authenticate();
    log("authenticate", result);
  } catch (err) {
    log("authenticate error", String(err));
    if ((err as any)?.layer) setLayer((err as any).layer);
  }
});

$("stepUp").addEventListener("click", async () => {
  try {
    const result = await client.stepUp();
    log("stepUp", result);
  } catch (err) {
    log("stepUp error", String(err));
  }
});

$("addDevice").addEventListener("click", async () => {
  try {
    const result = await client.addDevice();
    log("addDevice", result);
  } catch (err) {
    log("addDevice error", String(err));
  }
});

$("listDevices").addEventListener("click", async () => {
  try {
    const devices = await client.listDevices();
    log("devices", devices);
  } catch (err) {
    // Now session-gated (security review H2) — register/authenticate first.
    log("listDevices error", String(err));
  }
});

$("revoke").addEventListener("click", async () => {
  const target = $<HTMLInputElement>("revokeTarget").value.trim() || undefined;
  try {
    const result = await client.revokeDevice(target);
    log("revoke", { target: target ?? "(this device)", ...result });
  } catch (err) {
    log("revoke error", String(err));
  }
});

$("rotate").addEventListener("click", async () => {
  try {
    const result = await client.rotateKey();
    log("rotate", result);
  } catch (err) {
    log("rotate error", String(err));
  }
});

$("startRecovery").addEventListener("click", async () => {
  const result = await client.startRecovery();
  setLayer(result.layer);
  log("startRecovery", result);
});

$("completeRecovery").addEventListener("click", async () => {
  const admin_token = prompt("Admin token (stand-in for a support-verified identity check):", "dev-admin-token");
  const res = await fetch(`${SERVER_URL}/v1/account/recovery/complete`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ account_id: accountInput.value, admin_token }),
  });
  const body = await res.json();
  if (body.layer) setLayer(body.layer);
  log("completeRecovery", body);
});

/**
 * Bypasses the real WebAuthn ceremony to demonstrate the lock ladder
 * without 11 real failed platform-authenticator prompts. It hits the same
 * /v1/auth/challenge + /v1/auth/verify endpoints the SDK uses — the
 * server-side chain and lock-state logic being exercised here is 100%
 * real, only the "device" producing a bad signature is faked.
 */
$("simulateFailures").addEventListener("click", async () => {
  const accountId = accountInput.value;
  for (let i = 0; i < 3; i++) {
    const challengeRes = await fetch(`${SERVER_URL}/v1/auth/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ account_id: accountId }),
    });
    const { challenge } = await challengeRes.json();
    if (!challenge) {
      log("simulateFailures", "no active device — register one first");
      return;
    }
    const fakeAssertion = {
      id: "fake",
      rawId: "ZmFrZQ",
      type: "public-key",
      response: {
        clientDataJSON: base64UrlEncode({ challenge, type: "webauthn.get", origin: location.origin }),
        authenticatorData: "AA",
        signature: "AA",
      },
    };
    const verifyRes = await fetch(`${SERVER_URL}/v1/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ account_id: accountId, assertionResponse: fakeAssertion }),
    });
    const body = await verifyRes.json();
    if (body.layer) setLayer(body.layer);
    log(`simulated failure ${i + 1}/3`, body);
  }
});

$("refreshLog").addEventListener("click", async () => {
  try {
    const audit = await client.fetchAuditLog();
    setLayer(audit.layer);
    log("audit log", audit);
  } catch (err) {
    // Now session-gated (security review H1) — register/authenticate first.
    log("refreshLog error", String(err));
  }
});

$("verifyChain").addEventListener("click", async () => {
  try {
    const audit = await client.fetchAuditLog();
    const result = await client.verifyAuditLog(audit);
    log("chain verification", { valid: result.valid, reason: result.reason });
  } catch (err) {
    log("verifyChain error", String(err));
  }
});
