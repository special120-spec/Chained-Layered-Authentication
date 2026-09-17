import { LAYER_ORDER, type Layer } from "./types.js";

export interface LockPolicy {
  /** Rolling window over which failures count toward escalation. */
  windowMs: number;
  /** Failures needed to escalate OUT of each layer (RECOVERY has no next). */
  thresholds: Record<Exclude<Layer, "RECOVERY">, number>;
  /** Base for exponential cooldown: cooldownBase * 2^failuresInLayer, capped. */
  cooldownBaseSeconds: number;
  cooldownMaxSeconds: number;
}

export const DEFAULT_POLICY: LockPolicy = {
  windowMs: 15 * 60 * 1000,
  thresholds: { NORMAL: 3, LOCK: 5, STEP_UP: 3 },
  cooldownBaseSeconds: 2,
  cooldownMaxSeconds: 3600,
};

function layerIndex(layer: Layer): number {
  return LAYER_ORDER.indexOf(layer);
}

/**
 * One step down the ladder — never skips a layer, never goes below NORMAL.
 * Used for UNLOCK / STEP_UP_OK. Full RECOVERY_COMPLETE is handled
 * separately (it jumps straight to NORMAL by design: that's the one path
 * that doesn't require possession of any enrolled device, so it doesn't
 * owe the ladder a gradual descent).
 */
export function stepDown(current: Layer): Layer {
  const idx = layerIndex(current);
  return LAYER_ORDER[Math.max(idx - 1, 0)];
}

/**
 * One step up the ladder in response to a failure, IF the failure count
 * within the policy window meets this layer's threshold. Otherwise stays
 * put. Never silently jumps more than one layer per failure — a burst of
 * failures escalates one step per evaluation, which callers should invoke
 * once per FAILURE event as it's appended.
 */
export function stepUpOnFailure(
  current: Layer,
  failuresInLayerWithinWindow: number,
  policy: LockPolicy = DEFAULT_POLICY
): Layer {
  if (current === "RECOVERY") return "RECOVERY";
  const threshold = policy.thresholds[current];
  if (failuresInLayerWithinWindow >= threshold) {
    return LAYER_ORDER[layerIndex(current) + 1];
  }
  return current;
}

export function cooldownSeconds(
  failuresInLayer: number,
  policy: LockPolicy = DEFAULT_POLICY
): number {
  const raw = policy.cooldownBaseSeconds * Math.pow(2, failuresInLayer);
  return Math.min(raw, policy.cooldownMaxSeconds);
}

/**
 * IMPORTANT: cooldown gates *when a same-kind attempt is retried*, never
 * whether a device can attempt a structurally different, higher-assurance
 * proof (a step-up ceremony). An implementation that blocks ALL attempts
 * during cooldown turns the lockout ladder into a tool an attacker can use
 * against the legitimate owner (design doc §H/§I) — a valid device
 * signature must always be able to *initiate* a step-up or recovery
 * request, cooldown or not.
 */
export function canInitiateStepUp(_layer: Layer): boolean {
  return true;
}
