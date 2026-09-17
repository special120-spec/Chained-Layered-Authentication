/**
 * The "key pattern" mechanism for v1 (design doc §D, option 3): a plain
 * authorization policy evaluated ALONGSIDE an already-verified WebAuthn
 * signature. This is ordinary risk-based-auth policy, not cryptography —
 * it adds defense in depth, never a substitute for the signature check,
 * and must never be described to developers as adding cryptographic
 * strength. A bug here fails open to "ask for step-up," never to "skip
 * signature verification."
 */
export interface AuthContext {
  ipAddress: string;
  /** Coarse, e.g. ISO country code — never store precise geolocation. */
  ipCountry?: string;
  knownDeviceId: boolean;
}

export interface PolicyDecision {
  requireStepUp: boolean;
  reason?: string;
}

export interface PolicyEngine {
  evaluate(context: AuthContext): PolicyDecision;
}

/**
 * Minimal reference policy: flag unrecognized-device + denylisted-country
 * combinations for step-up. Intentionally simple — real deployments should
 * replace this with their own PolicyEngine (e.g. backed by an IP
 * reputation feed), not extend this one indefinitely.
 */
export class DenylistCountryPolicy implements PolicyEngine {
  constructor(private readonly denylistedCountries: ReadonlySet<string>) {}

  evaluate(context: AuthContext): PolicyDecision {
    if (!context.knownDeviceId) {
      return { requireStepUp: true, reason: "unrecognized_device" };
    }
    if (context.ipCountry && this.denylistedCountries.has(context.ipCountry)) {
      return { requireStepUp: true, reason: "denylisted_country" };
    }
    return { requireStepUp: false };
  }
}

export const ALLOW_ALL_POLICY: PolicyEngine = {
  evaluate: () => ({ requireStepUp: false }),
};
