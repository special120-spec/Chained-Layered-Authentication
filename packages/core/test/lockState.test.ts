import { describe, it, expect } from "vitest";
import {
  stepDown,
  stepUpOnFailure,
  cooldownSeconds,
  canInitiateStepUp,
  DEFAULT_POLICY,
} from "../src/lockState.js";

describe("stepUpOnFailure", () => {
  it("stays put below threshold", () => {
    expect(stepUpOnFailure("NORMAL", 1)).toBe("NORMAL");
    expect(stepUpOnFailure("NORMAL", 2)).toBe("NORMAL");
  });

  it("escalates exactly one layer at threshold", () => {
    expect(stepUpOnFailure("NORMAL", 3)).toBe("LOCK");
    expect(stepUpOnFailure("LOCK", 5)).toBe("STEP_UP");
    expect(stepUpOnFailure("STEP_UP", 3)).toBe("RECOVERY");
  });

  it("never escalates past RECOVERY", () => {
    expect(stepUpOnFailure("RECOVERY", 999)).toBe("RECOVERY");
  });
});

describe("stepDown", () => {
  it("moves exactly one layer down and never below NORMAL", () => {
    expect(stepDown("RECOVERY")).toBe("STEP_UP");
    expect(stepDown("STEP_UP")).toBe("LOCK");
    expect(stepDown("LOCK")).toBe("NORMAL");
    expect(stepDown("NORMAL")).toBe("NORMAL");
  });
});

describe("cooldownSeconds", () => {
  it("grows exponentially and is capped", () => {
    const c0 = cooldownSeconds(0, DEFAULT_POLICY);
    const c1 = cooldownSeconds(1, DEFAULT_POLICY);
    const c20 = cooldownSeconds(20, DEFAULT_POLICY);
    expect(c1).toBeGreaterThan(c0);
    expect(c20).toBe(DEFAULT_POLICY.cooldownMaxSeconds);
  });
});

describe("canInitiateStepUp — the anti-DoS invariant", () => {
  it("is always true, regardless of layer", () => {
    // This is the load-bearing test for the whole "lockout as denial of
    // service" concern raised in the design doc (§H/§I): a still-valid
    // device signature must always be able to START a step-up or recovery
    // request, even from the deepest layer. If this test ever needs to
    // become conditional, that's a sign the ladder has regressed into the
    // naive, DoS-able version.
    for (const layer of ["NORMAL", "LOCK", "STEP_UP", "RECOVERY"] as const) {
      expect(canInitiateStepUp(layer)).toBe(true);
    }
  });
});
