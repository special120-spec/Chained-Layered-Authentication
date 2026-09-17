import { describe, it, expect } from "vitest";
import { hotp, totp, verifyTotp, base32Encode, base32Decode, buildProvisioningUri, generateTotpSecret } from "../src/totp.js";

// RFC 6238 Appendix B's official SHA-1 test vectors use this exact 20-byte
// ASCII secret and 8-digit codes. If this file ever fails, the HOTP/TOTP
// math itself is wrong — this is not testing our own design choices, it's
// testing conformance to the standard every authenticator app implements.
const RFC_SECRET = new TextEncoder().encode("12345678901234567890");

describe("TOTP RFC 6238 conformance (SHA-1, 8 digits, 30s step)", () => {
  const vectors: Array<[number, string]> = [
    [59, "94287082"],
    [1111111109, "07081804"],
    [1111111111, "14050471"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
    [20000000000, "65353130"],
  ];

  it.each(vectors)("T=%i -> %s", async (unixSeconds, expected) => {
    const code = await totp(RFC_SECRET, unixSeconds * 1000, { digits: 8, stepSeconds: 30 });
    expect(code).toBe(expected);
  });

  it("hotp() matches the counter derived from the same T values", async () => {
    const counter = Math.floor(59 / 30);
    expect(await hotp(RFC_SECRET, counter, 8)).toBe("94287082");
  });
});

describe("verifyTotp", () => {
  it("accepts a correct code at the exact time and returns its step number", async () => {
    const forTimeMs = 1234567890 * 1000;
    const code = await totp(RFC_SECRET, forTimeMs, { digits: 8 });
    const step = await verifyTotp(RFC_SECRET, code, forTimeMs, { digits: 8, window: 1 });
    expect(step).toBe(Math.floor(1234567890 / 30));
  });

  it("accepts a code from one step in the past or future (clock skew tolerance)", async () => {
    const forTimeMs = 1234567890 * 1000;
    const pastCode = await totp(RFC_SECRET, forTimeMs - 30_000, { digits: 8 });
    const futureCode = await totp(RFC_SECRET, forTimeMs + 30_000, { digits: 8 });
    expect(await verifyTotp(RFC_SECRET, pastCode, forTimeMs, { digits: 8, window: 1 })).not.toBeNull();
    expect(await verifyTotp(RFC_SECRET, futureCode, forTimeMs, { digits: 8, window: 1 })).not.toBeNull();
  });

  it("rejects a code two steps away when window is 1", async () => {
    const forTimeMs = 1234567890 * 1000;
    const tooOld = await totp(RFC_SECRET, forTimeMs - 60_000, { digits: 8 });
    expect(await verifyTotp(RFC_SECRET, tooOld, forTimeMs, { digits: 8, window: 1 })).toBeNull();
  });

  it("rejects garbage, wrong-length, and non-numeric input without throwing", async () => {
    const forTimeMs = 1234567890 * 1000;
    expect(await verifyTotp(RFC_SECRET, "not-a-code", forTimeMs, { digits: 8 })).toBeNull();
    expect(await verifyTotp(RFC_SECRET, "123", forTimeMs, { digits: 8 })).toBeNull();
    expect(await verifyTotp(RFC_SECRET, "", forTimeMs, { digits: 8 })).toBeNull();
  });

  it("does NOT itself prevent replay — returning the matched step is what lets a caller do that", async () => {
    // This test documents the module boundary from the doc comment: calling
    // verifyTotp twice with the same still-valid code succeeds twice. The
    // reference server's totpStore.ts is what must reject a repeated step.
    const forTimeMs = 1234567890 * 1000;
    const code = await totp(RFC_SECRET, forTimeMs, { digits: 8 });
    const first = await verifyTotp(RFC_SECRET, code, forTimeMs, { digits: 8 });
    const second = await verifyTotp(RFC_SECRET, code, forTimeMs, { digits: 8 });
    expect(first).toBe(second);
    expect(first).not.toBeNull();
  });
});

describe("base32", () => {
  it("round-trips arbitrary bytes", () => {
    const secret = generateTotpSecret(20);
    expect(base32Decode(base32Encode(secret))).toEqual(secret);
  });

  it("is case-insensitive and ignores padding on decode", () => {
    const upper = base32Encode(new TextEncoder().encode("hello world"));
    expect(base32Decode(upper.toLowerCase())).toEqual(base32Decode(upper));
    expect(base32Decode(upper + "===")).toEqual(base32Decode(upper));
  });
});

describe("buildProvisioningUri", () => {
  it("produces a well-formed otpauth:// URI with the expected parameters", () => {
    const secret = new TextEncoder().encode("12345678901234567890");
    const uri = buildProvisioningUri({ secret, accountLabel: "user@example.com", issuer: "CLA Demo" });
    expect(uri.startsWith("otpauth://totp/")).toBe(true);
    const parsed = new URL(uri);
    expect(parsed.searchParams.get("issuer")).toBe("CLA Demo");
    expect(parsed.searchParams.get("algorithm")).toBe("SHA1");
    expect(parsed.searchParams.get("digits")).toBe("6");
    expect(parsed.searchParams.get("period")).toBe("30");
    expect(base32Decode(parsed.searchParams.get("secret")!)).toEqual(secret);
  });
});
