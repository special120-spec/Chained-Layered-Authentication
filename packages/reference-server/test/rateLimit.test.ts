import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { Request, Response } from "express";
import { createRateLimiter } from "../src/rateLimit.js";

/** Minimal fakes — this is a unit test of the limiter's own logic, no HTTP involved. */
function fakeReqRes(overrides: Partial<Request> = {}) {
  const req = { ip: "1.2.3.4", body: {}, ...overrides } as Request;
  const headers: Record<string, string> = {};
  const res = {
    set: vi.fn((key: string, value: string) => {
      headers[key] = value;
      return res;
    }),
    status: vi.fn(() => res),
    json: vi.fn(() => res),
  } as unknown as Response;
  const next = vi.fn();
  return { req, res, next, headers };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("createRateLimiter", () => {
  it("allows requests under the limit through to next()", () => {
    const limiter = createRateLimiter({ windowMs: 60_000, max: 3, keyFn: () => "k", code: "rate_limited" });
    for (let i = 0; i < 3; i++) {
      const { req, res, next } = fakeReqRes();
      limiter(req, res, next);
      expect(next).toHaveBeenCalledOnce();
      expect(res.status).not.toHaveBeenCalled();
    }
  });

  it("rejects the request that exceeds the limit with 429 and Retry-After", () => {
    const limiter = createRateLimiter({ windowMs: 60_000, max: 2, keyFn: () => "k", code: "too_fast" });
    for (let i = 0; i < 2; i++) {
      const { req, res, next } = fakeReqRes();
      limiter(req, res, next);
      expect(next).toHaveBeenCalledOnce();
    }
    const { req, res, next, headers } = fakeReqRes();
    limiter(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "too_fast" }));
    expect(headers["Retry-After"]).toBeDefined();
    expect(Number(headers["Retry-After"])).toBeGreaterThan(0);
  });

  it("resets the count once the window has elapsed", () => {
    const limiter = createRateLimiter({ windowMs: 1000, max: 1, keyFn: () => "k", code: "rate_limited" });
    const first = fakeReqRes();
    limiter(first.req, first.res, first.next);
    expect(first.next).toHaveBeenCalledOnce();

    const blocked = fakeReqRes();
    limiter(blocked.req, blocked.res, blocked.next);
    expect(blocked.next).not.toHaveBeenCalled();

    vi.setSystemTime(new Date(Date.now() + 1001));

    const afterWindow = fakeReqRes();
    limiter(afterWindow.req, afterWindow.res, afterWindow.next);
    expect(afterWindow.next).toHaveBeenCalledOnce();
  });

  it("tracks separate keys independently — one key's usage never blocks another's", () => {
    const limiter = createRateLimiter({ windowMs: 60_000, max: 1, keyFn: (req) => req.body.account_id, code: "rate_limited" });

    const a1 = fakeReqRes({ body: { account_id: "acct-a" } });
    limiter(a1.req, a1.res, a1.next);
    expect(a1.next).toHaveBeenCalledOnce();

    const aBlocked = fakeReqRes({ body: { account_id: "acct-a" } });
    limiter(aBlocked.req, aBlocked.res, aBlocked.next);
    expect(aBlocked.next).not.toHaveBeenCalled();

    // A different key is completely unaffected by account-a's usage.
    const b1 = fakeReqRes({ body: { account_id: "acct-b" } });
    limiter(b1.req, b1.res, b1.next);
    expect(b1.next).toHaveBeenCalledOnce();
  });

  it("a null key (e.g. no account_id yet) skips limiting entirely — the route's own validation handles it", () => {
    const limiter = createRateLimiter({ windowMs: 60_000, max: 1, keyFn: () => null, code: "rate_limited" });
    for (let i = 0; i < 5; i++) {
      const { req, res, next } = fakeReqRes();
      limiter(req, res, next);
      expect(next).toHaveBeenCalledOnce();
    }
  });
});
