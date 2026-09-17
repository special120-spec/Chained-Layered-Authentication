import type { NextFunction, Request, RequestHandler, Response } from "express";

interface Bucket {
  count: number;
  windowStart: number;
}

export interface RateLimitOptions {
  windowMs: number;
  max: number;
  /** How to derive the bucket key from a request — e.g. by IP, by account_id, or both combined. */
  keyFn: (req: Request) => string | null;
  /** Machine-readable error code returned in the 429 body. */
  code: string;
}

/**
 * Fixed-window in-memory rate limiter (security review H3). In-memory and
 * per-process by design, matching this reference server's existing scope
 * (single SQLite connection, no external cache) — a multi-instance
 * deployment needs a shared store (Redis, etc.) instead; this is
 * sufficient for the reference implementation and for closing the
 * specific findings it's applied against.
 *
 * `keyFn` returning `null` (e.g. no account_id in the body yet) skips
 * limiting for that request — the route's own validation handles it.
 */
export function createRateLimiter(opts: RateLimitOptions): RequestHandler {
  const buckets = new Map<string, Bucket>();

  // Bound memory growth from buckets that will never be touched again
  // (e.g. one-off IPs). Sweeps lazily rather than on every request.
  let lastSweep = Date.now();
  function sweep(now: number) {
    if (now - lastSweep < opts.windowMs * 2) return;
    lastSweep = now;
    for (const [key, bucket] of buckets) {
      if (now - bucket.windowStart >= opts.windowMs) buckets.delete(key);
    }
  }

  return (req: Request, res: Response, next: NextFunction) => {
    const key = opts.keyFn(req);
    if (key === null) return next();

    const now = Date.now();
    sweep(now);

    let bucket = buckets.get(key);
    if (!bucket || now - bucket.windowStart >= opts.windowMs) {
      bucket = { count: 0, windowStart: now };
      buckets.set(key, bucket);
    }
    bucket.count++;

    if (bucket.count > opts.max) {
      const retryAfterSeconds = Math.max(1, Math.ceil((bucket.windowStart + opts.windowMs - now) / 1000));
      res.set("Retry-After", String(retryAfterSeconds));
      return res.status(429).json({ error: opts.code, retry_after_seconds: retryAfterSeconds });
    }
    next();
  };
}

/** Rate-limit by client IP. Express's `trust proxy` setting governs what `req.ip` reflects behind a load balancer. */
export function byIp(req: Request): string {
  return req.ip ?? "unknown";
}

/** Rate-limit by the `account_id` in the JSON body — read after `express.json()` has already run. Falls back to skipping the limit if absent (the route's own validation rejects the request anyway). */
export function byAccountId(req: Request): string | null {
  const accountId = req.body?.account_id;
  return typeof accountId === "string" && accountId.length > 0 ? accountId : null;
}
