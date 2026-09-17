import type { NextFunction, Request, RequestHandler, Response } from "express";

/**
 * Express 4 does not catch rejections thrown from an async route handler
 * (Express 5 does; this project is still on 4). An uncaught rejection
 * terminates the Node process by default since Node 15 — one malformed
 * request could otherwise crash every account's auth (security review M3).
 * Wrap every route with this so any thrown/rejected error reaches Express's
 * error-handling middleware (see errorHandler.ts) instead of the process.
 */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>
): RequestHandler {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
