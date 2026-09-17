/**
 * Rejects the concrete crash scenario from security review M3: a JSON body
 * field that's supposed to be a plain id string arriving instead as an
 * object/array/number, which would otherwise reach a better-sqlite3
 * `.run()`/`.get()` call and throw synchronously. Bounds length too, since
 * nothing upstream does.
 *
 * This is intentionally narrow (id-shaped strings only), not a general
 * request-schema validator — see docs/security-findings-2026-09-17.md M3
 * for why a fuller schema-validation pass (e.g. zod) is still a worthwhile
 * follow-up.
 */
export function isValidId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256;
}
