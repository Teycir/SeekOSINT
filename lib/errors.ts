/**
 * errors.ts — unified error response helpers.
 *
 * Provides a consistent JSON error envelope across all API routes:
 *
 *   { error: string, code: ErrorCode, details?: unknown }
 *
 * Usage:
 *   return errorResponse(ErrorCode.INVALID_QUERY, 'invalid query', 422)
 *   return errorResponse(ErrorCode.RATE_LIMITED, 'rate limit exceeded', 429, { resetInSeconds: 60 })
 */

// ─── Error codes ──────────────────────────────────────────────────────────────

export const ErrorCode = {
  // Input validation
  MISSING_QUERY:   'MISSING_QUERY',
  INVALID_QUERY:   'INVALID_QUERY',

  // Rate limiting
  RATE_LIMITED:    'RATE_LIMITED',

  // Server / upstream
  INTERNAL_ERROR:  'INTERNAL_ERROR',
  SOURCE_ERROR:    'SOURCE_ERROR',
  TIMEOUT:         'TIMEOUT',

  // Auth (future)
  UNAUTHORIZED:    'UNAUTHORIZED',
  FORBIDDEN:       'FORBIDDEN',
} as const

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode]

// ─── Error envelope ───────────────────────────────────────────────────────────

export interface ErrorBody {
  error: string
  code: ErrorCode
  details?: unknown
}

// ─── Response factory ─────────────────────────────────────────────────────────

/**
 * Build a JSON Response with a consistent error envelope.
 *
 * @param code     - Machine-readable error code from ErrorCode enum
 * @param message  - Human-readable description
 * @param status   - HTTP status code (default 500)
 * @param details  - Optional extra context (e.g. resetInSeconds, field name)
 * @param headers  - Optional extra response headers (e.g. Retry-After)
 */
export function errorResponse(
  code: ErrorCode,
  message: string,
  status = 500,
  details?: unknown,
  headers?: Record<string, string>,
): Response {
  const body: ErrorBody = { error: message, code }
  if (details !== undefined) body.details = details

  return Response.json(body, { status, headers })
}
