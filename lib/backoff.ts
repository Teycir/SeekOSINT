/**
 * backoff.ts — Exponential back-off with jitter for retryable fetch calls.
 *
 * Usage:
 *   const data = await withBackoff(() => fetch(url), { source: 'ipapi' })
 *
 * Retries only on HTTP 429 (rate limit) or network errors.
 * Non-retryable HTTP errors (4xx except 429, 5xx) are thrown immediately.
 */

export interface BackoffOptions {
  /** Name used in log messages. */
  source: string
  /** Maximum retry attempts (default 3). */
  maxAttempts?: number
  /** Initial delay in ms before first retry (default 500 ms). */
  baseDelayMs?: number
  /** Maximum delay cap in ms (default 30 000 ms). */
  maxDelayMs?: number
}

/**
 * Sleep for `ms` milliseconds. Uses a Promise so it yields the CF micro-task
 * queue — safe inside Workers.
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * Full-jitter exponential delay: uniform random in [0, base * 2^attempt].
 * See: https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
 */
function jitteredDelay(attempt: number, baseMs: number, maxMs: number): number {
  const cap = Math.min(maxMs, baseMs * 2 ** attempt)
  return Math.random() * cap
}

/**
 * Retry `fn` with exponential back-off + full jitter.
 *
 * `fn` must return a `Response` (i.e. a native fetch call).  This wrapper
 * inspects the response status and re-tries only on 429.  All other non-ok
 * statuses are surfaced immediately so callers can handle them.
 */
export async function withBackoff(
  fn: () => Promise<Response>,
  opts: BackoffOptions,
): Promise<Response> {
  const {
    source,
    maxAttempts = 3,
    baseDelayMs = 500,
    maxDelayMs  = 30_000,
  } = opts

  let lastErr: unknown
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const res = await fn()

      if (res.status === 429) {
        // Respect the upstream's Retry-After header when present; fall back to
        // exponential jitter so we don't retry before the quota actually resets.
        const retryAfterHeader = res.headers.get('Retry-After')
        const retryAfterMs = retryAfterHeader
          ? parseFloat(retryAfterHeader) * 1000   // header is in seconds
          : NaN
        const delay = Number.isFinite(retryAfterMs) && retryAfterMs > 0
          ? Math.min(retryAfterMs, maxDelayMs)
          : jitteredDelay(attempt, baseDelayMs, maxDelayMs)
        console.warn(
          `[${source}] 429 rate-limited — waiting ${Math.round(delay)}ms` +
          ` (attempt ${attempt + 1}/${maxAttempts})`,
        )
        await sleep(delay)
        lastErr = new Error(`HTTP 429`)
        continue
      }

      // Any other status (ok or non-retryable error) — return as-is
      return res
    } catch (err) {
      // Network / timeout errors are retryable
      const delay = jitteredDelay(attempt, baseDelayMs, maxDelayMs)
      console.warn(
        `[${source}] fetch error — waiting ${Math.round(delay)}ms` +
        ` (attempt ${attempt + 1}/${maxAttempts})`,
        err,
      )
      await sleep(delay)
      lastErr = err
    }
  }

  throw lastErr ?? new Error(`[${source}] all ${maxAttempts} attempts failed`)
}
