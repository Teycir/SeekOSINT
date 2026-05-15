/**
 * ratelimit.ts — KV-backed per-IP rate limiter + circuit breaker.
 *
 * Rate limiter
 * ─────────────
 * Stores a sliding-window counter keyed by client IP in KV.
 * Default: 100 requests / hour (as specified in ROADMAP).
 * The counter key expires automatically via KV TTL, so no
 * explicit window reset is needed.
 *
 * Circuit breaker
 * ────────────────
 * Tracks consecutive failures for an upstream service in KV.
 * After TRIP_THRESHOLD failures the breaker OPENS and requests
 * are short-circuited for OPEN_TTL_SECONDS, then it half-opens
 * and allows the next probe through.
 */

// ─── Per-IP rate limiter ──────────────────────────────────────────────────────

export interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetInSeconds: number
}

const RL_WINDOW_SECONDS = 3600          // 1-hour sliding window
const RL_MAX_REQUESTS   = 100           // matches ROADMAP note
const RL_KV_PREFIX      = 'rl:ip:'

/**
 * Check (and increment) the per-IP counter in KV.
 * Returns { allowed: false } when the limit is exceeded.
 */
export async function checkRateLimit(
  ip: string,
  kv: KVNamespace,
  maxRequests = RL_MAX_REQUESTS,
  windowSeconds = RL_WINDOW_SECONDS,
): Promise<RateLimitResult> {
  const key = `${RL_KV_PREFIX}${ip}`

  try {
    const raw = await kv.get(key, 'text')
    const current = raw ? parseInt(raw, 10) : 0

    if (current >= maxRequests) {
      // Already at or over limit — do NOT increment; key TTL tells us reset time
      const meta = await kv.getWithMetadata<{ expiration?: number }>(key)
      const expiration = meta.metadata?.expiration ?? 0
      const resetInSeconds = expiration
        ? Math.max(0, expiration - Math.floor(Date.now() / 1000))
        : windowSeconds

      return { allowed: false, remaining: 0, resetInSeconds }
    }

    // Increment.  On first write, set the window TTL so it auto-resets.
    const next = current + 1
    await kv.put(key, String(next), {
      expirationTtl: windowSeconds,
    })

    return {
      allowed:        true,
      remaining:      maxRequests - next,
      resetInSeconds: windowSeconds,
    }
  } catch (err) {
    // KV failure — fail open (allow the request) to avoid self-DoS
    console.error('[ratelimit] KV error, failing open', err)
    return { allowed: true, remaining: maxRequests, resetInSeconds: windowSeconds }
  }
}

// ─── Circuit breaker ──────────────────────────────────────────────────────────

const CB_KV_PREFIX        = 'cb:'
const TRIP_THRESHOLD      = 5     // consecutive failures before opening
const OPEN_TTL_SECONDS    = 60    // stay open for 60 s, then half-open probe

export type BreakerState = 'closed' | 'open' | 'half-open'

export async function getBreakerState(
  source: string,
  kv: KVNamespace,
): Promise<BreakerState> {
  try {
    const failCount = await kv.get(`${CB_KV_PREFIX}${source}:fails`, 'text')
    const openFlag  = await kv.get(`${CB_KV_PREFIX}${source}:open`,  'text')

    if (openFlag) return 'open'
    const fails = failCount ? parseInt(failCount, 10) : 0
    return fails >= TRIP_THRESHOLD ? 'open' : 'closed'
  } catch {
    return 'closed'  // fail open
  }
}

export async function recordBreakerSuccess(
  source: string,
  kv: KVNamespace,
): Promise<void> {
  try {
    await kv.delete(`${CB_KV_PREFIX}${source}:fails`)
    await kv.delete(`${CB_KV_PREFIX}${source}:open`)
  } catch { /* ignore */ }
}

export async function recordBreakerFailure(
  source: string,
  kv: KVNamespace,
): Promise<void> {
  try {
    const raw = await kv.get(`${CB_KV_PREFIX}${source}:fails`, 'text')
    const fails = raw ? parseInt(raw, 10) + 1 : 1

    // Always update the failure counter (no expiry — reset only on success)
    await kv.put(`${CB_KV_PREFIX}${source}:fails`, String(fails))

    if (fails >= TRIP_THRESHOLD) {
      // Open the breaker for OPEN_TTL_SECONDS; after that KV TTL removes the
      // key and the next check returns half-open (first probe gets through).
      await kv.put(`${CB_KV_PREFIX}${source}:open`, '1', {
        expirationTtl: OPEN_TTL_SECONDS,
      })
    }
  } catch { /* ignore */ }
}
