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
 * Tracks requests and failures for each upstream source in a 5-minute
 * rolling window stored in KV.  The breaker OPENS when the failure
 * ratio exceeds 50 % of requests in that window.  After a 15-minute
 * cooldown (OPEN_TTL_SECONDS) the KV key expires and the breaker
 * moves to 'half-open': the next request probes through; if it
 * succeeds the breaker resets to 'closed'.
 *
 * KV schema (all keys prefixed with "cb:<source>:")
 *   :window_reqs  – total requests in the current 5-min window (TTL = 5 min)
 *   :window_fails – failures in the current 5-min window    (TTL = 5 min)
 *   :open         – presence means breaker is open          (TTL = 15 min)
 */

import { RATE_LIMIT, CIRCUIT_BREAKER } from './config'

// ─── Log sanitization ─────────────────────────────────────────────────────────

/**
 * Sanitize user input before logging to prevent log injection (CWE-117).
 * Removes newlines, carriage returns, and other control characters.
 */
function sanitizeForLog(input: string): string {
  return input.replace(/[\r\n\t\x00-\x1F\x7F]/g, '')
}

// ─── Per-IP rate limiter ──────────────────────────────────────────────────────

export interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetInSeconds: number
}

const RL_WINDOW_SECONDS = RATE_LIMIT.WINDOW_SECONDS
const RL_MAX_REQUESTS   = RATE_LIMIT.MAX_REQUESTS
const RL_KV_PREFIX      = RATE_LIMIT.KV_PREFIX

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

const CB_KV_PREFIX          = CIRCUIT_BREAKER.KV_PREFIX
const WINDOW_TTL_SECONDS    = CIRCUIT_BREAKER.WINDOW_TTL_SECONDS
const OPEN_TTL_SECONDS      = CIRCUIT_BREAKER.OPEN_TTL_SECONDS
const TRIP_RATIO            = CIRCUIT_BREAKER.TRIP_RATIO
const MIN_REQUESTS_TO_TRIP  = CIRCUIT_BREAKER.MIN_REQUESTS_TO_TRIP

export type BreakerState = 'closed' | 'open' | 'half-open'

export interface BreakerStatus {
  source: string
  state: BreakerState
  /** Requests counted in the current 5-min window */
  windowRequests: number
  /** Failures counted in the current 5-min window */
  windowFailures: number
  /** Unix-ms when the open key expires (i.e. recovery time); 0 if closed */
  opensUntil: number
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function reqKey  (source: string) { return `${CB_KV_PREFIX}${source}:window_reqs`  }
function failKey (source: string) { return `${CB_KV_PREFIX}${source}:window_fails` }
function openKey (source: string) { return `${CB_KV_PREFIX}${source}:open`         }

async function getWindowCounts(
  source: string,
  kv: KVNamespace,
): Promise<{ reqs: number; fails: number }> {
  try {
    const [r, f] = await Promise.all([
      kv.get(reqKey(source),  'text'),
      kv.get(failKey(source), 'text'),
    ])
    return {
      reqs:  r ? parseInt(r, 10) : 0,
      fails: f ? parseInt(f, 10) : 0,
    }
  } catch (err) {
    console.error(`[ratelimit] getWindowCounts failed for source=${sanitizeForLog(source)}:`, err)
    return { reqs: 0, fails: 0 }
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Returns the current breaker state for a source.
 * 'half-open' is signalled by the absence of the :open key (it expired)
 * combined with a non-zero failure history in the window.
 */
export async function getBreakerState(
  source: string,
  kv: KVNamespace,
): Promise<BreakerState> {
  try {
    const openFlag = await kv.get(openKey(source), 'text')
    if (openFlag !== null) return 'open'

    // If the open key has expired, the next probe is 'half-open'
    const { reqs, fails } = await getWindowCounts(source, kv)
    if (reqs >= MIN_REQUESTS_TO_TRIP && fails / reqs > TRIP_RATIO) {
      // Window counts are still warm but the open flag expired → half-open
      return 'half-open'
    }

    return 'closed'
  } catch (err) {
    console.error(`[ratelimit] getBreakerState failed for source=${sanitizeForLog(source)}:`, err)
    return 'closed'
  }
}

/**
 * Full status snapshot for a single source (used by the admin endpoint
 * and the meta block in API responses).
 */
export async function getBreakerStatus(
  source: string,
  kv: KVNamespace,
): Promise<BreakerStatus> {
  try {
    const [openMeta, { reqs, fails }] = await Promise.all([
      kv.getWithMetadata<{ expiration?: number }>(openKey(source)),
      getWindowCounts(source, kv),
    ])

    const isOpen    = openMeta.value !== null
    const opensUntil = isOpen && openMeta.metadata?.expiration
      ? openMeta.metadata.expiration * 1000   // KV expiration is unix-seconds
      : 0

    let state: BreakerState = 'closed'
    if (isOpen) {
      state = 'open'
    } else if (reqs >= MIN_REQUESTS_TO_TRIP && fails / reqs > TRIP_RATIO) {
      state = 'half-open'
    }

    return { source, state, windowRequests: reqs, windowFailures: fails, opensUntil }
  } catch (err) {
    console.error(`[ratelimit] getBreakerStatus failed for source=${sanitizeForLog(source)}:`, err)
    return { source, state: 'closed', windowRequests: 0, windowFailures: 0, opensUntil: 0 }
  }
}

/**
 * Bulk-fetch status for every source in one call (used by mergeResults).
 */
export async function getAllBreakerStatuses(
  sources: string[],
  kv: KVNamespace,
): Promise<BreakerStatus[]> {
  return Promise.all(sources.map(s => getBreakerStatus(s, kv)))
}

/**
 * Call on a successful response from a source.
 * Resets the failure/request window so closed stays closed.
 */
export async function recordBreakerSuccess(
  source: string,
  kv: KVNamespace,
): Promise<void> {
  try {
    await Promise.all([
      kv.delete(reqKey(source)),
      kv.delete(failKey(source)),
      kv.delete(openKey(source)),
    ])
  } catch (err) {
    console.error(`[ratelimit] recordBreakerSuccess failed for source=${sanitizeForLog(source)}:`, err)
  }
}

/**
 * Call on any failed response from a source (non-2xx, timeout, etc.).
 * Increments counters; opens the breaker when the failure ratio exceeds
 * TRIP_RATIO within the 5-minute window.
 */
export async function recordBreakerFailure(
  source: string,
  kv: KVNamespace,
): Promise<void> {
  try {
    const { reqs: prevReqs, fails: prevFails } = await getWindowCounts(source, kv)

    const newReqs  = prevReqs  + 1
    const newFails = prevFails + 1

    // Write updated counters; TTL resets the window after 5 minutes
    await Promise.all([
      kv.put(reqKey(source),  String(newReqs),  { expirationTtl: WINDOW_TTL_SECONDS }),
      kv.put(failKey(source), String(newFails), { expirationTtl: WINDOW_TTL_SECONDS }),
    ])

    // Trip the breaker when ratio > 50 % and we have enough data points
    if (newReqs >= MIN_REQUESTS_TO_TRIP && newFails / newReqs > TRIP_RATIO) {
      await kv.put(openKey(source), '1', { expirationTtl: OPEN_TTL_SECONDS })
    }
  } catch (err) {
    console.error(`[ratelimit] recordBreakerFailure failed for source=${sanitizeForLog(source)}:`, err)
  }
}

/**
 * Record a successful request without resetting the failure counters.
 * Used by sources to increment the request counter even on cache hits
 * so the ratio calculation stays accurate.
 */
export async function recordBreakerRequest(
  source: string,
  kv: KVNamespace,
): Promise<void> {
  try {
    const raw = await kv.get(reqKey(source), 'text')
    const next = (raw ? parseInt(raw, 10) : 0) + 1
    await kv.put(reqKey(source), String(next), { expirationTtl: WINDOW_TTL_SECONDS })
  } catch (err) {
    console.error(`[ratelimit] recordBreakerRequest failed for source=${sanitizeForLog(source)}:`, err)
  }
}

/**
 * Manually reset a circuit breaker — clears open flag and window counters.
 * Called by the admin endpoint.
 */
export async function resetBreaker(
  source: string,
  kv: KVNamespace,
): Promise<void> {
  await Promise.all([
    kv.delete(reqKey(source)),
    kv.delete(failKey(source)),
    kv.delete(openKey(source)),
  ])
}
