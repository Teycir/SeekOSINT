/**
 * lib/logger.ts — structured JSON logger for Cloudflare Workers tail logs.
 *
 * Two entry kinds:
 *
 *   Diagnostic   — generic info/warn/error for source errors, breaker events, etc.
 *   Provenance   — one entry per inbound request and per outbound fetch, capturing
 *                  who asked (caller IP, ray ID), what they asked for (query),
 *                  where we went (outbound URL + source), and what happened
 *                  (HTTP status, latency, cache hit, SSRF block).
 *
 * All entries are JSON-newline on stdout/stderr so Cloudflare logpush and
 * `wrangler tail --format json` can parse them without further processing.
 *
 * Usage:
 *   import { log } from './logger'
 *   log.info('internetdb', '1.2.3.4', 'completed', { durationMs: 312 })
 *   log.provenance({ kind: 'inbound', ... })
 *   log.provenance({ kind: 'outbound', ... })
 */

type LogLevel = 'info' | 'warn' | 'error'

// ─── Diagnostic entries ───────────────────────────────────────────────────────

interface LogEntry {
  level:   LogLevel
  source:  string
  query:   string
  message: string
  ts:      number
  [key: string]: unknown
}

function emit(
  level:   LogLevel,
  source:  string,
  query:   string,
  message: string,
  extra?:  Record<string, unknown>,
): void {
  const entry: LogEntry = { level, source, query, message, ts: Date.now(), ...extra }
  const line = JSON.stringify(entry)
  if      (level === 'error') console.error(line)
  else if (level === 'warn')  console.warn(line)
  else                        console.log(line)
}

// ─── Provenance entries ───────────────────────────────────────────────────────

/**
 * An inbound provenance entry is emitted once per incoming API request.
 * It records who is calling, what they asked for, and whether the request
 * was allowed through (rate limit, Turnstile, concurrency, SSRF gate).
 */
export interface InboundProvenance {
  kind:          'inbound'
  /** Source IP of the caller (CF-Connecting-IP or X-Forwarded-For[0]). */
  callerIp:      string
  /** Cloudflare ray ID — correlates with CF logs and R2 logpush. */
  rayId?:        string
  /** Country of the caller (CF-IPCountry header). */
  country?:      string
  /** Normalised query string, e.g. "1.2.3.4" or "example.com". */
  query:         string
  /** Query type resolved by parseQuery(). */
  queryType:     'ip' | 'domain' | 'asn' | 'unknown'
  /** HTTP method of the inbound request. */
  method:        string
  /** Which API endpoint received the request. */
  endpoint:      string
  /** Whether the request was served from KV cache (no upstream fan-out). */
  fromCache:     boolean
  /** Whether the Turnstile bot challenge passed. */
  turnstilePassed?: boolean
  /** Rate-limit state at time of request. */
  rateLimitRemaining?: number
  /** Concurrency slot count at time of request. */
  concurrencyActive?: number
  /** Final disposition of the inbound request. */
  outcome:       'allowed' | 'rate_limited' | 'concurrency_limited' | 'bot_blocked' | 'invalid_query' | 'error'
  /** HTTP status returned to the caller. */
  statusCode:    number
  /** Total wall-clock time (ms) from request receipt to response send. */
  durationMs:    number
}

/**
 * An outbound provenance entry is emitted once per upstream fetch attempt
 * inside each source file (via safeFetch or the withBreaker wrapper).
 * It records what we called, whether it was blocked (SSRF), and the outcome.
 */
export interface OutboundProvenance {
  kind:           'outbound'
  /** Source name, e.g. "internetdb", "nvd". */
  source:         string
  /** Normalised query that triggered this outbound call. */
  query:          string
  /** Exact URL dispatched to the upstream (may be redacted for API keys). */
  url:            string
  /** Whether the fetch was blocked by SSRF validation before hitting the network. */
  ssrfBlocked:    boolean
  /** The SSRF block reason, if ssrfBlocked is true. */
  ssrfReason?:    string
  /** HTTP status returned by the upstream. null if the call was blocked or threw. */
  statusCode:     number | null
  /** Whether the response was a KV cache hit (no network I/O). */
  fromCache:      boolean
  /** Whether the upstream circuit breaker was open (call short-circuited). */
  breakerOpen:    boolean
  /** Round-trip latency in ms (0 for cache hits and SSRF-blocked calls). */
  durationMs:     number
  /** Error message if the fetch threw or returned a non-ok status. */
  errorMsg?:      string
}

export type ProvenanceEntry = InboundProvenance | OutboundProvenance

function emitProvenance(entry: ProvenanceEntry): void {
  const line = JSON.stringify({ level: 'info', ts: Date.now(), ...entry })
  console.log(line)
}

// ─── Exported API ─────────────────────────────────────────────────────────────

export const log = {
  info(source: string, query: string, message: string, extra?: Record<string, unknown>): void {
    emit('info', source, query, message, extra)
  },
  warn(source: string, query: string, message: string, extra?: Record<string, unknown>): void {
    emit('warn', source, query, message, extra)
  },
  error(source: string, query: string, message: string, extra?: Record<string, unknown>): void {
    emit('error', source, query, message, extra)
  },

  /**
   * Emit a structured provenance entry.  Call once per inbound request
   * (from the API route) and once per outbound upstream fetch (from each
   * source file or the withBreaker wrapper in lookup.ts).
   */
  provenance(entry: ProvenanceEntry): void {
    emitProvenance(entry)
  },
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Redact the apiKey / Auth-Key query param from a URL string so it never
 * appears in logs.  Covers both ?apiKey=… and &apiKey=… patterns plus the
 * NVD ?apiKey= convention.
 */
export function redactUrl(url: string): string {
  try {
    const u = new URL(url)
    // Remove common API key param names
    for (const key of ['apiKey', 'api_key', 'Auth-Key', 'key', 'token', 'access_token']) {
      if (u.searchParams.has(key)) u.searchParams.set(key, '[REDACTED]')
    }
    return u.toString()
  } catch {
    // If the URL is somehow unparseable, redact the whole thing
    return '[UNPARSEABLE_URL]'
  }
}

/**
 * Extract the caller IP from an inbound Request.
 * Returns 'unknown' if neither CF-Connecting-IP nor X-Forwarded-For is present.
 */
export function extractCallerIp(req: Request): string {
  return (
    req.headers.get('CF-Connecting-IP') ??
    req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
    'unknown'
  )
}
