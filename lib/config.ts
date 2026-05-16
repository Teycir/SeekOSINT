/**
 * config.ts — single source of truth for all runtime configuration.
 *
 * Eliminates scattered magic numbers across the codebase.
 * Import the relevant constant group from here instead of hard-coding values.
 *
 * Categories:
 *   RATE_LIMIT   — per-IP sliding-window rate limiter
 *   CIRCUIT_BREAKER — upstream source circuit breaker
 *   CVE          — CVE enrichment limits
 *   GHW          — GrayHatWarfare key-ring size
 *   HTTP         — fetch timeouts & concurrency
 */

// ─── Per-IP rate limiter ───────────────────────────────────────────────────────

export const RATE_LIMIT = {
  /** Sliding-window duration in seconds (1 hour). */
  WINDOW_SECONDS: 3600,
  /** Maximum requests per IP per window. */
  MAX_REQUESTS: 100,
  /** KV key prefix for rate-limit counters. */
  KV_PREFIX: 'rl:ip:',
} as const

// ─── Circuit breaker ───────────────────────────────────────────────────────────

export const CIRCUIT_BREAKER = {
  /** Rolling window for failure-ratio calculation (5 minutes). */
  WINDOW_TTL_SECONDS: 5 * 60,
  /** How long the breaker stays open before auto-recovery (15 minutes). */
  OPEN_TTL_SECONDS: 15 * 60,
  /** Failure ratio that trips the breaker (75 %). */
  TRIP_RATIO: 0.75,
  /** Minimum requests in a window before the breaker can trip.
   *  10 prevents a single flaky request from locking out a source. */
  MIN_REQUESTS_TO_TRIP: 10,
  /** KV key prefix for circuit-breaker state. */
  KV_PREFIX: 'cb:',
} as const

// ─── CVE enrichment ───────────────────────────────────────────────────────────

export const CVE = {
  /** Maximum CVEs fetched from NVD per lookup to avoid stampeding the API. */
  MAX_PER_LOOKUP: 20,
  /** Maximum concurrent NVD requests (used with p-limit or similar). */
  MAX_CONCURRENT: 10,
} as const

// ─── GrayHatWarfare ───────────────────────────────────────────────────────────

export const GHW = {
  /** Number of GrayHatWarfare API keys expected in the environment. */
  KEY_COUNT: 18,
  /** KV key prefix used by the KeyRing for GHW key rotation. */
  KV_RING_PREFIX: 'ghw',
} as const

// ─── HTTP / fetch ─────────────────────────────────────────────────────────────

export const HTTP = {
  /** Default request timeout in milliseconds (10 s). */
  TIMEOUT_MS: 10_000,
  /** Maximum retries on transient failures (5xx, network errors). */
  MAX_RETRIES: 3,
  /** Base delay for exponential back-off in milliseconds. */
  BACKOFF_BASE_MS: 200,
} as const

// ─── Cache TTLs (seconds) — canonical source; re-exported by lib/cache.ts ────

export const TTL_SECONDS = {
  CVE:        60 * 60 * 24 * 30, // 30 days  — immutable after publish
  WAYBACK:    60 * 60 * 24 * 7,  // 7 days
  BGP:        60 * 60 * 24,      // 24 hours
  RDAP:       60 * 60 * 24,
  ROBTEX:     60 * 60 * 24,
  CERTS:      60 * 60 * 12,      // 12 hours
  PASSIVEDNS: 60 * 60 * 12,
  GHW:        60 * 60 * 6,       // 6 hours
  CORE:       60 * 60,           // 1 hour   — internetdb, ipapi
  BLOCKLIST:  60 * 60,           //           Feodo + SSLBL bulk downloads
  ABUSECH:    60 * 30,           // 30 minutes
} as const
