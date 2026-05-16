/**
 * config.ts — single source of truth for all runtime configuration.
 *
 * Eliminates scattered magic numbers across the codebase.
 * Import the relevant constant group from here instead of hard-coding values.
 *
 * Categories:
 *   RATE_LIMIT   — per-IP sliding-window rate limiter
 *   CONCURRENCY  — global parallel-request cap (protects upstream sources)
 *   CIRCUIT_BREAKER — upstream source circuit breaker
 *   CVE          — CVE enrichment limits
 *   GHW          — GrayHatWarfare key-ring size
 *   HTTP         — fetch timeouts & concurrency
 */

// ─── Per-IP rate limiter ───────────────────────────────────────────────────────

export const RATE_LIMIT = {
  /** Sliding-window duration in seconds (1 hour). */
  WINDOW_SECONDS: 3600,
  /**
   * Maximum requests per IP per window.
   * 500 is generous for a legitimate researcher doing multi-host investigations
   * while still blocking scrapers.
   */
  MAX_REQUESTS: 500,
  /** KV key prefix for rate-limit counters. */
  KV_PREFIX: 'rl:ip:',
} as const

// ─── Global concurrency limiter ────────────────────────────────────────────────

export const CONCURRENCY = {
  /**
   * Maximum number of lookup requests that may run simultaneously across
   * ALL users. Once this ceiling is hit, new requests receive 429 with a
   * Retry-After header. Keep this low: a single lookup fans out to ~15
   * parallel upstream fetches internally.
   */
  MAX_PARALLEL: 10,
  /**
   * How long (seconds) a concurrency slot is held before it is automatically
   * released, even if the worker crashes without calling releaseConcurrency().
   * Must be comfortably longer than the worst-case lookup (NVD can be slow).
   */
  SLOT_TTL_SECONDS: 90,
  /** KV key that stores the current active slot count (plain integer). */
  KV_KEY: 'concurrency:active',
} as const

// ─── Circuit breaker ───────────────────────────────────────────────────────────

export const CIRCUIT_BREAKER = {
  /** Rolling window for failure-ratio calculation (5 minutes). */
  WINDOW_TTL_SECONDS: 5 * 60,
  /**
   * How long the breaker stays open before auto-recovery (5 minutes).
   * Short recovery is fine because certspotter covers the cold-start gap
   * and the window counters expire on their own TTL anyway.
   */
  OPEN_TTL_SECONDS: 5 * 60,
  /**
   * Failure ratio that trips the breaker (95 %).
   * crt.sh and other rate-limited sources regularly return 429s on individual
   * requests without being "down". We only want to trip on near-total outages,
   * not on a noisy burst.  95 % means 19 of 20 requests must fail within
   * the 5-minute window before the breaker opens.
   */
  TRIP_RATIO: 0.95,
  /**
   * Minimum requests in a window before the breaker can trip.
   * 50 means we need at least 50 requests in 5 minutes before even evaluating
   * the ratio — this is a high-traffic guard that completely eliminates
   * false trips from cold-start bursts or small test runs.
   */
  MIN_REQUESTS_TO_TRIP: 50,
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
