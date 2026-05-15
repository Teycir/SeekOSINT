/**
 * lookup.ts — 4-layer execution orchestrator.
 *
 * Layer 1  always runs (Promise.allSettled — 7 sources)
 * Layer 2  runs in parallel with Layer 1 (no dependency)
 * Layer 3  fires only when InternetDB returns CVE IDs
 * Layer 4  domain queries only (GHW + Wayback); skipped for IP/ASN
 *
 * Circuit breakers
 * ─────────────────
 * Before each source is called, its breaker state is checked in KV.
 * If the breaker is OPEN the source is short-circuited with a 'skipped'
 * result — the 5-minute failure-ratio window stays intact and the source
 * auto-recovers after the 15-minute cooldown TTL expires.
 * Success / failure outcomes are fed back to the breaker after each call.
 *
 * Non-blocking D1 persistence via ctx.waitUntil().
 */
import type {
  BucketResult,
  CVEDetail,
  Env,
  HostResult,
  InternetDBResult,
  LookupQuery,
  SourceResult,
  WaybackResult,
} from '../lib/types'
import { KeyRing } from '../lib/keyring'
import { mergeResults } from '../lib/merge'
import { skipped, unwrap } from '../lib/results'
import { collectSecrets } from '../lib/validate'
import {
  getBreakerState,
  getAllBreakerStatuses,
  recordBreakerSuccess,
  recordBreakerFailure,
} from '../lib/ratelimit'

import { fetchInternetDB } from './sources/internetdb'
import { fetchIPAPI }      from './sources/ipapi'
import { fetchBGPView }    from './sources/bgpview'
import { fetchRDAP }       from './sources/rdap'
import { fetchCRTSH }      from './sources/crtsh'
import { fetchPassiveDNS } from './sources/passivedns'
import { fetchRobtex }     from './sources/robtex'
import {
  fetchURLhaus,
  fetchThreatFox,
  fetchMalwareBazaar,
  fetchFeodo,
  fetchSSLBL,
} from './sources/abusech'
import { CVE as CVE_CONFIG, GHW as GHW_CONFIG } from '../lib/config'
import { fetchCVEFull }       from './sources/nvd'
import { fetchGHWForQuery }   from './sources/grayhatwarfare'
import { fetchWayback }       from './sources/wayback'

// ─── All source names (must match the strings used inside each fetcher) ────────

const ALL_SOURCES = [
  'internetdb', 'ipapi', 'bgpview', 'rdap', 'crtsh',
  'passivedns', 'robtex',
  'urlhaus', 'threatfox', 'malwarebazaar', 'feodo', 'sslbl',
  'nvd', 'ghw', 'wayback',
] as const

// ─── Breaker-aware fetch wrapper ─────────────────────────────────────────────

/**
 * Wraps a source fetch with circuit-breaker guard.
 * - OPEN → immediately returns skipped()
 * - CLOSED / HALF-OPEN → calls fetcher, records success/failure
 */
async function withBreaker<T>(
  source: string,
  kv: KVNamespace,
  fetcher: () => Promise<SourceResult<T>>,
): Promise<SourceResult<T>> {
  const state = await getBreakerState(source, kv)
  if (state === 'open') {
    return skipped<T>(source)
  }

  const result = await fetcher()

  if (result.status === 'error') {
    await recordBreakerFailure(source, kv)
  } else {
    // ok, cached, skipped — all considered non-failures
    await recordBreakerSuccess(source, kv)
  }

  return result
}

// ─── D1 persistence ───────────────────────────────────────────────────────────

async function persistSearch(
  query: LookupQuery,
  result: HostResult,
  db: D1Database,
): Promise<void> {
  try {
    await db.prepare(
      `INSERT INTO searches (query, query_type, result_json, duration_ms)
       VALUES (?, ?, ?, ?)`,
    )
      .bind(
        query.normalised,
        query.type,
        JSON.stringify(result),
        result.meta.durationMs,
      )
      .run()
  } catch (err) {
    // Non-critical — log and continue
    console.error('[persist] D1 write failed', err)
  }
}

// ─── Main orchestrator ────────────────────────────────────────────────────────

export async function runLookup(
  query: LookupQuery,
  env: Env,
  ctx: ExecutionContext,
): Promise<HostResult> {
  const start = Date.now()

  // Key rings
  const ghwKeys = collectSecrets(env as Record<string, unknown>, 'GRAYHATWARFARE_API_KEY', GHW_CONFIG.KEY_COUNT)
  const ghwRing = new KeyRing(ghwKeys, env.KV, 'ghw')

  // ── Layers 1 + 2 run concurrently (each guarded by its circuit breaker) ──
  const [
    // Layer 1
    internetdbResult,
    geoResult,
    bgpResult,
    rdapResult,
    certsResult,
    passivednsResult,
    robtexResult,
    // Layer 2
    urlhausResult,
    threatfoxResult,
    malwarebazaarResult,
    feodoResult,
    sslblResult,
  ] = await Promise.allSettled([
    withBreaker('internetdb', env.KV, () => fetchInternetDB(query, env.KV)),
    withBreaker('ipapi',      env.KV, () => fetchIPAPI(query, env.KV)),
    withBreaker('bgpview',    env.KV, () => fetchBGPView(query, env.KV)),
    withBreaker('rdap',       env.KV, () => fetchRDAP(query, env.KV)),
    withBreaker('crtsh',      env.KV, () => fetchCRTSH(query, env.KV)),
    withBreaker('passivedns', env.KV, () => fetchPassiveDNS(query, env.KV)),
    withBreaker('robtex',     env.KV, () => fetchRobtex(query, env.KV)),
    withBreaker('urlhaus',       env.KV, () => fetchURLhaus(query, env.KV, env.ABUSECH_KEY)),
    withBreaker('threatfox',     env.KV, () => fetchThreatFox(query, env.KV, env.ABUSECH_KEY)),
    withBreaker('malwarebazaar', env.KV, () => fetchMalwareBazaar(query, env.KV, env.ABUSECH_KEY)),
    withBreaker('feodo',         env.KV, () => fetchFeodo(query, env.KV)),
    withBreaker('sslbl',         env.KV, () => fetchSSLBL(query, env.KV)),
  ])

  // ── Layer 3: CVE enrichment — only if InternetDB found CVEs ──────────────
  const idbData = unwrap<InternetDBResult>(internetdbResult)
  // Cap at configured max CVEs to avoid stampeding NVD with unbounded concurrent requests
  const cveIds = (idbData?.vulns ?? []).slice(0, CVE_CONFIG.MAX_PER_LOOKUP)

  const vulns = await Promise.allSettled(
    cveIds.map(id =>
      withBreaker('nvd', env.KV, () => fetchCVEFull(id, env.KV, env.NVD_KEY)),
    ),
  ) as PromiseSettledResult<SourceResult<CVEDetail>>[]

  // ── Layer 4: Bucket recon + Wayback — domain queries only ────────────────
  // Skip entirely for IP/ASN queries to avoid two no-op promise slots
  const [bucketsResult, waybackResult] = query.type === 'domain'
    ? await Promise.allSettled([
        withBreaker('ghw',     env.KV, () => fetchGHWForQuery(query, env.KV, ghwRing)),
        withBreaker('wayback', env.KV, () => fetchWayback(query, env.KV)),
      ])
    : [
        { status: 'fulfilled' as const, value: skipped<BucketResult[]>('ghw') },
        { status: 'fulfilled' as const, value: skipped<WaybackResult[]>('wayback') },
      ]

  // ── Collect breaker statuses for meta (non-blocking, best-effort) ─────────
  const circuitBreakers = await getAllBreakerStatuses([...ALL_SOURCES], env.KV)

  // ── Merge & return ────────────────────────────────────────────────────────
  const result = mergeResults({
    query,
    core: {
      internetdb: internetdbResult,
      geo:        geoResult,
      bgp:        bgpResult,
      rdap:       rdapResult,
      certs:      certsResult,
      passivedns: passivednsResult,
      robtex:     robtexResult,
    },
    threat: {
      urlhaus:       urlhausResult,
      threatfox:     threatfoxResult,
      malwarebazaar: malwarebazaarResult,
      feodo:         feodoResult,
      sslbl:         sslblResult,
    },
    vulns,
    recon: {
      buckets: bucketsResult,
      wayback: waybackResult,
    },
    durationMs:      Date.now() - start,
    circuitBreakers,
  })

  // Non-blocking D1 write
  ctx.waitUntil(persistSearch(query, result, env.DB))

  return result
}
