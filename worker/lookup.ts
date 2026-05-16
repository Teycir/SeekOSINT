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
  BGPViewResult,
  BucketResult,
  CVEDetail,
  Env,
  HostResult,
  InternetDBResult,
  LookupQuery,
  SourceResult,
  URLhausResult,
  ThreatFoxResult,
  MalwareBazaarResult,
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

// ─── DNS resolution (domain → IP) ─────────────────────────────────────────────

/**
 * Resolve a domain to its first A record using Cloudflare DoH.
 * Returns null if resolution fails or the domain has no A record.
 * Result is cached in KV for 5 minutes (short TTL — DNS can change).
 */
async function resolveDomainToIP(
  domain: string,
  kv: KVNamespace,
  forceRefresh: boolean,
): Promise<string | null> {
  const cacheKey = `dns:a:${domain}`

  if (!forceRefresh) {
    const cached = await kv.get(cacheKey)
    if (cached) return cached  // only successful IPs are ever cached (see below)
  }

  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(5000),
      },
    )
    if (!res.ok) return null
    const json = await res.json() as { Answer?: { type: number; data: string }[] }
    const ip = json.Answer?.find(r => r.type === 1)?.data ?? null
    // Only cache successful resolutions — never cache null/failures so that
    // a transient DNS timeout doesn't poison the cache for 5 minutes.
    if (ip) await kv.put(cacheKey, ip, { expirationTtl: 300 })
    return ip
  } catch (err) {
    console.error('[lookup] DNS resolution failed for', domain, err)
    return null
  }
}

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
 * - OPEN + cache hit  → returns cached data (status 'cached') so stale
 *   results are still shown while the upstream recovers.
 * - OPEN + cache miss → returns skipped() — nothing to show.
 * - CLOSED / HALF-OPEN → calls fetcher, records success/failure.
 *
 * The optional `cacheKey` enables the cache-fallback path.  Pass it for
 * any source whose KV key is trivially derivable here (crtsh, rdap, etc.)
 * If omitted, OPEN always returns skipped() (original behaviour).
 */
async function withBreaker<T>(
  source: string,
  kv: KVNamespace,
  fetcher: () => Promise<SourceResult<T>>,
  cacheKey?: string,
): Promise<SourceResult<T>> {
  const state = await getBreakerState(source, kv)
  if (state === 'open') {
    // Try to serve stale cache rather than returning nothing
    if (cacheKey) {
      try {
        const raw = await kv.get(cacheKey)
        if (raw) {
          return { source, status: 'cached', data: JSON.parse(raw) as T }
        }
      } catch {
        // Cache read failed — fall through to skipped
      }
    }
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

// ─── CVE batch helper ─────────────────────────────────────────────────────────

/**
 * Fetch CVE details in batches of CVE_CONFIG.MAX_CONCURRENT (default 5).
 * Sequential batches prevent stampeding NVD's rate limit while still being
 * ~5× faster than fully sequential lookups on CVE-heavy hosts.
 */
async function fetchCVEsBatched(
  cveIds: string[],
  kv: KVNamespace,
  nvdKey: string,
  forceRefresh: boolean,
): Promise<PromiseSettledResult<SourceResult<CVEDetail>>[]> {
  const results: PromiseSettledResult<SourceResult<CVEDetail>>[] = []
  const batchSize = CVE_CONFIG.MAX_CONCURRENT  // 5

  for (let i = 0; i < cveIds.length; i += batchSize) {
    const batch = cveIds.slice(i, i + batchSize)
    const settled = await Promise.allSettled(
      batch.map(id =>
        withBreaker('nvd', kv, () => fetchCVEFull(id, kv, nvdKey, forceRefresh)),
      ),
    )
    results.push(...settled)
  }

  return results
}

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

  // ── For domain queries: resolve to IP first so IP-only sources are useful ──
  // This runs before the main layer fan-out and adds ~50ms in the best case
  // (DoH is fast; result is KV-cached for 5 min).
  let ipQuery: LookupQuery | null = null
  if (query.type === 'domain') {
    const resolvedIP = await resolveDomainToIP(
      query.normalised,
      env.KV,
      query.forceRefresh ?? false,
    )
    if (resolvedIP) {
      ipQuery = {
        raw: resolvedIP,
        type: 'ip',
        normalised: resolvedIP,
        forceRefresh: query.forceRefresh ?? false,
      }
    }
  }

  // ── For ASN queries: derive a representative IP from the first announced
  //    prefix so that IP-only sources (InternetDB, ip-api, Robtex, threat
  //    intel) can be fanned in.  Without this every ASN query returns only
  //    the single BGPView card.
  let asnSyntheticIPQuery: LookupQuery | null = null
  if (query.type === 'asn') {
    // BGPView is called first in a short pre-flight to get the prefix list.
    // We use it to pick the first /24 host (.1) as the representative IP.
    const bgpPreflight = await withBreaker(
      'bgpview', env.KV, () => fetchBGPView(query, env.KV),
    )
    const bgpData = (bgpPreflight.status === 'ok' || bgpPreflight.status === 'cached') 
      ? bgpPreflight.data as BGPViewResult | null
      : null
    const firstPrefix = bgpData?.prefixes?.[0]
    if (firstPrefix) {
      // e.g. "185.26.182.0/24" → "185.26.182.1"
      const network = firstPrefix.split('/')[0]
      if (network) {
        const parts = network.split('.')
        parts[3] = '1'
        const syntheticIP = parts.join('.')
        asnSyntheticIPQuery = {
          raw: syntheticIP,
          type: 'ip',
          normalised: syntheticIP,
          forceRefresh: query.forceRefresh ?? false,
        }
      }
    }
  }

  // The effective IP query used for IP-only sources:
  //   IP query   → the original query
  //   domain     → the DNS-resolved IP
  //   ASN        → the synthetic IP derived from the first announced prefix
  const effectiveIPQuery: LookupQuery = ipQuery ?? asnSyntheticIPQuery ?? query

  // ── CDN / anycast detection ────────────────────────────────────────────────
  // Run InternetDB as a pre-flight. If the effective IP is tagged as CDN/proxy,
  // IP-specific sources (ip-api, robtex, bgpview, feodo, sslbl, threat-intel-IP)
  // will either fail or return meaningless shared-infrastructure data.
  // We skip them and rely on domain-string sources instead, which avoids
  // tripping circuit breakers on every Cloudflare-proxied domain lookup.
  //
  // CDN tags in InternetDB: 'cdn', 'cloud', 'proxy' (set by Shodan)
  const CDN_TAGS = new Set(['cdn', 'cloud', 'proxy'])

  let internetdbPreflight: SourceResult<InternetDBResult> | null = null
  let isCDNIP = false

  // Only run the pre-flight when we have a resolved IP from a domain query
  // (ASN synthetic IPs and direct IP queries are never CDN-tagged meaningfully).
  if (query.type === 'domain' && ipQuery !== null) {
    const preflight = await withBreaker(
      'internetdb', env.KV, () => fetchInternetDB(ipQuery, env.KV),
    )
    internetdbPreflight = preflight
    if (preflight.status === 'ok' || preflight.status === 'cached') {
      const tags = (preflight.data?.tags ?? []).map(t => t.toLowerCase())
      isCDNIP = tags.some(t => CDN_TAGS.has(t))
      if (isCDNIP) {
        console.log(
          `[lookup] CDN IP detected for ${query.normalised} (${ipQuery.normalised}) — skipping IP-specific sources`,
        )
      }
    }
  }

  // ── Layers 1 + 2 run concurrently (each guarded by its circuit breaker) ──
  //
  // For domain queries, threat intel is run against BOTH the original domain
  // string AND the resolved IP in parallel, then the best result is selected.
  // A domain listed as malicious in URLhaus/ThreatFox must not get a clean
  // result just because we searched the resolved IP instead of the domain name.
  //
  // Exception: when isCDNIP is true, the IP-path threat intel is skipped —
  // searching a shared Cloudflare anycast IP in abuse.ch returns noise.
  const domainQuery = query.type === 'domain' ? query : null

  const [
    // Layer 1
    internetdbResult,
    geoResult,
    bgpResult,
    rdapResult,
    certsResult,
    passivednsResult,
    robtexResult,
    // Layer 2 — IP-based threat intel
    urlhausIPResult,
    threatfoxIPResult,
    malwarebazaarIPResult,
    feodoResult,
    sslblResult,
    // Layer 2 — domain-string threat intel (null slots for non-domain queries)
    urlhausDomainResult,
    threatfoxDomainResult,
    malwarebazaarDomainResult,
  ] = await Promise.allSettled([
    // InternetDB: use pre-flight result when available (CDN detection ran it already)
    internetdbPreflight !== null
      ? Promise.resolve(internetdbPreflight)
      : withBreaker('internetdb', env.KV, () => fetchInternetDB(effectiveIPQuery, env.KV)),

    // ip-api, bgpview, robtex — skip for CDN IPs (they fail or return noise)
    isCDNIP
      ? Promise.resolve({ source: 'ipapi',   status: 'skipped' as const, data: null })
      : withBreaker('ipapi', env.KV, () => fetchIPAPI(effectiveIPQuery, env.KV)),
    isCDNIP
      ? Promise.resolve({ source: 'bgpview', status: 'skipped' as const, data: null })
      : withBreaker('bgpview', env.KV, () => fetchBGPView(effectiveIPQuery, env.KV)),

    // Domain + IP sources: always run regardless of CDN status
    withBreaker('rdap',       env.KV, () => fetchRDAP(query, env.KV),       `rdap:domain:${query.normalised}`),
    withBreaker('crtsh',      env.KV, () => fetchCRTSH(query, env.KV),      `crtsh:${query.normalised}`),
    withBreaker('passivedns', env.KV, () => fetchPassiveDNS(query, env.KV, ipQuery), `passivedns:${query.normalised}`),

    // Robtex — skip for CDN IPs
    isCDNIP
      ? Promise.resolve(skipped<ReturnType<typeof fetchRobtex> extends Promise<SourceResult<infer T>> ? T : never>('robtex'))
      : withBreaker('robtex', env.KV, () => fetchRobtex(effectiveIPQuery, env.KV)),

    // Threat intel — IP path: skip for CDN IPs (shared anycast = noise)
    isCDNIP
      ? Promise.resolve({ source: 'urlhaus',       status: 'skipped' as const, data: null })
      : withBreaker('urlhaus',       env.KV, () => fetchURLhaus(effectiveIPQuery, env.KV, env.ABUSECH_KEY)),
    isCDNIP
      ? Promise.resolve({ source: 'threatfox',     status: 'skipped' as const, data: null })
      : withBreaker('threatfox',     env.KV, () => fetchThreatFox(effectiveIPQuery, env.KV, env.ABUSECH_KEY)),
    isCDNIP
      ? Promise.resolve({ source: 'malwarebazaar', status: 'skipped' as const, data: null })
      : withBreaker('malwarebazaar', env.KV, () => fetchMalwareBazaar(effectiveIPQuery, env.KV, env.ABUSECH_KEY)),

    // Feodo / SSLBL: D1 blocklists — skip for CDN IPs
    isCDNIP
      ? Promise.resolve({ source: 'feodo', status: 'skipped' as const, data: null })
      : withBreaker('feodo', env.KV, () => fetchFeodo(effectiveIPQuery, env.DB)),
    isCDNIP
      ? Promise.resolve({ source: 'sslbl', status: 'skipped' as const, data: null })
      : withBreaker('sslbl', env.KV, () => fetchSSLBL(effectiveIPQuery, env.DB)),

    // Threat intel — domain-string path (only for domain queries; always runs regardless of CDN)
    domainQuery
      ? withBreaker('urlhaus',       env.KV, () => fetchURLhaus(domainQuery, env.KV, env.ABUSECH_KEY))
      : Promise.resolve({ source: 'urlhaus',       status: 'skipped' as const, data: null }),
    domainQuery
      ? withBreaker('threatfox',     env.KV, () => fetchThreatFox(domainQuery, env.KV, env.ABUSECH_KEY))
      : Promise.resolve({ source: 'threatfox',     status: 'skipped' as const, data: null }),
    domainQuery
      ? withBreaker('malwarebazaar', env.KV, () => fetchMalwareBazaar(domainQuery, env.KV, env.ABUSECH_KEY))
      : Promise.resolve({ source: 'malwarebazaar', status: 'skipped' as const, data: null }),
  ])

  // ── Merge dual threat intel results — prefer the more alarming result ──────
  // If either the IP or domain query shows a hit, that result wins.
  function pickWorstURLhaus(
    a: PromiseSettledResult<SourceResult<URLhausResult>>,
    b: PromiseSettledResult<SourceResult<URLhausResult>>,
  ): PromiseSettledResult<SourceResult<URLhausResult>> {
    const dataA = a.status === 'fulfilled' ? (a.value.data as URLhausResult | null) : null
    const dataB = b.status === 'fulfilled' ? (b.value.data as URLhausResult | null) : null
    if (dataA?.query_status === 'is_host') return a
    if (dataB?.query_status === 'is_host') return b
    return a
  }

  function pickWorstThreatFox(
    a: PromiseSettledResult<SourceResult<ThreatFoxResult>>,
    b: PromiseSettledResult<SourceResult<ThreatFoxResult>>,
  ): PromiseSettledResult<SourceResult<ThreatFoxResult>> {
    const dataA = a.status === 'fulfilled' ? (a.value.data as ThreatFoxResult | null) : null
    const dataB = b.status === 'fulfilled' ? (b.value.data as ThreatFoxResult | null) : null
    const countA = dataA?.data?.length ?? 0
    const countB = dataB?.data?.length ?? 0
    return countA >= countB ? a : b
  }

  function pickWorstMB(
    a: PromiseSettledResult<SourceResult<MalwareBazaarResult>>,
    b: PromiseSettledResult<SourceResult<MalwareBazaarResult>>,
  ): PromiseSettledResult<SourceResult<MalwareBazaarResult>> {
    const dataA = a.status === 'fulfilled' ? (a.value.data as MalwareBazaarResult | null) : null
    const dataB = b.status === 'fulfilled' ? (b.value.data as MalwareBazaarResult | null) : null
    if (dataA?.query_status === 'ok') return a
    if (dataB?.query_status === 'ok') return b
    return a
  }

  const urlhausResult       = pickWorstURLhaus(urlhausIPResult as PromiseSettledResult<SourceResult<URLhausResult>>,       urlhausDomainResult as PromiseSettledResult<SourceResult<URLhausResult>>)
  const threatfoxResult     = pickWorstThreatFox(threatfoxIPResult as PromiseSettledResult<SourceResult<ThreatFoxResult>>,   threatfoxDomainResult as PromiseSettledResult<SourceResult<ThreatFoxResult>>)
  const malwarebazaarResult = pickWorstMB(malwarebazaarIPResult as PromiseSettledResult<SourceResult<MalwareBazaarResult>>, malwarebazaarDomainResult as PromiseSettledResult<SourceResult<MalwareBazaarResult>>)

  // ── Layer 3: CVE enrichment — batched 5-at-a-time ────────────────────────
  const idbData = unwrap<InternetDBResult>(internetdbResult)
  const cveIds = (idbData?.vulns ?? []).slice(0, CVE_CONFIG.MAX_PER_LOOKUP)

  const vulns = await fetchCVEsBatched(
    cveIds, env.KV, env.NVD_KEY, query.forceRefresh ?? false,
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
    // Pass the DoH-resolved IP explicitly so merge always shows it even
    // when geo/ipapi was skipped (CDN path). Also signals DNS failure.
    resolvedIP:         ipQuery?.normalised ?? null,
    dnsResolutionFailed: query.type === 'domain' && ipQuery === null,
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
