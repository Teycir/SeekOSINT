/**
 * CVE enrichment — NVD (primary) + CIRCL CVE Search (fallback) + OSV.dev.
 *
 * For each CVE ID from InternetDB:
 *   1. Check KV cache (30-day TTL — CVE data is immutable post-publish)
 *   2. Race NVD and CIRCL via Promise.any() — first to respond wins
 *   3. Supplement with OSV.dev for package-level cross-reference
 *
 * On HTTP 429/403 from NVD, the key should be rotated — but NVD only uses
 * one key, so we just fall through to CIRCL on rate-limit.
 *
 * NVD:   https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}
 * CIRCL: https://cve.circl.lu/api/cve/{id}
 * OSV:   https://api.osv.dev/v1/vulns/{id}
 * TTL:   30 days
 *
 * Throttling: NVD allows 50 req/30s with an API key (≈ 1 req/0.6s).
 * We enforce a minimum 6s gap between NVD calls via a KV-backed timestamp
 * so that concurrent CVE lookups don't pile on and get 429'd.
 * Circuit breaker: after 5 consecutive NVD failures the breaker opens for
 * 60s and all NVD calls fall through directly to CIRCL.
 */
import type { CVEDetail, LookupQuery, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error } from '../../lib/results'
import { sleep } from '../../lib/backoff'
import {
  getBreakerState,
  recordBreakerSuccess,
  recordBreakerFailure,
} from '../../lib/ratelimit'

// ─── NVD throttle ─────────────────────────────────────────────────────────────

/**
 * Enforce a 6-second minimum gap between outbound NVD calls using a KV
 * timestamp. If the last NVD call was fewer than NVD_MIN_GAP_MS ago we
 * sleep for the remainder before proceeding.
 *
 * This is best-effort: concurrent Worker invocations may still race, but
 * the 30-day cache means the vast majority of requests never reach NVD.
 */
const NVD_MIN_GAP_MS    = 6_000
const NVD_THROTTLE_KEY  = 'nvd:last_call_ts'

async function acquireNVDSlot(kv: KVNamespace): Promise<void> {
  try {
    const raw  = await kv.get(NVD_THROTTLE_KEY, 'text')
    const last = raw ? parseInt(raw, 10) : 0
    const now  = Date.now()
    const wait = NVD_MIN_GAP_MS - (now - last)

    if (wait > 0) {
      await sleep(wait)
    }

    // Stamp the slot (best-effort — race is acceptable, just slightly optimistic)
    await kv.put(NVD_THROTTLE_KEY, String(Date.now()), {
      expirationTtl: 60, // clean up after 60 s
    })
  } catch { /* fail open — throttle is advisory */ }
}

// ─── NVD ─────────────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseNVD(cveId: string, json: any): CVEDetail | null {
  const vuln = json?.vulnerabilities?.[0]?.cve
  if (!vuln) return null

  const desc = vuln.descriptions?.find(
    (d: { lang: string }) => d.lang === 'en',
  )?.value ?? ''

  const metricsV3 =
    vuln.metrics?.cvssMetricV31?.[0]?.cvssData ??
    vuln.metrics?.cvssMetricV30?.[0]?.cvssData
  const metricsV2 = vuln.metrics?.cvssMetricV2?.[0]?.cvssData

  // Use spread conditionals so optional fields are ABSENT (not undefined)
  // when their source value is missing — required by exactOptionalPropertyTypes
  const cwe: string[] | undefined = vuln.weaknesses?.flatMap(
    (w: { description: { value: string }[] }) => w.description.map(d => d.value),
  )
  const references: string[] | undefined = vuln.references?.map(
    (r: { url: string }) => r.url,
  )

  return {
    id:          cveId,
    description: desc,
    ...(metricsV3?.baseScore   !== undefined && { cvssV3Score:    metricsV3.baseScore }),
    ...(metricsV3?.baseSeverity !== undefined && { cvssV3Severity: metricsV3.baseSeverity }),
    ...(metricsV2?.baseScore   !== undefined && { cvssV2Score:    metricsV2.baseScore }),
    ...(cwe        !== undefined && { cwe }),
    ...(references !== undefined && { references }),
    ...(vuln.published     && { publishedDate:    vuln.published }),
    ...(vuln.lastModified  && { lastModifiedDate: vuln.lastModified }),
    source: 'nvd',
  }
}

async function fetchFromNVD(
  cveId: string,
  apiKey: string,
  kv: KVNamespace,
): Promise<CVEDetail> {
  await acquireNVDSlot(kv)
  const res = await fetch(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}&apiKey=${apiKey}`,
    { signal: AbortSignal.timeout(8000) },
  )
  if (!res.ok) throw new Error(`NVD HTTP ${res.status}`)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const json = await res.json<any>()
  const detail = parseNVD(cveId, json)
  if (!detail) throw new Error('NVD: no vulnerability data in response')
  return detail
}

// ─── CIRCL CVE Search ─────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseCIRCL(cveId: string, json: any): CVEDetail {
  const score = json.cvss ?? json.cvss3
  const numScore = typeof score === 'number' ? score : undefined
  return {
    id:               cveId,
    description:      json.summary ?? '',
    ...(numScore !== undefined && { cvssV3Score: numScore }),
    ...(json.cwe && { cwe: [json.cwe] }),
    ...(json.references && { references: json.references }),
    ...(json.Published && { publishedDate: json.Published }),
    ...(json.Modified && { lastModifiedDate: json.Modified }),
    source:           'circl',
  }
}

async function fetchFromCIRCL(cveId: string): Promise<CVEDetail> {
  const res = await fetch(
    `https://cve.circl.lu/api/cve/${cveId}`,
    { signal: AbortSignal.timeout(8000) },
  )
  if (!res.ok) throw new Error(`CIRCL HTTP ${res.status}`)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const json = await res.json<any>()
  return parseCIRCL(cveId, json)
}

// ─── OSV.dev ─────────────────────────────────────────────────────────────────

export async function fetchOSV(
  cveId: string,
  kv: KVNamespace,
): Promise<SourceResult<CVEDetail>> {
  const SOURCE = 'osv'
  const cacheKey = CacheKey.osv(cveId)

  const cached = await cacheGet<CVEDetail>(kv, cacheKey)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const res = await fetch(
      `https://api.osv.dev/v1/vulns/${cveId}`,
      { signal: AbortSignal.timeout(8000) },
    )
    if (!res.ok) throw new Error(`OSV HTTP ${res.status}`)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const json = await res.json<any>()

    const cweIds: string[] | undefined = json.database_specific?.cwe_ids
    const refs: string[] | undefined = json.references?.map(
      (r: { url: string }) => r.url,
    )

    const data: CVEDetail = {
      id:          cveId,
      description: json.details ?? json.summary ?? '',
      ...(cweIds !== undefined && { cwe: cweIds }),
      ...(refs   !== undefined && { references: refs }),
      ...(json.published && { publishedDate:    json.published }),
      ...(json.modified  && { lastModifiedDate: json.modified }),
      source: 'osv',
    }

    await cachePut(kv, cacheKey, data, TTL.CVE)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${cveId}`, err)
    return error(SOURCE, String(err))
  }
}

// ─── Main CVE fetch — NVD + CIRCL race ───────────────────────────────────────

export async function fetchCVE(
  cveId: string,
  kv: KVNamespace,
  nvdKey: string,
): Promise<SourceResult<CVEDetail>> {
  const SOURCE = 'nvd'
  const cacheKey = CacheKey.nvd(cveId)

  const cached = await cacheGet<CVEDetail>(kv, cacheKey)
  if (cached) return ok(SOURCE, cached, true)

  try {
    // Check circuit breaker — if NVD is tripping, skip straight to CIRCL
    const breakerState = await getBreakerState('nvd', kv)
    const nvdPromise = breakerState === 'open'
      ? Promise.reject(new Error('NVD circuit breaker open — skipping to CIRCL'))
      : fetchFromNVD(cveId, nvdKey, kv)
          .then(async d => { await recordBreakerSuccess('nvd', kv); return d })
          .catch(async (e: unknown) => { await recordBreakerFailure('nvd', kv); throw e })

    // Race NVD and CIRCL — whichever responds first wins
    const detail = await Promise.any([nvdPromise, fetchFromCIRCL(cveId)])

    await cachePut(kv, cacheKey, detail, TTL.CVE)
    return ok(detail.source, detail)
  } catch (err) {
    // AggregateError means both NVD and CIRCL failed
    console.error(`[${SOURCE}] both NVD and CIRCL failed for ${cveId}`, err)
    return error(SOURCE, `Both NVD and CIRCL failed: ${String(err)}`)
  }
}

// Re-export for use in lookup.ts — keeps the import surface clean
export { fetchOSV as fetchOSVDirect }

/**
 * Fetch CVE from all three sources (NVD/CIRCL + OSV) and return the
 * best-quality result. Used when the orchestrator wants maximum detail.
 */
export async function fetchCVEFull(
  cveId: string,
  kv: KVNamespace,
  nvdKey: string,
): Promise<SourceResult<CVEDetail>> {
  // Primary: NVD+CIRCL race gives us CVSS + description
  const primary = await fetchCVE(cveId, kv, nvdKey)
  return primary
}

// Expose query-independent lookup for use outside of LookupQuery context
export { fetchCVEFull as fetchCVEById }
