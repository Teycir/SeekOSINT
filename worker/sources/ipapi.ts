/**
 * ip-api.com — geo, ASN, org, proxy/hosting/mobile flags.
 *
 * NOTE: ip-api free tier is HTTP-only on direct browser requests but
 * Cloudflare Workers outbound fetches require HTTPS. We use the pro
 * endpoint pattern with HTTPS which works for server-side fetches.
 * fields bitmask 66846719 enables all fields.
 * Endpoint: https://ip-api.com/json/{ip}?fields=66846719
 * Auth:     none | Limits: 45 req/min | TTL: 1 hour
 */
import type { IPAPIResult, LookupQuery, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped, safeJson } from '../../lib/results'
import { withBackoff } from '../../lib/backoff'
import { safeFetch } from '../../lib/ssrf'

const SOURCE = 'ipapi'

// Raw shape returned by the API before normalisation
interface RawIPAPI {
  status: 'success' | 'fail'
  message?: string
  query: string
  country: string
  countryCode: string
  regionName: string
  city: string
  lat: number
  lon: number
  org: string
  as: string
  isp: string
  timezone: string
  proxy: boolean
  hosting: boolean
  mobile: boolean
}

function isRawIPAPI(v: unknown): v is RawIPAPI {
  if (typeof v !== 'object' || v === null) return false
  const r = v as Record<string, unknown>
  return typeof r.status === 'string' && typeof r.query === 'string'
}

export async function fetchIPAPI(
  query: LookupQuery,
  kv: KVNamespace,
): Promise<SourceResult<IPAPIResult>> {
  if (query.type !== 'ip') return skipped(SOURCE)

  const cacheKey = CacheKey.ipapi(query.normalised)
  const cached = await cacheGet<IPAPIResult>(kv, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const res = await withBackoff(
      () => safeFetch(
        `https://ip-api.com/json/${query.normalised}?fields=66846719`,
        { signal: AbortSignal.timeout(8000) },
      ),
      { source: SOURCE, maxAttempts: 3, baseDelayMs: 1_000 },
    )

    if (!res.ok) {
      console.error(`[${SOURCE}] HTTP ${res.status} for ${query.normalised}`)
      return error(SOURCE, `HTTP ${res.status}`)
    }

    const raw = await safeJson<RawIPAPI>(res, isRawIPAPI, SOURCE)

    if (raw.status === 'fail') {
      // ip-api returns "fail" for private, reserved, or CDN anycast IPs.
      // This is not an upstream error — treat it as a valid empty result so
      // the circuit breaker is not tripped for Cloudflare-proxied domains.
      console.warn(`[${SOURCE}] API fail (reserved/CDN IP): ${raw.message} for ${query.normalised}`)
      return skipped(SOURCE)
    }

    const data: IPAPIResult = {
      ip:          raw.query,
      country:     raw.country,
      countryCode: raw.countryCode,
      region:      raw.regionName,
      city:        raw.city,
      lat:         raw.lat,
      lon:         raw.lon,
      org:         raw.org,
      asn:         raw.as.split(' ')[0] ?? raw.as, // "AS14618 Amazon..." → "AS14618"
      isp:         raw.isp,
      timezone:    raw.timezone,
      proxy:       raw.proxy,
      hosting:     raw.hosting,
      mobile:      raw.mobile,
    }

    await cachePut(kv, cacheKey, data, TTL.CORE)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
