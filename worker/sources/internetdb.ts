/**
 * Shodan InternetDB — open ports, hostnames, CVEs, CPEs, tags.
 *
 * IPv4 only. A 404 is not an error — unknown IPs return an empty result.
 * Endpoint: https://internetdb.shodan.io/{ip}
 * Auth:     none | Limits: unlimited | TTL: 1 hour
 */
import type { InternetDBResult, LookupQuery, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped } from '../../lib/results'

const SOURCE = 'internetdb'

export async function fetchInternetDB(
  query: LookupQuery,
  kv: KVNamespace,
): Promise<SourceResult<InternetDBResult>> {
  if (query.type !== 'ip') return skipped(SOURCE)

  const cacheKey = CacheKey.internetdb(query.normalised)
  const cached = await cacheGet<InternetDBResult>(kv, cacheKey)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const res = await fetch(
      `https://internetdb.shodan.io/${query.normalised}`,
      { signal: AbortSignal.timeout(8000) },
    )

    // 404 = IP not in Shodan — return an empty but valid result, not an error
    if (res.status === 404) {
      const empty: InternetDBResult = {
        ip: query.normalised,
        ports: [],
        hostnames: [],
        tags: [],
        vulns: [],
        cpes: [],
      }
      await cachePut(kv, cacheKey, empty, TTL.CORE)
      return ok(SOURCE, empty)
    }

    if (!res.ok) {
      console.error(`[${SOURCE}] HTTP ${res.status} for ${query.normalised}`)
      return error(SOURCE, `HTTP ${res.status}`)
    }

    const data = await res.json<InternetDBResult>()
    await cachePut(kv, cacheKey, data, TTL.CORE)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
