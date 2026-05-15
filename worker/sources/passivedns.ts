/**
 * CIRCL Passive DNS — historical DNS resolution records.
 *
 * Returns newline-delimited JSON (not a JSON array) — parsed line by line.
 * Accepts both IPs and domains.
 *
 * Endpoint: https://www.circl.lu/pdns/query/{ip_or_domain}
 * Auth:     none | Limits: unlimited | TTL: 12 hours
 */
import type { LookupQuery, PassiveDNSRecord, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error } from '../../lib/results'

const SOURCE = 'passivedns'

export async function fetchPassiveDNS(
  query: LookupQuery,
  kv: KVNamespace,
): Promise<SourceResult<PassiveDNSRecord[]>> {
  const cacheKey = CacheKey.passivedns(query.normalised)
  const cached = await cacheGet<PassiveDNSRecord[]>(kv, cacheKey)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const res = await fetch(
      `https://www.circl.lu/pdns/query/${query.normalised}`,
      { signal: AbortSignal.timeout(8000) },
    )

    if (!res.ok) {
      console.error(`[${SOURCE}] HTTP ${res.status} for ${query.normalised}`)
      return error(SOURCE, `HTTP ${res.status}`)
    }

    const text = await res.text()

    // CIRCL returns newline-delimited JSON objects, not a JSON array
    const data: PassiveDNSRecord[] = text
      .split('\n')
      .filter(line => line.trim().length > 0)
      .map(line => {
        try {
          return JSON.parse(line) as PassiveDNSRecord
        } catch {
          return null
        }
      })
      .filter((r): r is PassiveDNSRecord => r !== null)

    await cachePut(kv, cacheKey, data, TTL.PASSIVEDNS)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
