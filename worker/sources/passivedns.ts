/**
 * CIRCL Passive DNS — historical DNS resolution records.
 *
 * Returns newline-delimited JSON (not a JSON array) — parsed line by line.
 * Accepts both IPs and domains.
 *
 * For domain queries we run two fetches in parallel:
 *   1. The domain name itself — "what IPs did this domain resolve to?"
 *   2. The resolved IP (ipQuery) — "what other domains ever resolved to this IP?"
 * This unlocks shared-hosting pivot data that a domain-only query misses.
 *
 * Endpoint: https://www.circl.lu/pdns/query/{ip_or_domain}
 * Auth:     none | Limits: unlimited | TTL: 12 hours
 */
import type { LookupQuery, PassiveDNSRecord, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error } from '../../lib/results'

const SOURCE = 'passivedns'

async function queryPDNS(target: string): Promise<PassiveDNSRecord[]> {
  const res = await fetch(
    `https://www.circl.lu/pdns/query/${target}`,
    { signal: AbortSignal.timeout(8000) },
  )

  // 204 No Content = valid "no results" response — not an error
  if (res.status === 204) return []
  if (!res.ok) throw new Error(`HTTP ${res.status}`)

  const text = await res.text()
  // Empty body is also valid for "no results"
  if (!text.trim()) return []

  return text
    .split('\n')
    .filter(line => line.trim().length > 0)
    .map(line => {
      try { return JSON.parse(line) as PassiveDNSRecord }
      catch (err) {
        console.error('[passivedns] JSON parse failed for line:', line, err)
        return null
      }
    })
    .filter((r): r is PassiveDNSRecord => r !== null)
}

export async function fetchPassiveDNS(
  query: LookupQuery,
  kv: KVNamespace,
  /** Resolved IP query — supplied by lookup.ts for domain queries */
  ipQuery?: LookupQuery | null,
): Promise<SourceResult<PassiveDNSRecord[]>> {
  const cacheKey = CacheKey.passivedns(query.normalised)
  const cached = await cacheGet<PassiveDNSRecord[]>(kv, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    // For domain queries: also query by resolved IP so we surface all domains
    // that ever shared the same IP — a critical shared-hosting pivot point.
    const targets: string[] = [query.normalised]
    if (query.type === 'domain' && ipQuery) {
      targets.push(ipQuery.normalised)
    }

    const settled = await Promise.allSettled(targets.map(t => queryPDNS(t)))

    // Require the primary (domain/IP) query to succeed
    if (settled[0]?.status === 'rejected') throw settled[0].reason

    // Merge both result sets; deduplicate by (rrname, rdata, rrtype) triple
    const seen = new Set<string>()
    const data: PassiveDNSRecord[] = []

    for (const result of settled) {
      if (result.status === 'rejected') continue
      for (const r of result.value) {
        const key = `${r.rrname}|${r.rrtype}|${r.rdata}`
        if (seen.has(key)) continue
        seen.add(key)
        data.push(r)
      }
    }

    await cachePut(kv, cacheKey, data, TTL.PASSIVEDNS)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
