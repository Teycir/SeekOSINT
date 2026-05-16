/**
 * BGPView — ASN info, prefixes, upstreams, peers, RIR.
 *
 * Supports both IP and ASN queries. Domain queries are skipped.
 * Endpoint: https://api.bgpview.io/ip/{ip} | /asn/{asn}
 * Auth:     none | Limits: unlimited | TTL: 24 hours
 */
import type { BGPViewResult, LookupQuery, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped, safeJson } from '../../lib/results'

const SOURCE = 'bgpview'

function hasBGPViewData(v: unknown): v is { data: Record<string, unknown> } {
  if (typeof v !== 'object' || v === null) return false
  return 'data' in (v as object)
}

export async function fetchBGPView(
  query: LookupQuery,
  kv: KVNamespace,
): Promise<SourceResult<BGPViewResult>> {
  // Domain queries are skipped — caller must pass effectiveIPQuery (resolved IP)
  // so that domain lookups still get ASN/prefix/RIR context.
  if (query.type === 'domain') return skipped(SOURCE)

  let url: string
  let cacheKey: string

  if (query.type === 'asn') {
    const asnNum = query.normalised.replace(/^as/i, '')
    url = `https://api.bgpview.io/asn/${asnNum}`
    cacheKey = CacheKey.bgpASN(query.normalised)
  } else {
    url = `https://api.bgpview.io/ip/${query.normalised}`
    cacheKey = CacheKey.bgpIP(query.normalised)
  }

  const cached = await cacheGet<BGPViewResult>(kv, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(8000) })

    if (!res.ok) {
      console.error(`[${SOURCE}] HTTP ${res.status} for ${query.normalised}`)
      return error(SOURCE, `HTTP ${res.status}`)
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const json = await safeJson<any>(res, hasBGPViewData, SOURCE)
    const d = json.data

    // /ip and /asn responses have very different shapes.
    // /ip: { rir_allocation: { asn, name, ... }, prefixes: { ipv4: [...] }, ... }
    // /asn: { asn, name, description, prefixes: [...], upstreams: [...], peers: [...] }
    const asnObj = query.type === 'asn' ? d : d?.rir_allocation
    const prefixes: string[] =
      query.type === 'asn'
        ? (d?.prefixes ?? []).map((p: { prefix: string }) => p.prefix)
        : (d?.prefixes?.ipv4 ?? []).map((p: { prefix: string }) => p.prefix)

    // peers/upstreams only exist on the /asn endpoint
    const upstreams: number[] = query.type === 'asn'
      ? (d?.upstreams ?? []).map((u: { asn: number }) => u.asn)
      : []
    const peers: number[] = query.type === 'asn'
      ? (d?.peers ?? []).map((p: { asn: number }) => p.asn)
      : []

    const data: BGPViewResult = {
      asn:         asnObj?.asn ?? 0,
      name:        asnObj?.name ?? '',
      description: asnObj?.description ?? '',
      country:     asnObj?.country_code ?? '',
      prefixes,
      upstreams,
      peers,
      rir:         asnObj?.rir_name ?? asnObj?.rir_allocation?.rir_name ?? '',
    }

    await cachePut(kv, cacheKey, data, TTL.BGP)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
