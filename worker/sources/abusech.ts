/**
 * abuse.ch — five threat intel sources under one API key.
 *
 * All five use POST with application/x-www-form-urlencoded.
 * Feodo and SSLBL use a bulk-download strategy: the full blocklist is
 * fetched once per hour into KV, then lookups are local in-memory finds.
 *
 * Sources: URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker, SSLBL
 * Auth:    single ABUSECH_KEY for URLhaus, ThreatFox, MalwareBazaar
 * TTL:     30 minutes (threat intel), 1 hour (blocklists)
 */
import type {
  FeodoEntry,
  LookupQuery,
  MalwareBazaarResult,
  SSLBLEntry,
  SourceResult,
  ThreatFoxResult,
  URLhausResult,
} from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped } from '../../lib/results'

// ─── Shared POST helper ───────────────────────────────────────────────────────

async function abusePost<T>(
  url: string,
  body: Record<string, string>,
  apiKey: string,
): Promise<T> {
  const params = new URLSearchParams({ ...body, 'Auth-Key': apiKey })
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
    signal: AbortSignal.timeout(8000),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json<T>()
}

// ─── URLhaus ──────────────────────────────────────────────────────────────────

export async function fetchURLhaus(
  query: LookupQuery,
  kv: KVNamespace,
  apiKey: string,
): Promise<SourceResult<URLhausResult>> {
  const SOURCE = 'urlhaus'
  const cacheKey = CacheKey.urlhaus(query.normalised)

  const cached = await cacheGet<URLhausResult>(kv, cacheKey)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const data = await abusePost<URLhausResult>(
      'https://urlhaus-api.abuse.ch/v1/host/',
      { host: query.normalised },
      apiKey,
    )
    await cachePut(kv, cacheKey, data, TTL.ABUSECH)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}

// ─── ThreatFox ────────────────────────────────────────────────────────────────

export async function fetchThreatFox(
  query: LookupQuery,
  kv: KVNamespace,
  apiKey: string,
): Promise<SourceResult<ThreatFoxResult>> {
  const SOURCE = 'threatfox'
  const cacheKey = CacheKey.threatfox(query.normalised)

  const cached = await cacheGet<ThreatFoxResult>(kv, cacheKey)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Auth-Key': apiKey,          // key goes in HTTP header, not body
      },
      body: JSON.stringify({
        query: 'search_ioc',
        search_term: query.normalised,
      }),
      signal: AbortSignal.timeout(8000),
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = await res.json<ThreatFoxResult>()
    await cachePut(kv, cacheKey, data, TTL.ABUSECH)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}

// ─── MalwareBazaar ────────────────────────────────────────────────────────────
// Supports hash lookups (SHA256) and tag/signature queries.
// For IP/domain queries we search by the query value as a tag/signature term.
// Results are cached by query value.

export async function fetchMalwareBazaar(
  query: LookupQuery,
  kv: KVNamespace,
  apiKey: string,
  hash?: string,
): Promise<SourceResult<MalwareBazaarResult>> {
  const SOURCE = 'malwarebazaar'
  const lookupValue = hash ?? query.normalised
  const cacheKey = CacheKey.malwarebazaar(lookupValue)

  const cached = await cacheGet<MalwareBazaarResult>(kv, cacheKey)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const body = hash
      ? { query: 'search_hash', hash }
      : { query: 'search_tag', tag: query.normalised }

    const data = await abusePost<MalwareBazaarResult>(
      'https://mb-api.abuse.ch/api/v1/',
      body,
      apiKey,
    )
    await cachePut(kv, cacheKey, data, TTL.ABUSECH)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${lookupValue}`, err)
    return error(SOURCE, String(err))
  }
}

// ─── Feodo Tracker ────────────────────────────────────────────────────────────
// Downloads full blocklist into KV once per hour. Lookups are local in-memory.

export async function fetchFeodo(
  query: LookupQuery,
  kv: KVNamespace,
): Promise<SourceResult<FeodoEntry | null>> {
  const SOURCE = 'feodo'

  // Feodo only has meaning for IPs
  if (query.type !== 'ip') return skipped(SOURCE)

  let list = await cacheGet<FeodoEntry[]>(kv, CacheKey.feodoList())

  if (!list) {
    try {
      const res = await fetch(
        'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
        { signal: AbortSignal.timeout(15000) },
      )
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      list = await res.json<FeodoEntry[]>()
      await cachePut(kv, CacheKey.feodoList(), list, TTL.BLOCKLIST)
    } catch (err) {
      console.error(`[${SOURCE}] blocklist download failed`, err)
      return error(SOURCE, String(err))
    }
  }

  const match = list.find(e => e.ip_address === query.normalised) ?? null
  return ok(SOURCE, match)
}

// ─── SSLBL ────────────────────────────────────────────────────────────────────
// Same bulk-download strategy as Feodo.

export async function fetchSSLBL(
  query: LookupQuery,
  kv: KVNamespace,
): Promise<SourceResult<SSLBLEntry[]>> {
  const SOURCE = 'sslbl'

  // SSLBL tracks SSL certificates — only meaningful for IP queries
  if (query.type !== 'ip') return skipped(SOURCE)

  let list = await cacheGet<SSLBLEntry[]>(kv, CacheKey.sslblList())

  if (!list) {
    try {
      const res = await fetch(
        'https://sslbl.abuse.ch/blacklist/sslblacklist.json',
        { signal: AbortSignal.timeout(15000) },
      )
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      // The API wraps results under a "results" key
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const json = await res.json<any>()
      list = (json.results ?? json) as SSLBLEntry[]
      await cachePut(kv, CacheKey.sslblList(), list, TTL.BLOCKLIST)
    } catch (err) {
      console.error(`[${SOURCE}] blocklist download failed`, err)
      return error(SOURCE, String(err))
    }
  }

  // SSLBL indexes by SHA1 fingerprint, not IP. The JSON feed does include
  // a "DstIP" field on each entry — filter by that to surface matches.
  const matches = list.filter(e => (e as unknown as { DstIP?: string }).DstIP === query.normalised)
  return ok(SOURCE, matches)
}
