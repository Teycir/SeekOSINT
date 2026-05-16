/**
 * WHOIS — raw registration data via whoisjson.com (free, no auth).
 *
 * Complements RDAP with fields RDAP registries often omit:
 *   • Registrant / admin / tech contact names and emails
 *   • Abuse contact email
 *   • Raw WHOIS text (for copy-paste into other tools)
 *   • DNSSEC status
 *
 * Domain queries only — IPs are already covered by RDAP + BGPView.
 * Falls back gracefully: if the field is absent in the response it is
 * simply omitted from the result rather than erroring.
 *
 * Endpoint: https://whoisjson.com/api/v1/whois?domain={domain}
 * Auth:     none (free tier, rate-limited to ~100 req/hr per IP)
 * TTL:      24 hours (registration data changes rarely)
 */
import type { LookupQuery, SourceResult, WhoisResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'

const SOURCE = 'whois'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function str(v: unknown): string | undefined {
  if (typeof v === 'string' && v.trim()) return v.trim()
  return undefined
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normalise(raw: any, domain: string): WhoisResult {
  return {
    domain:          str(raw.domain)              ?? domain,
    registrar:       str(raw.registrar),
    registrarUrl:    str(raw.registrar_url),
    registrant:      str(raw.registrant_name)     ?? str(raw.registrant?.name),
    registrantOrg:   str(raw.registrant_org)      ?? str(raw.registrant?.organization),
    registrantEmail: str(raw.registrant_email)    ?? str(raw.registrant?.email),
    adminEmail:      str(raw.admin_email)          ?? str(raw.admin?.email),
    techEmail:       str(raw.tech_email)           ?? str(raw.tech?.email),
    abuseEmail:      str(raw.abuse_email),
    created:         str(raw.creation_date)        ?? str(raw.created),
    updated:         str(raw.updated_date)         ?? str(raw.updated),
    expires:         str(raw.expiration_date)      ?? str(raw.expires),
    nameservers:     Array.isArray(raw.name_servers)
                       ? (raw.name_servers as string[]).map(s => s.toLowerCase().trim()).filter(Boolean)
                       : undefined,
    dnssec:          str(raw.dnssec),
    status:          Array.isArray(raw.status)
                       ? (raw.status as string[]).map(s => String(s).trim()).filter(Boolean)
                       : str(raw.status)
                         ? [str(raw.status) as string]
                         : undefined,
    rawText:         str(raw.raw_text),
  }
}

export async function fetchWhois(
  query: LookupQuery,
  kv: KVNamespace,
): Promise<SourceResult<WhoisResult>> {
  if (query.type !== 'domain') return skipped(SOURCE)

  const cacheKey = CacheKey.whois(query.normalised)
  const cached = await cacheGet<WhoisResult>(kv, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const url = `https://whoisjson.com/api/v1/whois?domain=${encodeURIComponent(query.normalised)}`
    const res = await safeFetch(url, { signal: AbortSignal.timeout(15000) })

    if (res.status === 429) {
      console.warn(`[${SOURCE}] rate limited — skipping`)
      return skipped(SOURCE)
    }

    if (!res.ok) throw new Error(`HTTP ${res.status}`)

    const ct = res.headers.get('content-type') ?? ''
    if (!ct.includes('json')) {
      console.warn(`[${SOURCE}] unexpected content-type "${ct}"`)
      return skipped(SOURCE)
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let raw: any
    try {
      raw = await res.json()
    } catch (e) {
      throw new Error(`JSON parse failed: ${e}`)
    }

    if (!raw || typeof raw !== 'object') return skipped(SOURCE)

    // whoisjson wraps results in a "whois" key on some endpoints
    const data = raw.whois ?? raw
    const result = normalise(data, query.normalised)

    await cachePut(kv, cacheKey, result, TTL.RDAP) // 24-hour TTL — same as RDAP
    return ok(SOURCE, result)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
