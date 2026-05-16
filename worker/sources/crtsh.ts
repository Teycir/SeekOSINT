/**
 * crt.sh — certificate transparency log search.
 *
 * Queries with wildcard prefix %.domain to capture all subdomains,
 * plus a second fetch for the apex domain itself (certs issued to
 * "example.com" rather than "*.example.com" are otherwise invisible).
 *
 * The two fetches run sequentially with a 500ms gap to avoid triggering
 * crt.sh's per-IP rate limiter, which responds with HTML (not JSON) on
 * 429s and would otherwise corrupt the parse step.
 *
 * Deduplicates by cert id and caps at 500 records total.
 * Domain queries only — IPs and ASNs are skipped.
 *
 * Endpoint: https://crt.sh/?q={domain}&output=json
 * Auth:     none | Limits: rate-sensitive | TTL: 12 hours
 */
import type { CertRecord, LookupQuery, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'

const SOURCE = 'crtsh'
const MAX_RESULTS = 500

interface RawCert {
  id: number
  issuer_name: string
  common_name: string
  name_value: string
  not_before: string
  not_after: string
  serial_number: string
}

/**
 * Fetch one crt.sh query and return parsed certs.
 * Returns [] on rate-limit (429), empty result (no certs), or non-JSON body.
 * Throws only on genuine network errors or non-recoverable HTTP failures.
 */
async function fetchCerts(url: string): Promise<RawCert[]> {
  const res = await safeFetch(url, { signal: AbortSignal.timeout(20000) })

  // 429 = rate limited — treat as empty, not an error (avoids tripping breaker)
  if (res.status === 429) {
    console.warn(`[${SOURCE}] rate limited by crt.sh — returning empty`)
    return []
  }

  if (!res.ok) throw new Error(`HTTP ${res.status}`)

  // crt.sh returns HTML on error pages even with output=json.
  // Guard against that before trying JSON.parse.
  const ct = res.headers.get('content-type') ?? ''
  if (!ct.includes('json')) {
    console.warn(`[${SOURCE}] unexpected content-type "${ct}" — skipping`)
    return []
  }

  let parsed: unknown
  try {
    parsed = await res.json()
  } catch (err) {
    console.error(`[${SOURCE}] JSON parse failed:`, err)
    throw new Error('response body is not valid JSON')
  }

  if (!Array.isArray(parsed)) return []
  return parsed as RawCert[]
}

export async function fetchCRTSH(
  query: LookupQuery,
  kv: KVNamespace,
): Promise<SourceResult<CertRecord[]>> {
  if (query.type !== 'domain') return skipped(SOURCE)

  const cacheKey = CacheKey.crtsh(query.normalised)
  const cached = await cacheGet<CertRecord[]>(kv, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const wildcardUrl = `https://crt.sh/?q=${encodeURIComponent(`%.${query.normalised}`)}&output=json`
    const apexUrl     = `https://crt.sh/?q=${encodeURIComponent(query.normalised)}&output=json`

    // Fetch wildcard first. If it fails we surface the error immediately.
    const wildcardRaw = await fetchCerts(wildcardUrl)

    // Apex fetch is best-effort with a 500ms gap to avoid rate limiting.
    // Any failure here is silently swallowed — wildcard results still return.
    let apexRaw: RawCert[] = []
    try {
      await new Promise(r => setTimeout(r, 500))
      apexRaw = await fetchCerts(apexUrl)
    } catch (apexErr) {
      console.warn(`[${SOURCE}] apex fetch failed for ${query.normalised} (non-critical):`, apexErr)
    }

    // Deduplicate by id (wildcard first), then by name_value, cap at MAX_RESULTS
    const seenIds  = new Set<number>()
    const seenName = new Set<string>()
    const data: CertRecord[] = []

    for (const cert of [...wildcardRaw, ...apexRaw]) {
      if (seenIds.has(cert.id) || seenName.has(cert.name_value)) continue
      seenIds.add(cert.id)
      seenName.add(cert.name_value)
      data.push({
        id:           cert.id,
        issuer:       cert.issuer_name,
        commonName:   cert.common_name,
        nameValue:    cert.name_value,
        notBefore:    cert.not_before,
        notAfter:     cert.not_after,
        serialNumber: cert.serial_number,
      })
      if (data.length >= MAX_RESULTS) break
    }

    await cachePut(kv, cacheKey, data, TTL.CERTS)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
