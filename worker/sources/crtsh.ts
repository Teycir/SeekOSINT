/**
 * crt.sh — certificate transparency log search.
 *
 * Queries with wildcard prefix %.domain to capture all subdomains.
 * Deduplicates by name_value and caps at 500 records.
 * Domain queries only — IPs and ASNs are skipped.
 *
 * Endpoint: https://crt.sh/?q={domain}&output=json
 * Auth:     none | Limits: unlimited | TTL: 12 hours
 */
import type { CertRecord, LookupQuery, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped, safeJson } from '../../lib/results'

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

export async function fetchCRTSH(
  query: LookupQuery,
  kv: KVNamespace,
): Promise<SourceResult<CertRecord[]>> {
  if (query.type !== 'domain') return skipped(SOURCE)

  const cacheKey = CacheKey.crtsh(query.normalised)
  const cached = await cacheGet<CertRecord[]>(kv, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const encoded = encodeURIComponent(`%.${query.normalised}`)
    const res = await fetch(
      `https://crt.sh/?q=${encoded}&output=json`,
      { signal: AbortSignal.timeout(20000) },
    )

    if (!res.ok) {
      console.error(`[${SOURCE}] HTTP ${res.status} for ${query.normalised}`)
      return error(SOURCE, `HTTP ${res.status}`)
    }

    const raw = await safeJson<RawCert[]>(
      res,
      (v): v is RawCert[] => Array.isArray(v),
      SOURCE,
    )

    // Deduplicate by name_value, normalise shape, cap at MAX_RESULTS
    const seen = new Set<string>()
    const data: CertRecord[] = []

    for (const cert of raw) {
      if (seen.has(cert.name_value)) continue
      seen.add(cert.name_value)
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
