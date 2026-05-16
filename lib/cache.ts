// ─── TTL constants (seconds) ──────────────────────────────────────────────────

export const TTL = {
  CVE:        60 * 60 * 24 * 30, // 30 days  — CVE data is immutable post-publish
  WAYBACK:    60 * 60 * 24 * 7,  // 7 days
  BGP:        60 * 60 * 24,      // 24 hours
  RDAP:       60 * 60 * 24,
  ROBTEX:     60 * 60 * 24,
  CERTS:      60 * 60 * 12,      // 12 hours
  PASSIVEDNS: 60 * 60 * 12,
  GHW:        60 * 60 * 6,       // 6 hours
  CORE:       60 * 60,           // 1 hour   — internetdb, ipapi
  BLOCKLIST:  60 * 60,           //           Feodo + SSLBL bulk downloads
  ABUSECH:    60 * 30,           // 30 minutes
} as const

// ─── Cache key helpers ────────────────────────────────────────────────────────

/**
 * All cache keys in one place. Keeps the key format consistent across
 * source modules and avoids ad-hoc string construction in each file.
 */
export const CacheKey = {
  internetdb:  (ip: string)      => `internetdb:${ip}`,
  ipapi:       (ip: string)      => `ipapi:${ip}`,
  bgpIP:       (ip: string)      => `bgp:ip:${ip}`,
  bgpASN:      (asn: string)     => `bgp:asn:${asn}`,
  rdapIP:      (ip: string)      => `rdap:ip:${ip}`,
  rdapDomain:  (domain: string)  => `rdap:domain:${domain}`,
  crtsh:       (domain: string)  => `crtsh:${domain}`,
  whois:       (domain: string)  => `whois:${domain}`,
  passivedns:  (query: string)   => `passivedns:${query}`,
  robtex:      (ip: string)      => `robtex:${ip}`,
  malwarebazaar: (hash: string)   => `malwarebazaar:${hash}`,
  urlhaus:     (query: string)   => `urlhaus:${query}`,
  threatfox:   (query: string)   => `threatfox:${query}`,
  feodoList:   ()                => 'feodo:blocklist',
  sslblList:   ()                => 'sslbl:blocklist',
  nvd:         (cveId: string)   => `nvd:${cveId}`,
  osv:         (cveId: string)   => `osv:${cveId}`,
  ghwBuckets:  (domain: string)  => `ghw:buckets:${domain}`,
  ghwFiles:    (keyword: string) => `ghw:files:${keyword}`,
  wayback:     (domain: string)  => `wayback:${domain}`,
  rdapBootDNS: ()                => 'rdap:boot:dns',
  rdapBootIP:  ()                => 'rdap:boot:ip',
} as const

// ─── KV read / write ──────────────────────────────────────────────────────────

/**
 * Read a JSON value from KV. Returns null on miss, parse error, or when
 * `bypass` is true (used by the ?refresh=1 force-refresh path).
 */
export async function cacheGet<T>(
  kv: KVNamespace,
  key: string,
  bypass = false,
): Promise<T | null> {
  if (bypass) return null
  try {
    const raw = await kv.get(key)
    return raw ? (JSON.parse(raw) as T) : null
  } catch (err) {
    console.error(`[cache] get failed key=${key}`, err)
    return null
  }
}

/**
 * Write a JSON value to KV with an expiry TTL in seconds.
 * Swallows errors — a failed cache write should never break a response.
 *
 * KV write budget (Cloudflare free tier): 1,000 writes/day.
 * Target utilisation: ≤ 50 % (≤ 500 writes/day) to maintain a safety
 * margin for burst traffic.  Achieved by:
 *   • Long TTLs (CVE 30 days, BGP/RDAP 24 h) → most requests are cache hits
 *   • Never caching errors → avoids "poison" entries that must be re-fetched
 *   • Per-IP rate limiting → prevents a single user exhausting write quota
 *
 * If write quota pressure increases, consider:
 *   • Coalescing multi-source responses into a single KV key
 *   • Switching high-frequency keys (CORE, ABUSECH) to R2 object storage
 */
export async function cachePut<T>(
  kv: KVNamespace,
  key: string,
  value: T,
  ttl: number,
): Promise<void> {
  try {
    await kv.put(key, JSON.stringify(value), { expirationTtl: ttl })
  } catch (err) {
    console.error(`[cache] put failed key=${key}`, err)
  }
}
