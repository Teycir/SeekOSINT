# OSINT Tool — Full Technical Specification

## 1. Project Overview

A Shodan-class OSINT tool built entirely on free infrastructure. Given an IP address
or domain, it aggregates data from 17 free/unlimited sources across 4 execution layers
and returns a unified host intelligence report. Built with Next.js, deployed on
Cloudflare Pages + Workers, with KV caching and D1 persistence.

**Design principles**
- Never block the response on a slow or failing source
- Cache aggressively — most data is stable for hours or days
- Degrade gracefully — a source failure returns partial data, never an error page
- All secrets stored in Cloudflare Worker secrets, never in code or env files
- Every source module is independently testable and replaceable

---

## 2. Tech Stack

| Layer | Technology | Plan |
|---|---|---|
| Frontend | Next.js 14 App Router | — |
| Hosting | Cloudflare Pages | Free — unlimited requests |
| API layer | Cloudflare Workers | Free — 100k req/day, 10ms CPU/req |
| Cache | Cloudflare KV | Free — 100k reads/day, 1k writes/day |
| Database | Cloudflare D1 (SQLite) | Free — 5GB, 5M reads/day |
| Adapter | @cloudflare/next-on-pages | Bridges Next.js to CF runtime |
| Language | TypeScript strict mode | — |
| Styling | Tailwind CSS | — |
| Testing | Vitest | Unit + integration |

---

## 3. Repository Structure

```
/
├── app/                              Next.js App Router
│   ├── layout.tsx
│   ├── page.tsx                      Search landing page
│   ├── host/
│   │   └── [query]/
│   │       └── page.tsx              Results page — SSR
│   └── api/
│       └── lookup/
│           └── route.ts              Thin proxy to Worker
│
├── worker/
│   ├── index.ts                      Worker entry point + routing
│   ├── lookup.ts                     Layer orchestrator
│   └── sources/
│       ├── internetdb.ts
│       ├── ipapi.ts
│       ├── bgpview.ts
│       ├── rdap.ts
│       ├── crtsh.ts
│       ├── passivedns.ts
│       ├── robtex.ts
│       ├── abusech.ts                All 5 abuse.ch sources
│       ├── nvd.ts                    NVD + CIRCL fallback
│       ├── osv.ts
│       ├── grayhatwarfare.ts
│       └── wayback.ts
│
├── lib/
│   ├── types.ts                      All shared interfaces
│   ├── keyring.ts                    Multi-key rotation
│   ├── cache.ts                      KV wrapper with TTL constants
│   ├── merge.ts                      Normalise sources → HostResult
│   ├── validate.ts                   IP / domain input validation
│   └── logger.ts                     Structured error logging
│
├── test/
│   ├── sources/                      Per-source unit tests
│   ├── merge.test.ts
│   └── keyring.test.ts
│
├── wrangler.toml
├── next.config.ts
└── tsconfig.json
```

---

## 4. Shared Types — `lib/types.ts`

```typescript
// ─── Input ────────────────────────────────────────────────────────────────────

export type QueryType = 'ip' | 'domain' | 'asn'

export interface LookupQuery {
  raw: string          // original user input
  type: QueryType
  normalised: string   // trimmed, lowercased, stripped of protocol
}

// ─── Per-source result wrappers ───────────────────────────────────────────────

export type SourceStatus = 'ok' | 'cached' | 'error' | 'skipped'

export interface SourceResult<T> {
  source: string
  status: SourceStatus
  data: T | null
  error?: string
  cachedAt?: number    // unix ms
  fetchedAt?: number
}

// ─── Layer 1: Core ────────────────────────────────────────────────────────────

export interface InternetDBResult {
  ip: string
  ports: number[]
  hostnames: string[]
  tags: string[]
  vulns: string[]      // CVE IDs e.g. ["CVE-2021-44228"]
  cpes: string[]       // e.g. ["cpe:/a:apache:log4j:2.14.1"]
}

export interface IPAPIResult {
  ip: string
  country: string
  countryCode: string
  region: string
  city: string
  lat: number
  lon: number
  org: string          // "AS14618 Amazon.com, Inc."
  asn: string          // "AS14618"
  isp: string
  timezone: string
  proxy: boolean
  hosting: boolean
  mobile: boolean
}

export interface BGPViewResult {
  asn: number
  name: string
  description: string
  country: string
  prefixes: string[]   // ["1.2.3.0/24"]
  upstreams: number[]  // upstream ASN numbers
  peers: number[]
  rir: string          // ARIN, RIPE, etc.
}

export interface RDAPResult {
  domain?: string
  ip?: string
  registrar?: string
  registrant?: string
  created?: string
  expires?: string
  updated?: string
  nameservers?: string[]
  status?: string[]
  contacts?: RDAPContact[]
  cidr?: string
  networkName?: string
}

export interface RDAPContact {
  role: string
  email?: string
  org?: string
}

export interface CertRecord {
  id: number
  issuer: string
  commonName: string
  nameValue: string    // may contain \n-separated SANs
  notBefore: string
  notAfter: string
  serialNumber: string
}

export interface PassiveDNSRecord {
  rrname: string
  rrtype: string
  rdata: string
  time_first: number
  time_last: number
  count: number
}

export interface RobtexResult {
  as: number
  asname: string
  whoisdesc: string
  routedesc: string
  bgproute: string
  city: string
  country: string
  passiveDNS: { o: string; t: number }[]     // outgoing
  reverseDNS: { o: string; t: number }[]     // incoming
}

// ─── Layer 2: Threat intelligence ─────────────────────────────────────────────

export interface URLhausResult {
  query_status: 'is_host' | 'no_results'
  urlhaus_reference?: string
  urls?: URLhausURL[]
  blacklists?: { surbl: string; gsb: string }
  urls_count?: number
  tags?: string[]
}

export interface URLhausURL {
  id: string
  url_status: 'online' | 'offline' | 'unknown'
  url: string
  threat: string
  tags: string[]
  date_added: string
}

export interface ThreatFoxResult {
  query_status: 'ok' | 'no_results'
  data?: ThreatFoxIOC[]
}

export interface ThreatFoxIOC {
  id: string
  ioc: string
  ioc_type: string
  threat_type: string
  malware: string
  malware_alias: string
  confidence_level: number
  first_seen: string
  last_seen: string
  tags: string[]
}

export interface MalwareBazaarResult {
  query_status: 'ok' | 'no_results'
  data?: MalwareBazaarEntry[]
}

export interface MalwareBazaarEntry {
  sha256_hash: string
  file_name: string
  file_type: string
  signature: string | null
  tags: string[]
  first_seen: string
  last_seen: string
}

export interface FeodoEntry {
  ip_address: string
  port: number
  status: 'Online' | 'Offline'
  hostname: string | null
  as_number: number
  as_name: string
  country: string
  first_seen: string
  last_seen: string
  malware: string
}

export interface SSLBLEntry {
  SHA1: string
  Listingdate: string
  SuspiciousReason: string
  Listingtime: string
}

// ─── Layer 3: CVE enrichment ───────────────────────────────────────────────────

export interface CVEDetail {
  id: string
  description: string
  cvssV3Score?: number
  cvssV3Severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'
  cvssV2Score?: number
  cwe?: string[]
  references?: string[]
  publishedDate?: string
  lastModifiedDate?: string
  source: 'nvd' | 'circl' | 'osv'
}

// ─── Layer 4: Bucket recon ────────────────────────────────────────────────────

export interface BucketResult {
  bucket: string
  fileCount: number
  provider: 'aws' | 'azure' | 'gcp'
  url: string
  lastSeen: string
}

export interface WaybackResult {
  url: string
  timestamp: string   // YYYYMMDDHHmmss
  statusCode: string
  mimeType: string
}

// ─── Merged output ─────────────────────────────────────────────────────────────

export interface HostResult {
  query: LookupQuery
  resolvedIP?: string
  resolvedDomain?: string

  // Layer 1
  core: {
    internetdb:  SourceResult<InternetDBResult>
    geo:         SourceResult<IPAPIResult>
    bgp:         SourceResult<BGPViewResult>
    rdap:        SourceResult<RDAPResult>
    certs:       SourceResult<CertRecord[]>
    passivedns:  SourceResult<PassiveDNSRecord[]>
    robtex:      SourceResult<RobtexResult>
  }

  // Layer 2
  threat: {
    urlhaus:     SourceResult<URLhausResult>
    threatfox:   SourceResult<ThreatFoxResult>
    malwarebazaar: SourceResult<MalwareBazaarResult>
    feodo:       SourceResult<FeodoEntry | null>
    sslbl:       SourceResult<SSLBLEntry[]>
  }

  // Layer 3 — only populated if internetdb.vulns is non-empty
  vulns: SourceResult<CVEDetail>[]

  // Layer 4
  recon: {
    buckets:     SourceResult<BucketResult[]>
    wayback:     SourceResult<WaybackResult[]>
  }

  meta: {
    durationMs: number
    timestamp: number
    cacheHits: number
    sourcesQueried: number
    sourcesFailed: number
  }
}
```

---

## 5. Data Sources

### 5.1 Layer 1 — Core (always runs, `Promise.allSettled`)

#### Shodan InternetDB
- **Endpoint:** `https://internetdb.shodan.io/{ip}`
- **Auth:** None
- **Limits:** Unlimited
- **Cache TTL:** 1 hour
- **Notes:** IPv4 only. Returns 404 for unknown IPs (not an error — return empty result).

#### ip-api.com
- **Endpoint:** `http://ip-api.com/json/{ip}?fields=66846719`
- **Auth:** None
- **Limits:** 45 req/min (no monthly cap)
- **Cache TTL:** 1 hour
- **Notes:** HTTP only on free tier. `fields` bitmask enables all fields including proxy/hosting/mobile flags.

#### BGPView
- **Endpoint:** `https://api.bgpview.io/ip/{ip}` for IP; `https://api.bgpview.io/asn/{asn}` for ASN
- **Auth:** None
- **Limits:** Unlimited
- **Cache TTL:** 24 hours

#### RDAP
- **IP endpoint:** `https://rdap.arin.net/registry/ip/{ip}` (ARIN); fallback chain to RIPE, APNIC, LACNIC, AFRINIC
- **Domain endpoint:** `https://rdap.verisign.com/com/v1/domain/{domain}` (varies by TLD)
- **Auth:** None
- **Limits:** Unlimited
- **Cache TTL:** 24 hours
- **Notes:** Implement RDAP bootstrap — query `https://data.iana.org/rdap/dns.json` for domain TLD routing and `https://data.iana.org/rdap/ipv4.json` for IP block routing. Cache bootstrap responses for 24 hours.

#### crt.sh
- **Endpoint:** `https://crt.sh/?q={domain}&output=json`
- **Auth:** None
- **Limits:** Unlimited
- **Cache TTL:** 12 hours
- **Notes:** Query with `%.domain.com` for subdomain wildcard. Deduplicate by `name_value`. Cap results at 500.

#### CIRCL Passive DNS
- **Endpoint:** `https://www.circl.lu/pdns/query/{ip_or_domain}`
- **Auth:** None
- **Limits:** Unlimited
- **Cache TTL:** 12 hours
- **Notes:** Returns newline-delimited JSON, not a JSON array. Parse accordingly.

#### Robtex
- **IP endpoint:** `https://freeapi.robtex.com/ipquery/{ip}`
- **Auth:** None
- **Limits:** Unlimited
- **Cache TTL:** 24 hours

---

### 5.2 Layer 2 — Threat Intelligence (parallel, no dependency on Layer 1)

All five abuse.ch sources share the same request pattern: POST with
`Content-Type: application/x-www-form-urlencoded` and a free API key registered at
`https://abuse.ch`.

#### URLhaus
- **Endpoint:** `https://urlhaus-api.abuse.ch/v1/host/`
- **Body:** `host={ip_or_domain}`
- **Cache TTL:** 30 minutes

#### ThreatFox
- **Endpoint:** `https://threatfox-api.abuse.ch/api/v1/`
- **Body:** `{"query":"search_ioc","search_term":"{ip_or_domain}"}`
- **Cache TTL:** 30 minutes

#### MalwareBazaar
- **Endpoint:** `https://mb-api.abuse.ch/api/v1/`
- **Body:** `query=search_hash&hash={hash}` — only useful when a hash is known (e.g. from a file download URL found in another source)
- **Cache TTL:** 30 minutes
- **Notes:** Skip this source on plain IP/domain lookups unless a hash is derivable.

#### Feodo Tracker
- **Endpoint:** `https://feodotracker.abuse.ch/downloads/ipblocklist.json`
- **Auth:** None (public download, no key needed)
- **Strategy:** Download the full JSON blocklist once per hour into KV as a single key `feodo:blocklist`. Lookup is then a local in-memory find — no per-IP request needed.
- **Cache TTL:** 1 hour (the blocklist itself)

#### SSLBL
- **Endpoint:** `https://sslbl.abuse.ch/blacklist/sslblacklist.json`
- **Strategy:** Same as Feodo — bulk download into KV key `sslbl:blocklist`, local lookup.
- **Cache TTL:** 1 hour

---

### 5.3 Layer 3 — CVE Enrichment (fires only when InternetDB returns CVE IDs)

For each CVE ID returned by InternetDB, check KV first. On miss, run NVD and CIRCL
in parallel via `Promise.any()` and take whichever responds first.

#### NVD (NIST)
- **Endpoint:** `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cveId}`
- **Auth:** `apiKey` query param — 1 key, no monthly cap
- **Rate limit:** 50 req/30s with key
- **Cache TTL:** 30 days
- **Notes:** CVE data is immutable after publication. 30-day TTL is safe.

#### CIRCL CVE Search (fallback)
- **Endpoint:** `https://cve.circl.lu/api/cve/{cveId}`
- **Auth:** None
- **Limits:** Unlimited
- **Cache TTL:** 30 days
- **Notes:** Used as fallback if NVD returns non-200 or times out after 3 seconds.

#### OSV.dev
- **Endpoint:** `https://api.osv.dev/v1/vulns/{id}` — for cross-referencing CVE IDs against open source packages
- **Auth:** None
- **Limits:** Unlimited
- **Cache TTL:** 30 days

---

### 5.4 Layer 4 — Bucket Recon + Historical Web

#### GrayHatWarfare
- **Endpoint:** `https://buckets.grayhatwarfare.com/api/v2/buckets?keywords={domain}&access_token={key}`
- **Auth:** 18 rotating keys (see Key Rotation section)
- **Strategy:** Domain searches only. Never called for raw IP lookups.
- **Cache TTL:** 6 hours
- **Notes:** Also supports file search endpoint: `https://buckets.grayhatwarfare.com/api/v2/files?keywords={term}&access_token={key}`

#### Wayback CDX API
- **Endpoint:** `https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp,statuscode,mimetype&limit=100&collapse=urlkey`
- **Auth:** None
- **Limits:** Unlimited
- **Cache TTL:** 7 days

---

## 6. Key Rotation — `lib/keyring.ts`

```typescript
export class KeyRing {
  private keys: string[]
  private kv: KVNamespace
  private source: string

  constructor(keys: string[], kv: KVNamespace, source: string) {
    this.keys = keys.filter(Boolean)
    this.kv = kv
    this.source = source
  }

  async nextHealthy(): Promise<string | null> {
    for (const key of this.keys) {
      const burnt = await this.kv.get(`keyring:${this.source}:exhausted:${key}`)
      if (!burnt) return key
    }
    return null
  }

  async markExhausted(key: string, ttlSeconds = 3600): Promise<void> {
    await this.kv.put(
      `keyring:${this.source}:exhausted:${key}`,
      '1',
      { expirationTtl: ttlSeconds }
    )
  }

  get count(): number {
    return this.keys.length
  }
}
```

**Wrangler secrets** — add once per key:
```bash
wrangler secret put GHW_KEY_1   # ... through GHW_KEY_18
wrangler secret put NVD_KEY
wrangler secret put ABUSECH_KEY  # Single key covers all 5 abuse.ch APIs
```

**Worker env bindings** (`wrangler.toml`):
```toml
[[kv_namespaces]]
binding = "KV"
id = "<your-kv-id>"

[[d1_databases]]
binding = "DB"
database_name = "osint"
database_id = "<your-d1-id>"
```

---

## 7. Cache Layer — `lib/cache.ts`

```typescript
export const TTL = {
  CVE:       60 * 60 * 24 * 30,  // 30 days
  WAYBACK:   60 * 60 * 24 * 7,   // 7 days
  BGP:       60 * 60 * 24,        // 24 hours
  RDAP:      60 * 60 * 24,
  ROBTEX:    60 * 60 * 24,
  CERTS:     60 * 60 * 12,        // 12 hours
  PASSIVEDNS:60 * 60 * 12,
  GHW:       60 * 60 * 6,         // 6 hours
  CORE:      60 * 60,             // 1 hour
  ABUSECH:   60 * 30,             // 30 minutes
  BLOCKLIST: 60 * 60,             // Feodo + SSLBL bulk downloads
} as const

export async function cacheGet<T>(
  kv: KVNamespace,
  key: string
): Promise<T | null> {
  try {
    const raw = await kv.get(key)
    return raw ? (JSON.parse(raw) as T) : null
  } catch (err) {
    console.error(`[cache] get failed key=${key}`, err)
    return null
  }
}

export async function cachePut<T>(
  kv: KVNamespace,
  key: string,
  value: T,
  ttl: number
): Promise<void> {
  try {
    await kv.put(key, JSON.stringify(value), { expirationTtl: ttl })
  } catch (err) {
    console.error(`[cache] put failed key=${key}`, err)
  }
}
```

**Cache key conventions:**
```
internetdb:{ip}
ipapi:{ip}
bgp:ip:{ip}
bgp:asn:{asn}
rdap:ip:{ip}
rdap:domain:{domain}
crtsh:{domain}
passivedns:{query}
robtex:{ip}
urlhaus:{query}
threatfox:{query}
feodo:blocklist
sslbl:blocklist
nvd:{cveId}
osv:{cveId}
ghw:buckets:{domain}
ghw:files:{keyword}
wayback:{domain}
```

---

## 8. Execution Orchestrator — `worker/lookup.ts`

```typescript
export async function runLookup(
  query: LookupQuery,
  env: Env,
  ctx: ExecutionContext
): Promise<HostResult> {
  const start = Date.now()

  // Instantiate key rings
  const ghwKeys = collectSecrets(env, 'GHW_KEY', 18)
  const ghwRing = new KeyRing(ghwKeys, env.KV, 'ghw')

  // ── Layer 1: Core — always runs ──────────────────────────────────────────
  const [internetdb, geo, bgp, rdap, certs, passivedns, robtex] =
    await Promise.allSettled([
      fetchInternetDB(query, env.KV),
      fetchIPAPI(query, env.KV),
      fetchBGPView(query, env.KV),
      fetchRDAP(query, env.KV),
      fetchCRTSH(query, env.KV),
      fetchPassiveDNS(query, env.KV),
      fetchRobtex(query, env.KV),
    ])

  // ── Layer 2: Threat intel — parallel, no dependency on Layer 1 ──────────
  const [urlhaus, threatfox, malwarebazaar, feodo, sslbl] =
    await Promise.allSettled([
      fetchURLhaus(query, env.KV, env.ABUSECH_KEY),
      fetchThreatFox(query, env.KV, env.ABUSECH_KEY),
      fetchMalwareBazaar(query, env.KV, env.ABUSECH_KEY),
      fetchFeodo(query, env.KV),     // local blocklist lookup
      fetchSSLBL(query, env.KV),     // local blocklist lookup
    ])

  // ── Layer 3: CVE enrichment — only if vulns exist ────────────────────────
  const idbData = unwrap<InternetDBResult>(internetdb)
  const cveIds = idbData?.vulns ?? []
  const vulns = await Promise.allSettled(
    cveIds.map(id => fetchCVE(id, env.KV, env.NVD_KEY))
  )

  // ── Layer 4: Bucket recon — domain queries only ───────────────────────────
  const domainQuery = query.type === 'domain' ? query.normalised : null
  const [buckets, wayback] = await Promise.allSettled([
    domainQuery
      ? fetchGHW(domainQuery, env.KV, ghwRing)
      : Promise.resolve(skipped<BucketResult[]>('ghw')),
    fetchWayback(query, env.KV),
  ])

  const result = mergeResults({
    query,
    core: { internetdb, geo, bgp, rdap, certs, passivedns, robtex },
    threat: { urlhaus, threatfox, malwarebazaar, feodo, sslbl },
    vulns,
    recon: { buckets, wayback },
    durationMs: Date.now() - start,
  })

  // Persist search to D1 (non-blocking)
  ctx.waitUntil(persistSearch(query, result, env.DB))

  return result
}
```

---

## 9. Source Module Contract

Every source module must conform to this pattern:

```typescript
// Template for any source module
export async function fetchXXX(
  query: LookupQuery,
  kv: KVNamespace,
  // additional args: apiKey?, keyring?
): Promise<SourceResult<XXXResult>> {
  const cacheKey = `xxx:${query.normalised}`

  // 1. Check cache
  const cached = await cacheGet<XXXResult>(kv, cacheKey)
  if (cached) return ok('xxx', cached, true)

  // 2. Skip if query type not applicable
  if (query.type === 'domain') return skipped('xxx')

  try {
    // 3. Fetch
    const res = await fetch(`https://api.xxx.com/${query.normalised}`, {
      signal: AbortSignal.timeout(8000),  // 8s timeout on every external call
    })

    if (!res.ok) {
      console.error(`[xxx] HTTP ${res.status} for ${query.normalised}`)
      return error('xxx', `HTTP ${res.status}`)
    }

    const data = await res.json<XXXResult>()

    // 4. Cache
    await cachePut(kv, cacheKey, data, TTL.CORE)

    return ok('xxx', data)
  } catch (err) {
    console.error(`[xxx] fetch failed`, err)
    return error('xxx', String(err))
  }
}

// ─── Result constructors ───────────────────────────────────────────────────

function ok<T>(source: string, data: T, cached = false): SourceResult<T> {
  return {
    source,
    status: cached ? 'cached' : 'ok',
    data,
    [cached ? 'cachedAt' : 'fetchedAt']: Date.now(),
  }
}

function error<T>(source: string, message: string): SourceResult<T> {
  return { source, status: 'error', data: null, error: message }
}

function skipped<T>(source: string): SourceResult<T> {
  return { source, status: 'skipped', data: null }
}
```

---

## 10. Merge Layer — `lib/merge.ts`

`mergeResults` takes the raw `Promise.allSettled` output and normalises it into
`HostResult`. It must:

- Never throw — all settled results are either fulfilled or rejected
- Unwrap `PromiseSettledResult` into `SourceResult` (a rejected promise becomes a
  `SourceResult` with `status: 'error'`)
- Count cache hits, source failures, and total sources queried for the `meta` block
- Populate `resolvedIP` and `resolvedDomain` by cross-referencing InternetDB
  hostnames and ip-api results

---

## 11. D1 Schema — `schema.sql`

```sql
CREATE TABLE IF NOT EXISTS searches (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  query       TEXT NOT NULL,
  query_type  TEXT NOT NULL CHECK (query_type IN ('ip','domain','asn')),
  result_json TEXT NOT NULL,
  duration_ms INTEGER,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_searches_query
  ON searches (query, created_at DESC);

CREATE TABLE IF NOT EXISTS saved_targets (
  id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  query      TEXT NOT NULL UNIQUE,
  label      TEXT,
  notes      TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
```

---

## 12. Next.js App Routes

### `app/page.tsx` — Search landing
- Single input accepting IP, domain, or ASN
- Validates input client-side with `lib/validate.ts` before submit
- On submit, navigates to `/host/{query}` (no API call from this page)

### `app/host/[query]/page.tsx` — Results
- SSR: calls `/api/lookup?q={query}` on the server during render
- Returns the full `HostResult` as a prop
- Renders each layer as a collapsible card section:
  - **Overview** — IP, geo, org, ASN, risk badges
  - **Open ports** — port list with service labels from CPEs
  - **Vulnerabilities** — CVE table with CVSS score, severity badge
  - **Certificates** — cert list, SAN domains, expiry
  - **DNS history** — passive DNS table
  - **Threat intel** — abuse.ch findings, IOC matches
  - **Exposed buckets** — GrayHatWarfare results (domain only)
  - **Web history** — Wayback CDX snapshot list
- Failed or skipped sources render a subtle "unavailable" placeholder, never an
  error state that breaks the layout

### `app/api/lookup/route.ts`
```typescript
export const runtime = 'edge'

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url)
  const q = searchParams.get('q')
  if (!q) return Response.json({ error: 'missing q' }, { status: 400 })

  const query = parseQuery(q)
  if (!query) return Response.json({ error: 'invalid query' }, { status: 422 })

  const result = await runLookup(query, getCloudflareContext().env, getCloudflareContext().ctx)
  return Response.json(result)
}
```

---

## 13. Input Validation — `lib/validate.ts`

```typescript
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6_RE = /^[0-9a-fA-F:]{2,39}$/
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i
const ASN_RE = /^as\d+$/i

export function parseQuery(raw: string): LookupQuery | null {
  const s = raw.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')

  if (IPV4_RE.test(s) && isValidIPv4(s)) return { raw, type: 'ip', normalised: s }
  if (IPV6_RE.test(s))                   return { raw, type: 'ip', normalised: s }
  if (ASN_RE.test(s))                    return { raw, type: 'asn', normalised: s }
  if (DOMAIN_RE.test(s))                 return { raw, type: 'domain', normalised: s }

  return null
}

function isValidIPv4(ip: string): boolean {
  return ip.split('.').every(o => parseInt(o) <= 255)
}
```

---

## 14. Error Handling Rules

1. Every `fetch()` call uses `AbortSignal.timeout(8000)` — 8-second hard timeout
2. Every source module wraps its fetch in `try/catch` and returns a `SourceResult`
   with `status: 'error'` on failure — it never throws up to the orchestrator
3. `Promise.allSettled` is used at every layer — a rejected promise is caught and
   converted to an error `SourceResult` in `mergeResults`
4. HTTP 429 / 403 on a keyed source calls `keyring.markExhausted()` and retries
   once with the next healthy key before returning an error result
5. All errors are logged with `console.error` including the source name and query,
   so they appear in Cloudflare Workers tail logs
6. The UI never surfaces raw error messages to users — failed sources show a
   generic "source unavailable" badge

---

## 15. Environment Variables Summary

| Secret / Binding | Type | Value |
|---|---|---|
| `GHW_KEY_1` … `GHW_KEY_18` | Secret | GrayHatWarfare API keys |
| `NVD_KEY` | Secret | NVD NIST API key |
| `ABUSECH_KEY` | Secret | abuse.ch API key (covers all 5 sources) |
| `KV` | KV Namespace | Cache store |
| `DB` | D1 Database | Search history + saved targets |

---

## 16. Scaffolding Order

Build in this order so each step is independently testable:

1. `lib/types.ts` — define all interfaces, no logic
2. `lib/validate.ts` — pure functions, easy to unit test
3. `lib/cache.ts` — KV wrapper with TTL map
4. `lib/keyring.ts` — key rotation, unit test with mock KV
5. `worker/sources/internetdb.ts` — first source, establishes the module pattern
6. `worker/sources/ipapi.ts`
7. `worker/sources/bgpview.ts`
8. `worker/sources/rdap.ts`
9. `worker/sources/crtsh.ts`
10. `worker/sources/passivedns.ts`
11. `worker/sources/robtex.ts`
12. `lib/merge.ts` — write against mock source results, test thoroughly
13. `worker/lookup.ts` — wire Layer 1 only, get end-to-end working
14. `worker/sources/abusech.ts` — all 5 abuse.ch sources, add Layer 2
15. `worker/sources/nvd.ts` — NVD + CIRCL + OSV, add Layer 3
16. `worker/sources/grayhatwarfare.ts` — add key rotation, add Layer 4
17. `worker/sources/wayback.ts`
18. `app/` — Next.js pages and result UI last, once API is stable
19. D1 schema + `persistSearch` — non-critical, add last

---

## 17. Cloudflare Limits Reference

| Resource | Free limit | Expected usage |
|---|---|---|
| Workers requests | 100k/day | Low — most served from Pages SSR |
| KV reads | 100k/day | Medium — cache hit rate should be high |
| KV writes | 1k/day | Low — one write per unique query per TTL |
| D1 reads | 5M/day | Very low — search history only |
| D1 storage | 5GB | Negligible |
| Workers CPU | 10ms/invocation | Fine — all work is I/O, not compute |

KV writes are the tightest constraint. Every unique query writes up to ~17 KV keys
(one per source). At 1k writes/day that supports ~58 fully unique queries per day
before any caching. In practice, repeat queries on the same IPs dominate so effective
throughput is much higher. Monitor with `wrangler tail`.