// ─── Input ────────────────────────────────────────────────────────────────────

export type QueryType = 'ip' | 'domain' | 'asn'

export interface LookupQuery {
  raw: string        // original user input
  type: QueryType
  normalised: string // trimmed, lowercased, stripped of protocol
  /** When true, all KV cache reads are bypassed (force-fresh from upstream). */
  forceRefresh?: boolean
}

// ─── Per-source result wrappers ───────────────────────────────────────────────

export type SourceStatus = 'ok' | 'cached' | 'error' | 'skipped'

export interface SourceResult<T> {
  source: string
  status: SourceStatus
  data: T | null
  error?: string
  cachedAt?: number  // unix ms
  fetchedAt?: number
}

// ─── Layer 1: Core ────────────────────────────────────────────────────────────

export interface InternetDBResult {
  ip: string
  ports: number[]
  hostnames: string[]
  tags: string[]
  vulns: string[]   // CVE IDs e.g. ["CVE-2021-44228"]
  cpes: string[]    // e.g. ["cpe:/a:apache:log4j:2.14.1"]
}

export interface IPAPIResult {
  ip: string
  country: string
  countryCode: string
  region: string
  city: string
  lat: number
  lon: number
  org: string       // "AS14618 Amazon.com, Inc."
  asn: string       // "AS14618"
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
  prefixes: string[]  // ["1.2.3.0/24"]
  upstreams: number[] // upstream ASN numbers
  peers: number[]
  rir: string         // ARIN, RIPE, etc.
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
  country?: string
}

export interface RDAPContact {
  role: string
  email?: string
  org?: string
}

export interface WhoisResult {
  domain:           string
  registrar?:       string
  registrarUrl?:    string
  registrant?:      string
  registrantOrg?:   string
  registrantEmail?: string
  adminEmail?:      string
  techEmail?:       string
  abuseEmail?:      string
  created?:         string
  updated?:         string
  expires?:         string
  nameservers?:     string[]
  dnssec?:          string
  status?:          string[]
  rawText?:         string
}

export interface CertRecord {
  id: number
  issuer: string
  commonName: string
  nameValue: string   // may contain \n-separated SANs
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
  passiveDNS: { o: string; t: number }[]  // outgoing
  reverseDNS: { o: string; t: number }[]  // incoming
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
  DstIP?: string       // destination IP — present in the JSON feed, used for IP lookup matching
  DstPort?: number
  Subject?: string
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
  timestamp: string  // YYYYMMDDHHmmss
  statusCode: string
  mimeType: string
}

// ─── Circuit breaker meta (embedded in HostResult.meta) ───────────────────────

export interface CircuitBreakerMeta {
  source:         string
  state:          'closed' | 'open' | 'half-open'
  windowRequests: number
  windowFailures: number
  /** Unix-ms when the breaker auto-recovers; 0 when closed */
  opensUntil:     number
}

// ─── Normalised threat indicators ─────────────────────────────────────────────
// Re-exported from lib/normalize.ts so consumers import from a single place.

export type { ThreatIndicator, ThreatFeed } from './normalize'

// ─── Risk score ───────────────────────────────────────────────────────────────
// Re-exported from lib/risk.ts so consumers import from a single place.

export type { RiskScore, RiskBreakdown, RiskSeverity } from './risk'

// ─── Merged output ─────────────────────────────────────────────────────────────

export interface HostResult {
  query: LookupQuery
  /** For domain queries: the A record IP DNS resolved to. Null if DNS failed. */
  resolvedIP?: string
  /** For IP queries: the PTR/rDNS hostname, if available. */
  resolvedDomain?: string
  /** True when a domain query could not be resolved to an IP via DoH.
   *  IP-based sources (geo, ports, threat intel) will all be skipped.
   *  Domain-string sources (RDAP, certs, passive DNS) still run. */
  dnsResolutionFailed?: boolean

  // Layer 1
  core: {
    internetdb:  SourceResult<InternetDBResult>
    geo:         SourceResult<IPAPIResult>
    bgp:         SourceResult<BGPViewResult>
    rdap:        SourceResult<RDAPResult>
    whois:       SourceResult<WhoisResult>
    certs:       SourceResult<CertRecord[]>
    passivedns:  SourceResult<PassiveDNSRecord[]>
    robtex:      SourceResult<RobtexResult>
  }

  // Layer 2
  threat: {
    urlhaus:       SourceResult<URLhausResult>
    threatfox:     SourceResult<ThreatFoxResult>
    malwarebazaar: SourceResult<MalwareBazaarResult>
    feodo:         SourceResult<FeodoEntry | null>
    sslbl:         SourceResult<SSLBLEntry[]>
  }

  /**
   * Deduplicated, cross-feed threat indicators derived from all Layer 2
   * sources. Computed by normalizeThreatIndicators() in merge.ts.
   * This is the canonical view consumers should render — the raw
   * per-source threat data is still present in `threat` for debugging.
   */
  normalizedThreats: import('./normalize').ThreatIndicator[]

  /**
   * Aggregated risk score (0–100) with per-category breakdown.
   * Computed by computeRiskScore() in merge.ts from the full HostResult.
   */
  riskScore: import('./risk').RiskScore

  // Layer 3 — only populated if internetdb.vulns is non-empty
  vulns: SourceResult<CVEDetail>[]

  // Layer 4
  recon: {
    buckets:  SourceResult<BucketResult[]>
    wayback:  SourceResult<WaybackResult[]>
  }

  meta: {
    durationMs:      number
    timestamp:       number
    cacheHits:       number
    sourcesQueried:  number
    sourcesFailed:   number
    /** Snapshot of every source's circuit-breaker state at response time */
    circuitBreakers: CircuitBreakerMeta[]
  }
}

// ─── Cloudflare Worker env bindings ───────────────────────────────────────────

export interface Env {
  KV: KVNamespace
  DB: D1Database
  NVD_KEY: string
  ABUSECH_KEY: string
  ADMIN_TOKEN?: string
  /**
   * Optional webhook endpoint.  When set, the cron job POSTs a JSON payload
   * there for every target that has changed since the last snapshot.
   * Format: any HTTPS URL that accepts POST with Content-Type: application/json.
   * Slack incoming webhooks, Discord webhooks, and generic HTTP endpoints all work.
   */
  WEBHOOK_URL?: string
  TURNSTILE_SECRET_KEY?: string
  // GHW_KEY_1 … GHW_KEY_18 — accessed dynamically via collectSecrets()
  [key: string]: unknown
}
