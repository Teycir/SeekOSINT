/**
 * normalize.ts — Threat indicator normalization layer.
 *
 * When the same IP/domain appears across multiple threat feeds
 * (URLhaus, ThreatFox, Feodo, SSLBL), this module deduplicates and
 * merges them into a canonical ThreatIndicator shape with:
 *   - provenance (which feeds reported it)
 *   - aggregated confidence score
 *   - unified first/last seen timestamps
 *   - merged tag set
 *
 * This is a pure result-transformation step — no DB writes, no fetches.
 * It runs inside mergeResults() before the HostResult is returned.
 *
 * Confidence scoring logic:
 *   URLhaus online URL     → 90
 *   URLhaus offline URL    → 60
 *   ThreatFox IOC          → uses ioc.confidence_level directly (0–100)
 *   Feodo C2 Online        → 95
 *   Feodo C2 Offline       → 70
 *   SSLBL entry            → 80
 *
 * When an indicator comes from multiple feeds the confidence is the
 * MAX across all sources (not averaged — each source is independent
 * evidence, and the highest single-source confidence is the floor).
 */

import type {
  FeodoEntry,
  MalwareBazaarResult,
  SourceResult,
  SSLBLEntry,
  ThreatFoxResult,
  URLhausResult,
} from './types'

// ─── Canonical indicator type ─────────────────────────────────────────────────

export type ThreatFeed = 'urlhaus' | 'threatfox' | 'feodo' | 'sslbl' | 'malwarebazaar'

export interface ThreatIndicator {
  /** The observable value — IP, domain, URL, hash, etc. */
  ioc: string
  /** What kind of observable it is */
  iocType: 'ip' | 'domain' | 'url' | 'hash' | 'unknown'
  /** Human-readable threat category e.g. "C2", "malware_download", "phishing" */
  threatType: string
  /** Malware family name(s), deduplicated */
  malwareFamilies: string[]
  /** Which feeds reported this indicator */
  provenance: ThreatFeed[]
  /** 0–100. MAX across all contributing sources. */
  confidence: number
  /** Earliest first_seen across all sources (ISO string) */
  firstSeen: string | null
  /** Latest last_seen across all sources (ISO string) */
  lastSeen: string | null
  /** Deduplicated union of all tags across sources */
  tags: string[]
  /** Source-specific reference URLs for pivot links */
  references: Partial<Record<ThreatFeed, string>>
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Deduplicate, lowercase, sort, and assert the result is a ThreatFeed array. */
function dedupFeeds(arr: ThreatFeed[]): ThreatFeed[] {
  return [...new Set(arr)].sort() as ThreatFeed[]
}

/** Deduplicate, lowercase and sort an array of strings. */
function dedup(arr: (string | null | undefined)[]): string[] {
  return [...new Set(
    arr
      .filter((s): s is string => typeof s === 'string' && s.length > 0)
      .map(s => s.toLowerCase()),
  )].sort()
}

/** Return the earlier of two ISO strings, or whichever is non-null. */
function earlierDate(a: string | null, b: string | null): string | null {
  if (!a) return b
  if (!b) return a
  return a < b ? a : b
}

/** Return the later of two ISO strings, or whichever is non-null. */
function laterDate(a: string | null, b: string | null): string | null {
  if (!a) return b
  if (!b) return a
  return a > b ? a : b
}

function guessIocType(ioc: string): ThreatIndicator['iocType'] {
  if (/^https?:\/\//i.test(ioc)) return 'url'
  if (/^[0-9]{1,3}(\.[0-9]{1,3}){3}(:\d+)?$/.test(ioc)) return 'ip'
  if (/^[0-9a-f]{32,64}$/i.test(ioc)) return 'hash'
  if (/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/i.test(ioc)) return 'domain'
  return 'unknown'
}

// ─── Per-feed extractors ──────────────────────────────────────────────────────

function fromURLhaus(r: SourceResult<URLhausResult>): ThreatIndicator[] {
  if (
    r.status === 'error' ||
    r.status === 'skipped' ||
    !r.data ||
    r.data.query_status !== 'is_host'
  ) return []

  const indicators: ThreatIndicator[] = []

  for (const url of r.data.urls ?? []) {
    const confidence = url.url_status === 'online' ? 90 : 60

    indicators.push({
      ioc:             url.url,
      iocType:         'url',
      threatType:      url.threat || 'malware_download',
      malwareFamilies: [],
      provenance:      ['urlhaus'],
      confidence,
      firstSeen:       url.date_added ?? null,
      lastSeen:        url.date_added ?? null,
      tags:            dedup(url.tags),
      references:      r.data.urlhaus_reference
        ? { urlhaus: r.data.urlhaus_reference }
        : {},
    })
  }

  return indicators
}

function fromThreatFox(r: SourceResult<ThreatFoxResult>): ThreatIndicator[] {
  if (
    r.status === 'error' ||
    r.status === 'skipped' ||
    !r.data ||
    r.data.query_status !== 'ok'
  ) return []

  return (r.data.data ?? []).map(ioc => ({
    ioc:             ioc.ioc,
    iocType:         guessIocType(ioc.ioc),
    threatType:      ioc.threat_type || 'unknown',
    malwareFamilies: dedup([ioc.malware, ioc.malware_alias]),
    provenance:      ['threatfox' as ThreatFeed],
    confidence:      ioc.confidence_level,
    firstSeen:       ioc.first_seen ?? null,
    lastSeen:        ioc.last_seen ?? null,
    tags:            dedup(ioc.tags),
    references:      {},
  }))
}

function fromFeodo(r: SourceResult<FeodoEntry | null>): ThreatIndicator[] {
  if (r.status === 'error' || r.status === 'skipped' || !r.data) return []
  const entry = r.data
  const confidence = entry.status === 'Online' ? 95 : 70

  return [{
    ioc:             entry.ip_address,
    iocType:         'ip',
    threatType:      'c2',
    malwareFamilies: dedup([entry.malware]),
    provenance:      ['feodo'],
    confidence,
    firstSeen:       entry.first_seen ?? null,
    lastSeen:        entry.last_seen ?? null,
    tags:            dedup([entry.malware, entry.status.toLowerCase()]),
    references:      { feodo: `https://feodotracker.abuse.ch/browse/host/${entry.ip_address}/` },
  }]
}

function fromSSLBL(r: SourceResult<SSLBLEntry[]>): ThreatIndicator[] {
  if (r.status === 'error' || r.status === 'skipped' || !r.data) return []

  return r.data.map(entry => ({
    ioc:             entry.SHA1,
    iocType:         'hash' as ThreatIndicator['iocType'],
    threatType:      'ssl_botnet',
    malwareFamilies: [],
    provenance:      ['sslbl' as ThreatFeed],
    confidence:      80,
    firstSeen:       entry.Listingdate ?? null,
    lastSeen:        entry.Listingtime ?? null,
    tags:            dedup([entry.SuspiciousReason]),
    references:      { sslbl: `https://sslbl.abuse.ch/ssl-certificates/sha1/${entry.SHA1}/` },
  }))
}

function fromMalwareBazaar(r: SourceResult<MalwareBazaarResult>): ThreatIndicator[] {
  if (
    r.status === 'error' ||
    r.status === 'skipped' ||
    !r.data ||
    r.data.query_status !== 'ok'
  ) return []

  return (r.data.data ?? []).map(entry => ({
    ioc:             entry.sha256_hash,
    iocType:         'hash' as ThreatIndicator['iocType'],
    threatType:      'malware_sample',
    malwareFamilies: dedup([entry.signature ?? undefined]),
    provenance:      ['malwarebazaar' as ThreatFeed],
    confidence:      85,
    firstSeen:       entry.first_seen ?? null,
    lastSeen:        entry.last_seen ?? null,
    tags:            dedup(entry.tags),
    references:      { malwarebazaar: `https://bazaar.abuse.ch/sample/${entry.sha256_hash}/` },
  }))
}

// ─── Merge step ───────────────────────────────────────────────────────────────

/**
 * Merge two indicators that share the same canonical ioc value.
 * Called after grouping all raw indicators by ioc.
 */
function mergeIndicators(a: ThreatIndicator, b: ThreatIndicator): ThreatIndicator {
  return {
    ioc:             a.ioc,
    iocType:         a.iocType !== 'unknown' ? a.iocType : b.iocType,
    threatType:      a.threatType !== 'unknown' ? a.threatType : b.threatType,
    malwareFamilies: dedup([...a.malwareFamilies, ...b.malwareFamilies]),
    provenance:      dedupFeeds([...a.provenance, ...b.provenance]),
    confidence:      Math.max(a.confidence, b.confidence),
    firstSeen:       earlierDate(a.firstSeen, b.firstSeen),
    lastSeen:        laterDate(a.lastSeen, b.lastSeen),
    tags:            dedup([...a.tags, ...b.tags]),
    references:      { ...a.references, ...b.references },
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface ThreatSourceResults {
  urlhaus:       SourceResult<URLhausResult>
  threatfox:     SourceResult<ThreatFoxResult>
  feodo:         SourceResult<FeodoEntry | null>
  sslbl:         SourceResult<SSLBLEntry[]>
  malwarebazaar: SourceResult<MalwareBazaarResult>
}

/**
 * normalizeThreatIndicators — aggregate all threat feed results into a
 * deduplicated list of canonical ThreatIndicator objects, sorted by
 * descending confidence then ascending firstSeen.
 *
 * Identical ioc values from different feeds are merged into one entry
 * with combined provenance, max confidence, and the widest seen window.
 */
export function normalizeThreatIndicators(
  sources: ThreatSourceResults,
): ThreatIndicator[] {
  const raw: ThreatIndicator[] = [
    ...fromURLhaus(sources.urlhaus),
    ...fromThreatFox(sources.threatfox),
    ...fromFeodo(sources.feodo),
    ...fromSSLBL(sources.sslbl),
    ...fromMalwareBazaar(sources.malwarebazaar),
  ]

  // Group by normalised ioc value, then reduce each group to one merged entry
  const grouped = new Map<string, ThreatIndicator>()
  for (const indicator of raw) {
    const key = indicator.ioc.toLowerCase()
    const existing = grouped.get(key)
    grouped.set(key, existing ? mergeIndicators(existing, indicator) : indicator)
  }

  const result = [...grouped.values()]

  // Sort: highest confidence first, then earliest firstSeen as tiebreaker
  result.sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence
    if (a.firstSeen && b.firstSeen) return a.firstSeen < b.firstSeen ? -1 : 1
    return 0
  })

  return result
}
