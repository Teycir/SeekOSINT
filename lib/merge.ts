/**
 * mergeResults — normalise Promise.allSettled output into HostResult.
 *
 * Rules:
 * - Never throws — all settled results are fulfilled or rejected
 * - A rejected promise becomes a SourceResult with status: 'error'
 * - Counts cache hits, failures, and total sources for the meta block
 * - Populates resolvedIP / resolvedDomain by cross-referencing sources
 */
import type {
  BucketResult,
  CVEDetail,
  CertRecord,
  FeodoEntry,
  HostResult,
  IPAPIResult,
  InternetDBResult,
  LookupQuery,
  MalwareBazaarResult,
  PassiveDNSRecord,
  BGPViewResult,
  RDAPResult,
  RobtexResult,
  SSLBLEntry,
  SourceResult,
  ThreatFoxResult,
  URLhausResult,
  WaybackResult,
} from './types'
import { unwrapSettled } from './results'

interface MergeInput {
  query: LookupQuery
  core: {
    internetdb: PromiseSettledResult<SourceResult<InternetDBResult>>
    geo:        PromiseSettledResult<SourceResult<IPAPIResult>>
    bgp:        PromiseSettledResult<SourceResult<BGPViewResult>>
    rdap:       PromiseSettledResult<SourceResult<RDAPResult>>
    certs:      PromiseSettledResult<SourceResult<CertRecord[]>>
    passivedns: PromiseSettledResult<SourceResult<PassiveDNSRecord[]>>
    robtex:     PromiseSettledResult<SourceResult<RobtexResult>>
  }
  threat: {
    urlhaus:       PromiseSettledResult<SourceResult<URLhausResult>>
    threatfox:     PromiseSettledResult<SourceResult<ThreatFoxResult>>
    malwarebazaar: PromiseSettledResult<SourceResult<MalwareBazaarResult>>
    feodo:         PromiseSettledResult<SourceResult<FeodoEntry | null>>
    sslbl:         PromiseSettledResult<SourceResult<SSLBLEntry[]>>
  }
  vulns:  PromiseSettledResult<SourceResult<CVEDetail>>[]
  recon: {
    buckets: PromiseSettledResult<SourceResult<BucketResult[]>>
    wayback: PromiseSettledResult<SourceResult<WaybackResult[]>>
  }
  durationMs: number
}

function countMeta(results: SourceResult<unknown>[]): {
  cacheHits: number
  sourcesQueried: number
  sourcesFailed: number
} {
  let cacheHits = 0
  let sourcesQueried = 0
  let sourcesFailed = 0

  for (const r of results) {
    if (r.status === 'skipped') continue
    sourcesQueried++
    if (r.status === 'cached') cacheHits++
    if (r.status === 'error') sourcesFailed++
  }

  return { cacheHits, sourcesQueried, sourcesFailed }
}

export function mergeResults(input: MergeInput): HostResult {
  const { query, durationMs } = input

  // Unwrap all settled results into SourceResults
  const core = {
    internetdb: unwrapSettled(input.core.internetdb, 'internetdb'),
    geo:        unwrapSettled(input.core.geo, 'ipapi'),
    bgp:        unwrapSettled(input.core.bgp, 'bgpview'),
    rdap:       unwrapSettled(input.core.rdap, 'rdap'),
    certs:      unwrapSettled(input.core.certs, 'crtsh'),
    passivedns: unwrapSettled(input.core.passivedns, 'passivedns'),
    robtex:     unwrapSettled(input.core.robtex, 'robtex'),
  }

  const threat = {
    urlhaus:       unwrapSettled(input.threat.urlhaus, 'urlhaus'),
    threatfox:     unwrapSettled(input.threat.threatfox, 'threatfox'),
    malwarebazaar: unwrapSettled(input.threat.malwarebazaar, 'malwarebazaar'),
    feodo:         unwrapSettled(input.threat.feodo, 'feodo'),
    sslbl:         unwrapSettled(input.threat.sslbl, 'sslbl'),
  }

  const vulns = input.vulns.map(
    (s, i) => {
      // Use the real CVE ID from the settled value if available, else fall back to index
      const sourceId = s.status === 'fulfilled' && s.value.data?.id
        ? s.value.data.id
        : `cve-${i}`
      return unwrapSettled(s, sourceId)
    },
  ) as SourceResult<CVEDetail>[]

  const recon = {
    buckets: unwrapSettled(input.recon.buckets, 'ghw'),
    wayback: unwrapSettled(input.recon.wayback, 'wayback'),
  }

  // Derive resolvedIP / resolvedDomain
  let resolvedIP: string | undefined
  let resolvedDomain: string | undefined

  if (query.type === 'ip') {
    resolvedIP = query.normalised
    // Best effort: grab first hostname from InternetDB
    const idb = core.internetdb.data
    if (idb && idb.hostnames.length > 0) resolvedDomain = idb.hostnames[0]
  } else if (query.type === 'domain') {
    resolvedDomain = query.normalised
    // Geo source returns the IP we resolved to
    const geo = core.geo.data
    if (geo) resolvedIP = geo.ip
  }

  // Collect all non-skipped results for meta counting
  const allResults: SourceResult<unknown>[] = [
    ...Object.values(core),
    ...Object.values(threat),
    ...vulns,
    ...Object.values(recon),
  ]

  const { cacheHits, sourcesQueried, sourcesFailed } = countMeta(allResults)

  return {
    query,
    ...(resolvedIP !== undefined && { resolvedIP }),
    ...(resolvedDomain !== undefined && { resolvedDomain }),
    core,
    threat,
    vulns,
    recon,
    meta: {
      durationMs,
      timestamp:      Date.now(),
      cacheHits,
      sourcesQueried,
      sourcesFailed,
    },
  }
}
