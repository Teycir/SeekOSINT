/**
 * test/merge.test.ts — mergeResults non-regression suite
 *
 * Covers the exactOptionalPropertyTypes fix for resolvedIP/resolvedDomain:
 * when undefined, those keys must be ABSENT from the returned object.
 */
import { describe, it, expect } from 'vitest'
import { mergeResults } from '../lib/merge'
import { ok, error, skipped } from '../lib/results'
import type { LookupQuery, IPAPIResult, InternetDBResult } from '../lib/types'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeSettled<T>(value: T): PromiseFulfilledResult<T> {
  return { status: 'fulfilled', value }
}
function makeRejected(reason: string): PromiseRejectedResult {
  return { status: 'rejected', reason }
}

const ipQuery: LookupQuery = { raw: '1.1.1.1', type: 'ip', normalised: '1.1.1.1' }
const domainQuery: LookupQuery = { raw: 'example.com', type: 'domain', normalised: 'example.com' }
const asnQuery: LookupQuery = { raw: 'as13335', type: 'asn', normalised: 'as13335' }

function allSkipped() {
  return {
    internetdb: makeSettled(skipped('internetdb')),
    geo:        makeSettled(skipped('ipapi')),
    bgp:        makeSettled(skipped('bgpview')),
    rdap:       makeSettled(skipped('rdap')),
    whois:      makeSettled(skipped('whois')),
    certs:      makeSettled(skipped('crtsh')),
    passivedns: makeSettled(skipped('passivedns')),
    robtex:     makeSettled(skipped('robtex')),
  }
}

function allThreatSkipped() {
  return {
    urlhaus:       makeSettled(skipped('urlhaus')),
    threatfox:     makeSettled(skipped('threatfox')),
    malwarebazaar: makeSettled(skipped('malwarebazaar')),
    feodo:         makeSettled(skipped('feodo')),
    sslbl:         makeSettled(skipped('sslbl')),
  }
}

function allReconSkipped() {
  return {
    buckets: makeSettled(skipped('ghw')),
    wayback: makeSettled(skipped('wayback')),
  }
}

function baseInput(query: LookupQuery) {
  return {
    query,
    core: allSkipped(),
    threat: allThreatSkipped(),
    vulns: [],
    recon: allReconSkipped(),
    durationMs: 100,
    circuitBreakers: [],
  }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('mergeResults', () => {
  it('produces a valid HostResult from fulfilled sources', () => {
    const idb = ok('internetdb', {
      ip: '1.1.1.1', ports: [], hostnames: ['one.one.one.one'],
      tags: [], vulns: [], cpes: [],
    })
    const input = baseInput(ipQuery)
    input.core.internetdb = makeSettled(idb)
    const result = mergeResults(input)

    expect(result.query.normalised).toBe('1.1.1.1')
    expect(result.resolvedIP).toBe('1.1.1.1')
    expect(result.resolvedDomain).toBe('one.one.one.one')
    expect(result.meta.durationMs).toBe(100)
    expect(result.meta.sourcesFailed).toBe(0)
    expect(result.core.internetdb.status).toBe('ok')
  })

  it('converts rejected promises into error SourceResults', () => {
    const input = baseInput(ipQuery)
    input.core.internetdb = makeRejected('network error')
    const result = mergeResults(input)

    expect(result.core.internetdb.status).toBe('error')
    expect(result.core.internetdb.error).toContain('network error')
    expect(result.meta.sourcesFailed).toBe(1)
  })

  // ── exactOptionalPropertyTypes regression ──────────────────────────────────

  it('omits resolvedIP key entirely when query type is domain with no geo IP', () => {
    const result = mergeResults(baseInput(domainQuery))
    // Key must be ABSENT, not set to undefined — this was the bug
    expect('resolvedIP' in result).toBe(false)
    expect(result.resolvedDomain).toBe('example.com')
  })

  it('omits resolvedDomain key entirely when query type is IP with no hostnames', () => {
    const idb = ok('internetdb', {
      ip: '1.1.1.1', ports: [], hostnames: [],
      tags: [], vulns: [], cpes: [],
    })
    const input = baseInput(ipQuery)
    input.core.internetdb = makeSettled(idb)
    const result = mergeResults(input)

    expect(result.resolvedIP).toBe('1.1.1.1')
    expect('resolvedDomain' in result).toBe(false)
  })

  it('populates resolvedIP from geo.ip for domain queries', () => {
    const geo = ok<IPAPIResult>('ipapi', {
      ip: '93.184.216.34', country: 'US', countryCode: 'US', region: 'MA',
      city: 'Norwell', lat: 42, lon: -70, org: 'EDGECAST', asn: 'AS15133',
      isp: 'EdgeCast', timezone: 'America/New_York', proxy: false, hosting: true, mobile: false,
    })
    const input = baseInput(domainQuery)
    input.core.geo = makeSettled(geo)
    const result = mergeResults(input)

    expect(result.resolvedIP).toBe('93.184.216.34')
    expect(result.resolvedDomain).toBe('example.com')
  })

  it('omits both resolvedIP and resolvedDomain for ASN queries', () => {
    const result = mergeResults(baseInput(asnQuery))
    expect('resolvedIP' in result).toBe(false)
    expect('resolvedDomain' in result).toBe(false)
  })

  // ── Meta counting ──────────────────────────────────────────────────────────

  it('counts skipped sources as neither queried nor failed', () => {
    const result = mergeResults(baseInput(ipQuery))
    expect(result.meta.sourcesQueried).toBe(0)
    expect(result.meta.sourcesFailed).toBe(0)
    expect(result.meta.cacheHits).toBe(0)
  })

  it('counts cached sources separately from fresh fetches', () => {
    const cached = ok('internetdb', {
      ip: '1.1.1.1', ports: [], hostnames: [], tags: [], vulns: [], cpes: [],
    }, true)
    const fresh = ok('ipapi', {
      ip: '1.1.1.1', country: 'US', countryCode: 'US', region: '', city: '',
      lat: 0, lon: 0, org: '', asn: '', isp: '', timezone: '', proxy: false, hosting: false, mobile: false,
    })
    const input = baseInput(ipQuery)
    input.core.internetdb = makeSettled(cached)
    input.core.geo = makeSettled(fresh)
    const result = mergeResults(input)

    expect(result.meta.cacheHits).toBe(1)
    expect(result.meta.sourcesQueried).toBe(2)
    expect(result.meta.sourcesFailed).toBe(0)
  })

  it('aggregates multiple failed sources in sourcesFailed', () => {
    const input = baseInput(ipQuery)
    input.core.internetdb = makeRejected('err1')
    input.core.geo        = makeRejected('err2')
    input.core.bgp        = makeRejected('err3')
    const result = mergeResults(input)
    expect(result.meta.sourcesFailed).toBe(3)
  })

  it('passes vulns array through to output', () => {
    const cveResult = ok('nvd', {
      id: 'CVE-2021-44228', description: 'Log4Shell', source: 'nvd' as const,
    })
    const input = baseInput(ipQuery)
    input.vulns = [makeSettled(cveResult)]
    const result = mergeResults(input)
    expect(result.vulns).toHaveLength(1)
    expect(result.vulns[0]?.data?.id).toBe('CVE-2021-44228')
  })

  it('sets meta.timestamp close to Date.now()', () => {
    const before = Date.now()
    const result = mergeResults(baseInput(ipQuery))
    const after = Date.now()
    expect(result.meta.timestamp).toBeGreaterThanOrEqual(before)
    expect(result.meta.timestamp).toBeLessThanOrEqual(after)
  })
})
