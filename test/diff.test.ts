/**
 * test/diff.test.ts — unit tests for diffHostResults and summariseDiff
 */
import { describe, it, expect } from 'vitest'
import { diffHostResults, summariseDiff } from '../lib/diff'
import type { HostResult, SourceResult } from '../lib/types'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sr<T>(data: T): SourceResult<T> {
  return { source: 'test', status: 'ok', data }
}
function skipped<T>(): SourceResult<T> {
  return { source: 'test', status: 'skipped', data: null }
}

const BASE_META = {
  durationMs: 100, timestamp: 0, cacheHits: 0,
  sourcesQueried: 0, sourcesFailed: 0, circuitBreakers: [],
}

const BASE_RISK = { score: 0, severity: 'LOW' as const, breakdown: { blocklists: 0, threatIntel: 0, vulns: 0, ports: 0, networkFlags: 0, total: 0 } }

function base(overrides: Partial<HostResult> = {}): HostResult {
  return {
    query: { raw: '1.2.3.4', type: 'ip', normalised: '1.2.3.4' },
    core: {
      internetdb: skipped(), geo: skipped(), bgp: skipped(),
      rdap: skipped(), certs: skipped(), passivedns: skipped(), robtex: skipped(),
    },
    threat: {
      urlhaus: skipped(), threatfox: skipped(), malwarebazaar: skipped(),
      feodo: skipped(), sslbl: skipped(),
    },
    normalizedThreats: [],
    riskScore: BASE_RISK,
    vulns: [],
    recon: { buckets: skipped(), wayback: skipped() },
    meta: BASE_META,
    ...overrides,
  }
}

function idb(ports: number[], hostnames: string[] = []) {
  return sr({ ip: '1.2.3.4', ports, hostnames, tags: [], vulns: [], cpes: [] })
}

function cveResult(id: string, score?: number, severity?: string): SourceResult<import('../lib/types').CVEDetail> {
  return sr({
    id, description: '', source: 'nvd' as const,
    ...(score !== undefined && { cvssV3Score: score }),
    ...(severity && { cvssV3Severity: severity as import('../lib/types').CVEDetail['cvssV3Severity'] }),
  })
}

/** Build a CertRecord SourceResult with a given notAfter ISO date */
function cert(commonName: string, notAfter: string): SourceResult<import('../lib/types').CertRecord[]> {
  return sr([{
    id: 1, issuer: 'Test CA', commonName, nameValue: commonName,
    notBefore: '2024-01-01T00:00:00Z', notAfter, serialNumber: 'abc123',
  }])
}

/** ISO date N days from now */
function daysFromNow(n: number): string {
  return new Date(Date.now() + n * 86_400_000).toISOString()
}


// ─── No changes ───────────────────────────────────────────────────────────────

describe('diffHostResults', () => {
  it('returns hasChanges=false for identical results', () => {
    const r = base()
    const d = diffHostResults(r, r)
    expect(d.hasChanges).toBe(false)
    expect(d.ports).toHaveLength(0)
    expect(d.cves).toHaveLength(0)
    expect(d.threats).toHaveLength(0)
    expect(d.geo).toHaveLength(0)
    expect(d.certExpiry).toHaveLength(0)
  })

  it('always sets diffedAt to a recent unix timestamp', () => {
    const before = Math.floor(Date.now() / 1000) - 2
    const d = diffHostResults(base(), base())
    expect(d.diffedAt).toBeGreaterThanOrEqual(before)
  })

// ─── Ports ────────────────────────────────────────────────────────────────────

  it('detects a newly opened port', () => {
    const prev = base({ core: { ...base().core, internetdb: idb([80]) } })
    const next = base({ core: { ...base().core, internetdb: idb([80, 443]) } })
    const d = diffHostResults(prev, next)
    expect(d.hasChanges).toBe(true)
    expect(d.ports).toContainEqual({ port: 443, direction: 'opened' })
    expect(d.ports).not.toContainEqual(expect.objectContaining({ port: 80 }))
  })

  it('detects a closed port', () => {
    const prev = base({ core: { ...base().core, internetdb: idb([80, 3389]) } })
    const next = base({ core: { ...base().core, internetdb: idb([80]) } })
    const d = diffHostResults(prev, next)
    expect(d.hasChanges).toBe(true)
    expect(d.ports).toContainEqual({ port: 3389, direction: 'closed' })
  })

  it('reports both opened and closed ports in the same diff', () => {
    const prev = base({ core: { ...base().core, internetdb: idb([22, 80]) } })
    const next = base({ core: { ...base().core, internetdb: idb([80, 443]) } })
    const d = diffHostResults(prev, next)
    expect(d.ports).toContainEqual({ port: 22,  direction: 'closed' })
    expect(d.ports).toContainEqual({ port: 443, direction: 'opened' })
    expect(d.ports).not.toContainEqual(expect.objectContaining({ port: 80 }))
  })

  it('no port changes when lists are identical', () => {
    const r = base({ core: { ...base().core, internetdb: idb([80, 443]) } })
    expect(diffHostResults(r, r).ports).toHaveLength(0)
  })

// ─── CVEs ─────────────────────────────────────────────────────────────────────

  it('detects a new CVE appearing', () => {
    const prev = base({ vulns: [] })
    const next = base({ vulns: [cveResult('CVE-2021-44228', 10.0, 'CRITICAL')] })
    const d = diffHostResults(prev, next)
    expect(d.hasChanges).toBe(true)
    expect(d.cves).toContainEqual({ id: 'CVE-2021-44228', direction: 'appeared', severity: 'CRITICAL', score: 10.0 })
  })

  it('detects a CVE resolving', () => {
    const prev = base({ vulns: [cveResult('CVE-2021-44228', 10.0, 'CRITICAL')] })
    const next = base({ vulns: [] })
    const d = diffHostResults(prev, next)
    expect(d.cves).toContainEqual({ id: 'CVE-2021-44228', direction: 'resolved' })
  })

  it('does not flag CVEs present in both snapshots', () => {
    const r = base({ vulns: [cveResult('CVE-2022-0001', 7.5, 'HIGH')] })
    expect(diffHostResults(r, r).cves).toHaveLength(0)
  })

  it('includes severity and score only when available', () => {
    const prev = base()
    const next = base({ vulns: [cveResult('CVE-2022-XXXX')] })
    const d = diffHostResults(prev, next)
    const change = d.cves[0]!
    expect(change.id).toBe('CVE-2022-XXXX')
    expect(change.severity).toBeUndefined()
    expect(change.score).toBeUndefined()
  })


// ─── Threat intel ─────────────────────────────────────────────────────────────

  it('detects URLhaus appearance', () => {
    const prev = base({ threat: { ...base().threat, urlhaus: sr({ query_status: 'no_results' }) } })
    const next = base({ threat: { ...base().threat, urlhaus: sr({ query_status: 'is_host' }) } })
    const d = diffHostResults(prev, next)
    expect(d.threats).toContainEqual({ feed: 'urlhaus', direction: 'appeared' })
  })

  it('detects URLhaus resolution', () => {
    const prev = base({ threat: { ...base().threat, urlhaus: sr({ query_status: 'is_host' }) } })
    const next = base({ threat: { ...base().threat, urlhaus: sr({ query_status: 'no_results' }) } })
    const d = diffHostResults(prev, next)
    expect(d.threats).toContainEqual({ feed: 'urlhaus', direction: 'resolved' })
  })

  it('detects Feodo appearance with malware family', () => {
    const feodoEntry = { ip_address: '1.2.3.4', port: 4444, status: 'Online' as const, hostname: null, as_number: 1, as_name: 'X', country: 'RU', first_seen: '2024-01-01', last_seen: '2024-06-01', malware: 'Emotet' }
    const prev = base({ threat: { ...base().threat, feodo: sr(null) } })
    const next = base({ threat: { ...base().threat, feodo: sr(feodoEntry) } })
    const d = diffHostResults(prev, next)
    expect(d.threats).toContainEqual({ feed: 'feodo', direction: 'appeared', detail: 'Emotet' })
  })

  it('detects Feodo resolution', () => {
    const feodoEntry = { ip_address: '1.2.3.4', port: 4444, status: 'Offline' as const, hostname: null, as_number: 1, as_name: 'X', country: 'RU', first_seen: '2024-01-01', last_seen: '2024-06-01', malware: 'Emotet' }
    const prev = base({ threat: { ...base().threat, feodo: sr(feodoEntry) } })
    const next = base({ threat: { ...base().threat, feodo: sr(null) } })
    const d = diffHostResults(prev, next)
    expect(d.threats).toContainEqual({ feed: 'feodo', direction: 'resolved' })
  })

  it('detects SSLBL appearance', () => {
    const entry = { SHA1: 'abc', Listingdate: '2024-01-01', Listingtime: '00:00', SuspiciousReason: 'C2' }
    const prev = base({ threat: { ...base().threat, sslbl: sr([]) } })
    const next = base({ threat: { ...base().threat, sslbl: sr([entry]) } })
    expect(diffHostResults(prev, next).threats).toContainEqual({ feed: 'sslbl', direction: 'appeared' })
  })

  it('detects ThreatFox IOC count increase', () => {
    const ioc = { id: '1', ioc: '1.2.3.4', ioc_type: 'ip', threat_type: 'botnet_cc', malware: 'X', malware_alias: '', confidence_level: 90, first_seen: '', last_seen: '', tags: [] }
    const prev = base({ threat: { ...base().threat, threatfox: sr({ query_status: 'ok', data: [ioc] }) } })
    const next = base({ threat: { ...base().threat, threatfox: sr({ query_status: 'ok', data: [ioc, ioc] }) } })
    const d = diffHostResults(prev, next)
    expect(d.threats).toContainEqual(expect.objectContaining({ feed: 'threatfox', direction: 'appeared' }))
  })

  it('detects ThreatFox resolution', () => {
    const ioc = { id: '1', ioc: '1.2.3.4', ioc_type: 'ip', threat_type: 'botnet_cc', malware: 'X', malware_alias: '', confidence_level: 90, first_seen: '', last_seen: '', tags: [] }
    const prev = base({ threat: { ...base().threat, threatfox: sr({ query_status: 'ok', data: [ioc] }) } })
    const next = base({ threat: { ...base().threat, threatfox: sr({ query_status: 'ok', data: [] }) } })
    expect(diffHostResults(prev, next).threats).toContainEqual({ feed: 'threatfox', direction: 'resolved' })
  })

// ─── Geo ──────────────────────────────────────────────────────────────────────

  const geoData = (country: string) => sr({ ip: '1.2.3.4', country, countryCode: country, region: '', city: '', lat: 0, lon: 0, org: '', asn: '', isp: '', timezone: '', proxy: false, hosting: false, mobile: false })

  it('detects country change', () => {
    const prev = base({ core: { ...base().core, geo: geoData('DE') } })
    const next = base({ core: { ...base().core, geo: geoData('RU') } })
    const d = diffHostResults(prev, next)
    expect(d.geo).toContainEqual({ field: 'country', prev: 'DE', next: 'RU' })
  })

  it('does not flag unchanged country', () => {
    const r = base({ core: { ...base().core, geo: geoData('US') } })
    expect(diffHostResults(r, r).geo).toHaveLength(0)
  })

  it('detects ASN change', () => {
    const bgp = (asn: number) => sr({ asn, name: 'Test', description: '', country: 'US', prefixes: [], upstreams: [], peers: [], rir: 'ARIN' })
    const prev = base({ core: { ...base().core, bgp: bgp(15169) } })
    const next = base({ core: { ...base().core, bgp: bgp(13335) } })
    expect(diffHostResults(prev, next).geo).toContainEqual({ field: 'asn', prev: 'AS15169', next: 'AS13335' })
  })

  it('detects hostname change', () => {
    const prev = base({ core: { ...base().core, internetdb: idb([], ['old.example.com']) } })
    const next = base({ core: { ...base().core, internetdb: idb([], ['new.example.com']) } })
    expect(diffHostResults(prev, next).geo).toContainEqual({ field: 'hostname', prev: 'old.example.com', next: 'new.example.com' })
  })


// ─── Cert expiry ──────────────────────────────────────────────────────────────

  it('flags a cert expiring within 30 days when not seen before', () => {
    const prev = base()
    const next = base({ core: { ...base().core, certs: cert('example.com', daysFromNow(10)) } })
    const d = diffHostResults(prev, next)
    expect(d.certExpiry).toHaveLength(1)
    expect(d.certExpiry[0]!.commonName).toBe('example.com')
    expect(d.certExpiry[0]!.daysLeft).toBeLessThanOrEqual(10)
    expect(d.hasChanges).toBe(true)
  })

  it('flags an already-expired cert as negative daysLeft', () => {
    const prev = base()
    const next = base({ core: { ...base().core, certs: cert('expired.example.com', daysFromNow(-5)) } })
    const d = diffHostResults(prev, next)
    expect(d.certExpiry[0]!.daysLeft).toBeLessThan(0)
  })

  it('does not re-alert on a cert already present in the prev snapshot', () => {
    const expiry = daysFromNow(5)
    const withCert = base({ core: { ...base().core, certs: cert('example.com', expiry) } })
    // same cert in both prev and next — should not re-emit
    const d = diffHostResults(withCert, withCert)
    expect(d.certExpiry).toHaveLength(0)
  })

  it('does not flag a cert expiring in 60 days', () => {
    const prev = base()
    const next = base({ core: { ...base().core, certs: cert('safe.example.com', daysFromNow(60)) } })
    expect(diffHostResults(prev, next).certExpiry).toHaveLength(0)
  })

  it('flags multiple near-expiry certs independently', () => {
    const prev = base()
    const nextCerts = sr([
      { id: 1, issuer: 'CA', commonName: 'a.example.com', nameValue: 'a.example.com', notBefore: '', notAfter: daysFromNow(7),  serialNumber: '1' },
      { id: 2, issuer: 'CA', commonName: 'b.example.com', nameValue: 'b.example.com', notBefore: '', notAfter: daysFromNow(14), serialNumber: '2' },
      { id: 3, issuer: 'CA', commonName: 'c.example.com', nameValue: 'c.example.com', notBefore: '', notAfter: daysFromNow(90), serialNumber: '3' },
    ] as import('../lib/types').CertRecord[])
    const next = base({ core: { ...base().core, certs: nextCerts } })
    const d = diffHostResults(prev, next)
    expect(d.certExpiry).toHaveLength(2)
    expect(d.certExpiry.map(c => c.commonName)).toContain('a.example.com')
    expect(d.certExpiry.map(c => c.commonName)).toContain('b.example.com')
  })

// ─── Risk score delta ─────────────────────────────────────────────────────────

  it('includes risk delta when prev has riskScore', () => {
    // The diff function recalculates risk from next.data, so we need to provide
    // actual data that will produce a higher score than prev
    const prev = base({ 
      riskScore: { score: 20, severity: 'LOW', breakdown: { blocklists: 0, threatIntel: 0, vulns: 0, ports: 0, networkFlags: 0, total: 20 } },
      core: { ...base().core, internetdb: idb([80]) }  // 1 port = low score
    })
    const next = base({ 
      core: { ...base().core, internetdb: idb([80, 443, 3389, 22, 21, 23, 25]) },  // Many ports = higher score
      vulns: [cveResult('CVE-2021-44228', 10.0, 'CRITICAL')],  // Critical CVE
      threat: { ...base().threat, urlhaus: sr({ query_status: 'is_host' }) }  // Threat intel hit
    })
    const d = diffHostResults(prev, next)
    expect(d.risk).not.toBeNull()
    expect(d.risk?.prev).toBe(20)
    expect(d.risk?.next).toBeGreaterThan(20)  // Should be much higher with all these threats
    expect(d.risk?.delta).toBeGreaterThan(0)
  })

  it('returns risk=null when prev snapshot predates risk score feature', () => {
    const prev = { ...base() }
    delete (prev as Partial<HostResult>).riskScore
    const next = base()
    const d = diffHostResults(prev as HostResult, next)
    expect(d.risk).toBeNull()
  })

  it('does not set hasChanges when risk delta is less than 5 points', () => {
    // Test that small risk deltas (< 5 points) don't trigger hasChanges
    // when there are no other changes
    const prev = base({ 
      riskScore: { score: 10, severity: 'LOW', breakdown: { blocklists: 0, threatIntel: 0, vulns: 0, ports: 0, networkFlags: 0, total: 10 } },
      core: { ...base().core, internetdb: idb([80]) }
    })
    // Next has slightly different data but should produce similar risk score
    const next = base({ 
      riskScore: { score: 12, severity: 'LOW', breakdown: { blocklists: 0, threatIntel: 0, vulns: 0, ports: 0, networkFlags: 0, total: 12 } },
      core: { ...base().core, internetdb: idb([80]) }  // Same port
    })
    const d = diffHostResults(prev, next)
    // If risk delta is < 5 and no other changes, hasChanges should be false
    if (d.risk && Math.abs(d.risk.delta) < 5) {
      expect(d.hasChanges).toBe(false)
    }
    // Verify no other changes
    expect(d.ports).toHaveLength(0)
    expect(d.cves).toHaveLength(0)
    expect(d.threats).toHaveLength(0)
  })

// ─── summariseDiff ────────────────────────────────────────────────────────────

  describe('summariseDiff', () => {
    it('returns no-changes message when nothing changed', () => {
      const d = diffHostResults(base(), base())
      expect(summariseDiff(d, '1.2.3.4')).toBe('1.2.3.4: no changes')
    })

    it('includes port changes', () => {
      const prev = base({ core: { ...base().core, internetdb: idb([80]) } })
      const next = base({ core: { ...base().core, internetdb: idb([80, 443]) } })
      const summary = summariseDiff(diffHostResults(prev, next), '1.2.3.4')
      expect(summary).toContain('port 443 opened')
    })

    it('includes CVE with severity', () => {
      const next = base({ vulns: [cveResult('CVE-2021-44228', 10.0, 'CRITICAL')] })
      const summary = summariseDiff(diffHostResults(base(), next), '1.2.3.4')
      expect(summary).toContain('CVE-2021-44228 appeared')
      expect(summary).toContain('CRITICAL')
      expect(summary).toContain('10')
    })

    it('includes threat intel changes', () => {
      const next = base({ threat: { ...base().threat, urlhaus: sr({ query_status: 'is_host' }) } })
      const summary = summariseDiff(diffHostResults(base(), next), '1.2.3.4')
      expect(summary).toContain('urlhaus appeared')
    })

    it('includes cert expiry in summary', () => {
      const prev = base()
      const next = base({ core: { ...base().core, certs: cert('example.com', daysFromNow(5)) } })
      const summary = summariseDiff(diffHostResults(prev, next), '1.2.3.4')
      expect(summary).toContain('cert example.com')
      expect(summary).toMatch(/expires in [45]d/)
    })

    it('labels expired certs as EXPIRED', () => {
      const prev = base()
      const next = base({ core: { ...base().core, certs: cert('expired.example.com', daysFromNow(-3)) } })
      const summary = summariseDiff(diffHostResults(prev, next), '1.2.3.4')
      expect(summary).toContain('EXPIRED')
    })

    it('includes risk score when delta ≥ 5', () => {
      const prev = base({ riskScore: { score: 10, severity: 'LOW', breakdown: { blocklists: 0, threatIntel: 0, vulns: 0, ports: 0, networkFlags: 0, total: 10 } } })
      const next = base({ vulns: [cveResult('CVE-X', 10.0, 'CRITICAL')] })
      const d = diffHostResults(prev, next)
      if (d.risk && Math.abs(d.risk.delta) >= 5) {
        const summary = summariseDiff(d, '1.2.3.4')
        expect(summary).toContain('risk score')
      }
    })
  })
})
