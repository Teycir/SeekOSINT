/**
 * test/risk.test.ts — unit tests for computeRiskScore
 */
import { describe, it, expect } from 'vitest'
import { computeRiskScore } from '../lib/risk'
import type { HostResult, SourceResult } from '../lib/types'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sr<T>(data: T): SourceResult<T> {
  return { source: 'test', status: 'ok', data }
}
function skipped<T>(): SourceResult<T> {
  return { source: 'test', status: 'skipped', data: null }
}
function errored<T>(): SourceResult<T> {
  return { source: 'test', status: 'error', data: null }
}

function baseResult(overrides: Partial<HostResult> = {}): HostResult {
  return {
    query: { raw: '1.2.3.4', type: 'ip', normalised: '1.2.3.4' },
    core: {
      internetdb:  skipped(),
      geo:         skipped(),
      bgp:         skipped(),
      rdap:        skipped(),
      certs:       skipped(),
      passivedns:  skipped(),
      robtex:      skipped(),
    },
    threat: {
      urlhaus:       skipped(),
      threatfox:     skipped(),
      malwarebazaar: skipped(),
      feodo:         skipped(),
      sslbl:         skipped(),
    },
    normalizedThreats: [],
    vulns: [],
    recon: {
      buckets: skipped(),
      wayback: skipped(),
    },
    meta: {
      durationMs: 100,
      timestamp: Date.now(),
      cacheHits: 0,
      sourcesQueried: 0,
      sourcesFailed: 0,
      circuitBreakers: [],
    },
    ...overrides,
  }
}

// ─── Baseline ─────────────────────────────────────────────────────────────────

describe('computeRiskScore', () => {
  it('returns 0 / LOW for a completely clean host', () => {
    const r = computeRiskScore(baseResult())
    expect(r.score).toBe(0)
    expect(r.severity).toBe('LOW')
    expect(r.breakdown.blocklists).toBe(0)
    expect(r.breakdown.threatIntel).toBe(0)
    expect(r.breakdown.vulns).toBe(0)
    expect(r.breakdown.ports).toBe(0)
    expect(r.breakdown.networkFlags).toBe(0)
  })

  it('ignores errored sources — does not throw', () => {
    const r = computeRiskScore(baseResult({
      threat: {
        urlhaus:       errored(),
        threatfox:     errored(),
        malwarebazaar: errored(),
        feodo:         errored(),
        sslbl:         errored(),
      },
    }))
    expect(r.score).toBe(0)
  })

// ─── Blocklists ───────────────────────────────────────────────────────────────

  it('adds 35 for Feodo Online', () => {
    const r = computeRiskScore(baseResult({
      threat: {
        ...baseResult().threat,
        feodo: sr({
          ip_address: '1.2.3.4', port: 4444, status: 'Online',
          hostname: null, as_number: 1, as_name: 'X', country: 'RU',
          first_seen: '2024-01-01', last_seen: '2024-06-01', malware: 'Emotet',
        }),
      },
    }))
    expect(r.breakdown.blocklists).toBe(35)
    expect(r.severity).toBe('MEDIUM')
  })

  it('adds 20 for Feodo Offline', () => {
    const r = computeRiskScore(baseResult({
      threat: {
        ...baseResult().threat,
        feodo: sr({
          ip_address: '1.2.3.4', port: 4444, status: 'Offline',
          hostname: null, as_number: 1, as_name: 'X', country: 'RU',
          first_seen: '2024-01-01', last_seen: '2024-06-01', malware: 'Emotet',
        }),
      },
    }))
    expect(r.breakdown.blocklists).toBe(20)
  })

  it('adds 0 when feodo data is null (IP not on blocklist)', () => {
    const r = computeRiskScore(baseResult({
      threat: { ...baseResult().threat, feodo: sr(null) },
    }))
    expect(r.breakdown.blocklists).toBe(0)
  })

  it('adds 25 for SSLBL hit', () => {
    const r = computeRiskScore(baseResult({
      threat: {
        ...baseResult().threat,
        sslbl: sr([{ SHA1: 'abc', Listingdate: '2024-01-01', Listingtime: '00:00', SuspiciousReason: 'C2' }]),
      },
    }))
    expect(r.breakdown.blocklists).toBe(25)
  })

  it('caps blocklists at 35 even with both Feodo Online + SSLBL', () => {
    const r = computeRiskScore(baseResult({
      threat: {
        ...baseResult().threat,
        feodo: sr({ ip_address: '1.2.3.4', port: 4444, status: 'Online', hostname: null, as_number: 1, as_name: 'X', country: 'RU', first_seen: '2024-01-01', last_seen: '2024-06-01', malware: 'Emotet' }),
        sslbl: sr([{ SHA1: 'abc', Listingdate: '2024-01-01', Listingtime: '00:00', SuspiciousReason: 'C2' }]),
      },
    }))
    expect(r.breakdown.blocklists).toBe(35)
  })

// ─── Threat intel ─────────────────────────────────────────────────────────────

  it('adds 15 for URLhaus is_host', () => {
    const r = computeRiskScore(baseResult({
      threat: {
        ...baseResult().threat,
        urlhaus: sr({ query_status: 'is_host', urls_count: 3 }),
      },
    }))
    expect(r.breakdown.threatIntel).toBe(15)
  })

  it('does not add for URLhaus no_results', () => {
    const r = computeRiskScore(baseResult({
      threat: {
        ...baseResult().threat,
        urlhaus: sr({ query_status: 'no_results' }),
      },
    }))
    expect(r.breakdown.threatIntel).toBe(0)
  })

  it('adds 10 per ThreatFox IOC up to 20', () => {
    const ioc = { id: '1', ioc: '1.2.3.4', ioc_type: 'ip', threat_type: 'botnet_cc', malware: 'X', malware_alias: '', confidence_level: 90, first_seen: '', last_seen: '', tags: [] }
    const r1 = computeRiskScore(baseResult({ threat: { ...baseResult().threat, threatfox: sr({ query_status: 'ok', data: [ioc] }) } }))
    const r3 = computeRiskScore(baseResult({ threat: { ...baseResult().threat, threatfox: sr({ query_status: 'ok', data: [ioc, ioc, ioc] }) } }))
    expect(r1.breakdown.threatIntel).toBe(10)
    expect(r3.breakdown.threatIntel).toBe(20) // capped at 20
  })

  it('adds 10 for MalwareBazaar ok', () => {
    const r = computeRiskScore(baseResult({
      threat: {
        ...baseResult().threat,
        malwarebazaar: sr({ query_status: 'ok', data: [] }),
      },
    }))
    expect(r.breakdown.threatIntel).toBe(10)
  })

  it('caps threatIntel at 30', () => {
    const ioc = { id: '1', ioc: '1.2.3.4', ioc_type: 'ip', threat_type: 'botnet_cc', malware: 'X', malware_alias: '', confidence_level: 90, first_seen: '', last_seen: '', tags: [] }
    const r = computeRiskScore(baseResult({
      threat: {
        ...baseResult().threat,
        urlhaus:       sr({ query_status: 'is_host' }),
        threatfox:     sr({ query_status: 'ok', data: [ioc, ioc, ioc] }),
        malwarebazaar: sr({ query_status: 'ok', data: [] }),
      },
    }))
    expect(r.breakdown.threatIntel).toBe(30) // 15+20+10 = 45 → capped at 30
  })

// ─── Vulnerabilities ─────────────────────────────────────────────────────────

  it('scores critical CVE (CVSS 9.8) as 15', () => {
    const r = computeRiskScore(baseResult({
      vulns: [sr({ id: 'CVE-2021-44228', description: '', cvssV3Score: 9.8, source: 'nvd' })],
    }))
    expect(r.breakdown.vulns).toBe(15)
  })

  it('scores high CVE (CVSS 8.0) as 8', () => {
    const r = computeRiskScore(baseResult({
      vulns: [sr({ id: 'CVE-2022-0001', description: '', cvssV3Score: 8.0, source: 'nvd' })],
    }))
    expect(r.breakdown.vulns).toBe(8)
  })

  it('scores medium CVE (CVSS 5.0) as 4', () => {
    const r = computeRiskScore(baseResult({
      vulns: [sr({ id: 'CVE-2022-0002', description: '', cvssV3Score: 5.0, source: 'nvd' })],
    }))
    expect(r.breakdown.vulns).toBe(4)
  })

  it('scores low CVE (CVSS 2.0) as 1', () => {
    const r = computeRiskScore(baseResult({
      vulns: [sr({ id: 'CVE-2022-0003', description: '', cvssV3Score: 2.0, source: 'nvd' })],
    }))
    expect(r.breakdown.vulns).toBe(1)
  })

  it('scores CVE with no CVSS as 2', () => {
    const r = computeRiskScore(baseResult({
      vulns: [sr({ id: 'CVE-2022-0004', description: '', source: 'circl' })],
    }))
    expect(r.breakdown.vulns).toBe(2)
  })

  it('caps vulns at 25', () => {
    const critical = sr({ id: 'CVE-X', description: '', cvssV3Score: 10.0, source: 'nvd' })
    // 3 critical CVEs = 3×15 = 45 → should cap at 25
    const r = computeRiskScore(baseResult({ vulns: [critical, critical, critical] }))
    expect(r.breakdown.vulns).toBe(25)
  })

// ─── Ports ────────────────────────────────────────────────────────────────────

  it('adds 4 per high-risk port', () => {
    const r = computeRiskScore(baseResult({
      core: {
        ...baseResult().core,
        internetdb: sr({ ip: '1.2.3.4', ports: [22, 445], hostnames: [], tags: [], vulns: [], cpes: [] }),
      },
    }))
    expect(r.breakdown.ports).toBe(8) // 2 × 4
  })

  it('adds 1 per low-risk port', () => {
    const r = computeRiskScore(baseResult({
      core: {
        ...baseResult().core,
        internetdb: sr({ ip: '1.2.3.4', ports: [80, 443], hostnames: [], tags: [], vulns: [], cpes: [] }),
      },
    }))
    expect(r.breakdown.ports).toBe(2)
  })

  it('caps high-risk ports at 12', () => {
    const r = computeRiskScore(baseResult({
      core: {
        ...baseResult().core,
        internetdb: sr({ ip: '1.2.3.4', ports: [22, 445, 3389, 5900, 27017], hostnames: [], tags: [], vulns: [], cpes: [] }),
      },
    }))
    expect(r.breakdown.ports).toBe(12) // 5×4=20 → capped at 12
  })

  it('caps low-risk ports at 5', () => {
    const r = computeRiskScore(baseResult({
      core: {
        ...baseResult().core,
        internetdb: sr({ ip: '1.2.3.4', ports: [80, 443, 8000, 8008, 9090, 9091], hostnames: [], tags: [], vulns: [], cpes: [] }),
      },
    }))
    expect(r.breakdown.ports).toBe(5)
  })

// ─── Network flags ────────────────────────────────────────────────────────────

  it('adds 5 for proxy flag', () => {
    const r = computeRiskScore(baseResult({
      core: {
        ...baseResult().core,
        geo: sr({ ip: '1.2.3.4', country: 'US', countryCode: 'US', region: '', city: '', lat: 0, lon: 0, org: '', asn: '', isp: '', timezone: '', proxy: true, hosting: false, mobile: false }),
      },
    }))
    expect(r.breakdown.networkFlags).toBe(5)
  })

  it('adds 3 for hosting flag', () => {
    const r = computeRiskScore(baseResult({
      core: {
        ...baseResult().core,
        geo: sr({ ip: '1.2.3.4', country: 'US', countryCode: 'US', region: '', city: '', lat: 0, lon: 0, org: '', asn: '', isp: '', timezone: '', proxy: false, hosting: true, mobile: false }),
      },
    }))
    expect(r.breakdown.networkFlags).toBe(3)
  })

  it('adds 5 for Shodan honeypot tag', () => {
    const r = computeRiskScore(baseResult({
      core: {
        ...baseResult().core,
        internetdb: sr({ ip: '1.2.3.4', ports: [], hostnames: [], tags: ['honeypot'], vulns: [], cpes: [] }),
      },
    }))
    expect(r.breakdown.networkFlags).toBe(5)
  })

  it('adds 3 for Shodan scanner tag', () => {
    const r = computeRiskScore(baseResult({
      core: {
        ...baseResult().core,
        internetdb: sr({ ip: '1.2.3.4', ports: [], hostnames: [], tags: ['scanner'], vulns: [], cpes: [] }),
      },
    }))
    expect(r.breakdown.networkFlags).toBe(3)
  })

// ─── Severity bands ──────────────────────────────────────────────────────────

  it('scores < 25 as LOW', () => {
    const r = computeRiskScore(baseResult({
      core: { ...baseResult().core, internetdb: sr({ ip: '1.2.3.4', ports: [80], hostnames: [], tags: [], vulns: [], cpes: [] }) },
    }))
    expect(r.severity).toBe('LOW')
  })

  it('scores 25–49 as MEDIUM', () => {
    // URLhaus (15) + ThreatFox 1 IOC (10) = 25
    const ioc = { id: '1', ioc: '1.2.3.4', ioc_type: 'ip', threat_type: 'botnet_cc', malware: 'X', malware_alias: '', confidence_level: 90, first_seen: '', last_seen: '', tags: [] }
    const r = computeRiskScore(baseResult({
      threat: {
        ...baseResult().threat,
        urlhaus:   sr({ query_status: 'is_host' }),
        threatfox: sr({ query_status: 'ok', data: [ioc] }),
      },
    }))
    expect(r.score).toBe(25)
    expect(r.severity).toBe('MEDIUM')
  })

  it('scores 50–74 as HIGH', () => {
    const ioc = { id: '1', ioc: '1.2.3.4', ioc_type: 'ip', threat_type: 'botnet_cc', malware: 'X', malware_alias: '', confidence_level: 90, first_seen: '', last_seen: '', tags: [] }
    const critical = sr({ id: 'CVE-X', description: '', cvssV3Score: 10.0, source: 'nvd' as const })
    const r = computeRiskScore(baseResult({
      threat: {
        ...baseResult().threat,
        urlhaus:   sr({ query_status: 'is_host' }),
        threatfox: sr({ query_status: 'ok', data: [ioc, ioc] }),
      },
      vulns: [critical, critical],
    }))
    // blocklists=0, threat=30, vulns=25, ports=0, flags=0 → 55
    expect(r.score).toBe(55)
    expect(r.severity).toBe('HIGH')
  })

  it('scores ≥ 75 as CRITICAL', () => {
    const ioc = { id: '1', ioc: '1.2.3.4', ioc_type: 'ip', threat_type: 'botnet_cc', malware: 'X', malware_alias: '', confidence_level: 90, first_seen: '', last_seen: '', tags: [] }
    const critical = sr({ id: 'CVE-X', description: '', cvssV3Score: 10.0, source: 'nvd' as const })
    const r = computeRiskScore(baseResult({
      threat: {
        ...baseResult().threat,
        feodo:     sr({ ip_address: '1.2.3.4', port: 4444, status: 'Online' as const, hostname: null, as_number: 1, as_name: 'X', country: 'RU', first_seen: '2024-01-01', last_seen: '2024-06-01', malware: 'Emotet' }),
        urlhaus:   sr({ query_status: 'is_host' }),
        threatfox: sr({ query_status: 'ok', data: [ioc, ioc] }),
      },
      vulns: [critical, critical],
      core: {
        ...baseResult().core,
        internetdb: sr({ ip: '1.2.3.4', ports: [22, 445, 3389], hostnames: [], tags: [], vulns: [], cpes: [] }),
      },
    }))
    // blocklists=35, threat=30, vulns=25, ports=12, flags=0 → 100 (capped)
    expect(r.score).toBe(100)
    expect(r.severity).toBe('CRITICAL')
  })

// ─── Total cap ────────────────────────────────────────────────────────────────

  it('never exceeds 100', () => {
    const feodoEntry = { ip_address: '1.2.3.4', port: 4444, status: 'Online' as const, hostname: null, as_number: 1, as_name: 'X', country: 'RU', first_seen: '2024-01-01', last_seen: '2024-06-01', malware: 'Emotet' }
    const ioc = { id: '1', ioc: '1.2.3.4', ioc_type: 'ip', threat_type: 'botnet_cc', malware: 'X', malware_alias: '', confidence_level: 90, first_seen: '', last_seen: '', tags: [] }
    const critical = sr({ id: 'CVE-X', description: '', cvssV3Score: 10.0, source: 'nvd' as const })
    const geo = sr({ ip: '1.2.3.4', country: 'RU', countryCode: 'RU', region: '', city: '', lat: 0, lon: 0, org: '', asn: '', isp: '', timezone: '', proxy: true, hosting: true, mobile: false })
    const r = computeRiskScore(baseResult({
      threat: {
        feodo:         sr(feodoEntry),
        sslbl:         sr([{ SHA1: 'abc', Listingdate: '', Listingtime: '', SuspiciousReason: 'C2' }]),
        urlhaus:       sr({ query_status: 'is_host' }),
        threatfox:     sr({ query_status: 'ok', data: [ioc, ioc, ioc] }),
        malwarebazaar: sr({ query_status: 'ok', data: [] }),
      },
      vulns:  [critical, critical, critical, critical],
      core: {
        ...baseResult().core,
        geo,
        internetdb: sr({ ip: '1.2.3.4', ports: [22, 23, 445, 3389, 5900, 9200, 27017, 6379], hostnames: [], tags: ['honeypot', 'scanner'], vulns: [], cpes: [] }),
      },
    }))
    expect(r.score).toBeLessThanOrEqual(100)
    expect(r.score).toBeGreaterThanOrEqual(75)
  })

// ─── RDAP domain registration signals ────────────────────────────────────────

  it('adds 15 for a newly registered domain (< 30 days)', () => {
    const yesterday = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString()
    const r = computeRiskScore(baseResult({
      query: { raw: 'evil.com', type: 'domain', normalised: 'evil.com' },
      core: {
        ...baseResult().core,
        rdap: sr({ domain: 'evil.com', created: yesterday, nameservers: ['ns1.evil.com'], contacts: [] }),
      },
    }))
    expect(r.breakdown.domainRegistration).toBe(15)
  })

  it('does not penalise an old domain for age', () => {
    const twoYearsAgo = new Date(Date.now() - 2 * 365 * 24 * 60 * 60 * 1000).toISOString()
    const r = computeRiskScore(baseResult({
      query: { raw: 'legit.com', type: 'domain', normalised: 'legit.com' },
      core: {
        ...baseResult().core,
        rdap: sr({ domain: 'legit.com', created: twoYearsAgo, nameservers: ['ns1.legit.com'], contacts: [] }),
      },
    }))
    expect(r.breakdown.domainRegistration).toBe(0)
  })

  it('adds 10 for an expired domain', () => {
    const expired = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString()
    const registered = new Date(Date.now() - 2 * 365 * 24 * 60 * 60 * 1000).toISOString()
    const r = computeRiskScore(baseResult({
      query: { raw: 'parked.com', type: 'domain', normalised: 'parked.com' },
      core: {
        ...baseResult().core,
        rdap: sr({ domain: 'parked.com', created: registered, expires: expired, nameservers: ['ns1.park.com'], contacts: [] }),
      },
    }))
    expect(r.breakdown.domainRegistration).toBe(10)
  })

  it('adds 5 for a privacy-protected registrant org', () => {
    const registered = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString()
    const r = computeRiskScore(baseResult({
      query: { raw: 'hidden.com', type: 'domain', normalised: 'hidden.com' },
      core: {
        ...baseResult().core,
        rdap: sr({
          domain: 'hidden.com',
          created: registered,
          nameservers: ['ns1.hidden.com'],
          contacts: [{ role: 'registrant', org: 'Domains By Proxy Privacy Protection' }],
        }),
      },
    }))
    expect(r.breakdown.domainRegistration).toBe(5)
  })

  it('adds 8 for missing nameservers', () => {
    const registered = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString()
    const r = computeRiskScore(baseResult({
      query: { raw: 'nodns.com', type: 'domain', normalised: 'nodns.com' },
      core: {
        ...baseResult().core,
        rdap: sr({ domain: 'nodns.com', created: registered, nameservers: [], contacts: [] }),
      },
    }))
    expect(r.breakdown.domainRegistration).toBe(8)
  })

  it('caps domainRegistration at 15', () => {
    // Brand-new + expired + privacy + no-NS = 15+10+5+8 = 38 → capped at 15
    const yesterday = new Date(Date.now() - 1000).toISOString() // just now = created AND expires yesterday
    const r = computeRiskScore(baseResult({
      query: { raw: 'maxed.com', type: 'domain', normalised: 'maxed.com' },
      core: {
        ...baseResult().core,
        rdap: sr({
          domain: 'maxed.com',
          created:  yesterday,
          expires:  yesterday,
          nameservers: [],
          contacts: [{ role: 'registrant', org: 'Redacted for Privacy' }],
        }),
      },
    }))
    expect(r.breakdown.domainRegistration).toBe(15)
  })

  it('does not add RDAP domain signals for IP result with ip-only RDAPResult', () => {
    // RDAPResult with only ip/cidr fields (no .domain) should not trigger any domain scoring
    const r = computeRiskScore(baseResult({
      core: {
        ...baseResult().core,
        rdap: sr({ ip: '1.2.3.4', cidr: '1.2.3.0/24', networkName: 'ACME', contacts: [] }),
      },
    }))
    expect(r.breakdown.domainRegistration).toBe(0)
  })

// ─── Feodo/SSLBL type guard — domain→IP resolved query ───────────────────────
// Regression: ensures that effectiveIPQuery (type:'ip') constructed post-DNS
// resolution correctly passes the type guard inside fetchFeodo/fetchSSLBL.
// This test validates the risk scorer's behaviour when those sources return
// data via the resolved-IP path (simulating a domain lookup).

  it('scores Feodo hit arriving via a domain query (resolvedIP path)', () => {
    // Simulate: user typed "malicious.example.com", DNS resolved to 5.6.7.8,
    // Feodo returned a hit for 5.6.7.8. The HostResult.query is still domain.
    const r = computeRiskScore(baseResult({
      query: { raw: 'malicious.example.com', type: 'domain', normalised: 'malicious.example.com' },
      resolvedIP: '5.6.7.8',
      threat: {
        ...baseResult().threat,
        feodo: sr({
          ip_address: '5.6.7.8', port: 80, status: 'Online' as const,
          hostname: null, as_number: 0, as_name: '', country: 'XX',
          first_seen: '2025-01-01', last_seen: '2025-05-01', malware: 'QakBot',
        }),
      },
    }))
    // Must detect the Feodo hit and score it — type guard must not skip it
    expect(r.breakdown.blocklists).toBe(35)
    expect(r.severity).not.toBe('LOW')
  })

  it('scores SSLBL hit arriving via a domain query (resolvedIP path)', () => {
    const r = computeRiskScore(baseResult({
      query: { raw: 'c2-server.example.com', type: 'domain', normalised: 'c2-server.example.com' },
      resolvedIP: '9.10.11.12',
      threat: {
        ...baseResult().threat,
        sslbl: sr([{
          SHA1: 'deadbeef', Listingdate: '2025-01-01', Listingtime: '00:00',
          SuspiciousReason: 'Dridex botnet', DstIP: '9.10.11.12', DstPort: 443,
        }]),
      },
    }))
    expect(r.breakdown.blocklists).toBe(25)
  })
})
