/**
 * test/normalize.test.ts — normalizeThreatIndicators()
 *
 * Tests deduplication, merge logic, confidence scoring,
 * provenance aggregation, and sort order.
 */
import { describe, it, expect } from 'vitest'
import { normalizeThreatIndicators } from '../lib/normalize'
import type { ThreatSourceResults } from '../lib/normalize'
import { ok, skipped } from '../lib/results'

// ─── Fixture builders ─────────────────────────────────────────────────────────

function emptySources(): ThreatSourceResults {
  return {
    urlhaus:       skipped('urlhaus'),
    threatfox:     skipped('threatfox'),
    feodo:         skipped('feodo'),
    sslbl:         skipped('sslbl'),
    malwarebazaar: skipped('malwarebazaar'),
  }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('normalizeThreatIndicators()', () => {
  it('returns empty array when all sources are skipped', () => {
    const result = normalizeThreatIndicators(emptySources())
    expect(result).toEqual([])
  })

  it('extracts URLhaus online URLs with confidence 90', () => {
    const sources = emptySources()
    sources.urlhaus = ok('urlhaus', {
      query_status: 'is_host' as const,
      urlhaus_reference: 'https://urlhaus.abuse.ch/host/1.2.3.4/',
      urls_count: 1,
      urls: [{
        id: '1',
        url_status: 'online' as const,
        url: 'http://1.2.3.4/evil.exe',
        threat: 'malware_download',
        tags: ['emotet', 'loader'],
        date_added: '2024-01-15 10:00:00',
      }],
    })

    const result = normalizeThreatIndicators(sources)
    expect(result).toHaveLength(1)
    const ind = result[0]
    expect(ind.ioc).toBe('http://1.2.3.4/evil.exe')
    expect(ind.iocType).toBe('url')
    expect(ind.confidence).toBe(90)
    expect(ind.provenance).toEqual(['urlhaus'])
    expect(ind.threatType).toBe('malware_download')
    expect(ind.tags).toEqual(['emotet', 'loader'])
    expect(ind.references).toHaveProperty('urlhaus')
  })

  it('extracts URLhaus offline URLs with confidence 60', () => {
    const sources = emptySources()
    sources.urlhaus = ok('urlhaus', {
      query_status: 'is_host' as const,
      urls_count: 1,
      urls: [{
        id: '2',
        url_status: 'offline' as const,
        url: 'http://bad.example.com/x',
        threat: 'phishing',
        tags: [],
        date_added: '2024-01-10 00:00:00',
      }],
    })

    const result = normalizeThreatIndicators(sources)
    expect(result[0].confidence).toBe(60)
  })

  it('extracts ThreatFox IOCs using their own confidence_level', () => {
    const sources = emptySources()
    sources.threatfox = ok('threatfox', {
      query_status: 'ok' as const,
      data: [{
        id: 'tf1',
        ioc: '1.2.3.4:4444',
        ioc_type: 'ip:port',
        threat_type: 'botnet_cc',
        malware: 'cobalt_strike',
        malware_alias: 'cobaltstrike',
        confidence_level: 75,
        first_seen: '2024-01-01 00:00:00',
        last_seen: '2024-01-20 00:00:00',
        tags: ['c2', 'rat'],
      }],
    })

    const result = normalizeThreatIndicators(sources)
    expect(result).toHaveLength(1)
    const ind = result[0]
    expect(ind.confidence).toBe(75)
    expect(ind.provenance).toEqual(['threatfox'])
    expect(ind.malwareFamilies).toContain('cobalt_strike')
    expect(ind.malwareFamilies).toContain('cobaltstrike')
    expect(ind.firstSeen).toBe('2024-01-01 00:00:00')
    expect(ind.lastSeen).toBe('2024-01-20 00:00:00')
  })

  it('extracts Feodo Online C2 with confidence 95', () => {
    const sources = emptySources()
    sources.feodo = ok('feodo', {
      ip_address: '5.6.7.8',
      port: 443,
      status: 'Online' as const,
      hostname: null,
      as_number: 12345,
      as_name: 'BadASN',
      country: 'RU',
      first_seen: '2024-01-05',
      last_seen: '2024-01-25',
      malware: 'Emotet',
    })

    const result = normalizeThreatIndicators(sources)
    expect(result).toHaveLength(1)
    const ind = result[0]
    expect(ind.ioc).toBe('5.6.7.8')
    expect(ind.iocType).toBe('ip')
    expect(ind.confidence).toBe(95)
    expect(ind.threatType).toBe('c2')
    expect(ind.malwareFamilies).toContain('emotet')
    expect(ind.provenance).toEqual(['feodo'])
    expect(ind.references.feodo).toContain('5.6.7.8')
  })

  it('extracts Feodo Offline C2 with confidence 70', () => {
    const sources = emptySources()
    sources.feodo = ok('feodo', {
      ip_address: '9.9.9.9',
      port: 80,
      status: 'Offline' as const,
      hostname: null,
      as_number: 1,
      as_name: 'x',
      country: 'CN',
      first_seen: '2023-12-01',
      last_seen: '2024-01-01',
      malware: 'Dridex',
    })

    expect(normalizeThreatIndicators(sources)[0].confidence).toBe(70)
  })

  it('deduplicates same IOC across URLhaus and ThreatFox — merges provenance and takes MAX confidence', () => {
    const sources = emptySources()
    // URLhaus: confidence 90 for this URL
    sources.urlhaus = ok('urlhaus', {
      query_status: 'is_host' as const,
      urlhaus_reference: 'https://urlhaus.abuse.ch/host/evil.com/',
      urls_count: 1,
      urls: [{
        id: 'u1',
        url_status: 'online' as const,
        url: 'http://evil.com/payload',
        threat: 'malware_download',
        tags: ['loader'],
        date_added: '2024-01-10 00:00:00',
      }],
    })
    // ThreatFox: same URL, confidence 60
    sources.threatfox = ok('threatfox', {
      query_status: 'ok' as const,
      data: [{
        id: 'tf2',
        ioc: 'http://evil.com/payload',
        ioc_type: 'url',
        threat_type: 'malware_download',
        malware: 'AgentTesla',
        malware_alias: '',
        confidence_level: 60,
        first_seen: '2024-01-08 00:00:00',
        last_seen: '2024-01-12 00:00:00',
        tags: ['stealer'],
      }],
    })

    const result = normalizeThreatIndicators(sources)
    expect(result).toHaveLength(1)
    const ind = result[0]
    // MAX confidence wins
    expect(ind.confidence).toBe(90)
    // Both feeds in provenance
    expect(ind.provenance).toContain('urlhaus')
    expect(ind.provenance).toContain('threatfox')
    // Tags merged
    expect(ind.tags).toContain('loader')
    expect(ind.tags).toContain('stealer')
    // Widest seen window
    expect(ind.firstSeen).toBe('2024-01-08 00:00:00')
    expect(ind.lastSeen).toBe('2024-01-12 00:00:00')
    // Malware family from threatfox preserved
    expect(ind.malwareFamilies).toContain('agenttesla')
  })

  it('sorts by descending confidence', () => {
    const sources = emptySources()
    sources.threatfox = ok('threatfox', {
      query_status: 'ok' as const,
      data: [
        {
          id: 'a',
          ioc: '1.1.1.1:80',
          ioc_type: 'ip:port',
          threat_type: 'c2',
          malware: 'X',
          malware_alias: '',
          confidence_level: 50,
          first_seen: '2024-01-01',
          last_seen: '2024-01-01',
          tags: [],
        },
        {
          id: 'b',
          ioc: '2.2.2.2:443',
          ioc_type: 'ip:port',
          threat_type: 'c2',
          malware: 'Y',
          malware_alias: '',
          confidence_level: 90,
          first_seen: '2024-01-01',
          last_seen: '2024-01-01',
          tags: [],
        },
        {
          id: 'c',
          ioc: '3.3.3.3:8080',
          ioc_type: 'ip:port',
          threat_type: 'c2',
          malware: 'Z',
          malware_alias: '',
          confidence_level: 70,
          first_seen: '2024-01-01',
          last_seen: '2024-01-01',
          tags: [],
        },
      ],
    })

    const result = normalizeThreatIndicators(sources)
    expect(result.map(r => r.confidence)).toEqual([90, 70, 50])
  })

  it('ignores sources with status error or no_results', () => {
    const sources = emptySources()
    sources.urlhaus = ok('urlhaus', { query_status: 'no_results' as const })
    sources.threatfox = ok('threatfox', { query_status: 'no_results' as const })

    expect(normalizeThreatIndicators(sources)).toEqual([])
  })

  it('handles null feodo data (IP not in blocklist)', () => {
    const sources = emptySources()
    sources.feodo = ok('feodo', null)
    expect(normalizeThreatIndicators(sources)).toEqual([])
  })

  it('deduplicates tags and lowercases them', () => {
    const sources = emptySources()
    sources.threatfox = ok('threatfox', {
      query_status: 'ok' as const,
      data: [{
        id: 'x',
        ioc: 'bad.example.com',
        ioc_type: 'domain',
        threat_type: 'phishing',
        malware: 'Phisher',
        malware_alias: 'PHISHER',
        confidence_level: 80,
        first_seen: '2024-01-01',
        last_seen: '2024-01-01',
        tags: ['Banking', 'banking', 'PHISHING'],
      }],
    })

    const result = normalizeThreatIndicators(sources)
    expect(result[0].tags).toEqual(['banking', 'phishing'])
    // malware alias deduplicated (both normalise to 'phisher')
    expect(result[0].malwareFamilies).toEqual(['phisher'])
  })

  it('guesses iocType correctly', () => {
    const sources = emptySources()
    sources.threatfox = ok('threatfox', {
      query_status: 'ok' as const,
      data: [
        { id:'1', ioc:'https://evil.com/x', ioc_type:'url', threat_type:'c2', malware:'X', malware_alias:'', confidence_level:80, first_seen:'', last_seen:'', tags:[] },
        { id:'2', ioc:'1.2.3.4',            ioc_type:'ip',  threat_type:'c2', malware:'X', malware_alias:'', confidence_level:80, first_seen:'', last_seen:'', tags:[] },
        { id:'3', ioc:'evil.example.com',   ioc_type:'domain', threat_type:'c2', malware:'X', malware_alias:'', confidence_level:80, first_seen:'', last_seen:'', tags:[] },
        { id:'4', ioc:'aabbccdd' + 'aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabb', ioc_type:'sha256', threat_type:'sample', malware:'X', malware_alias:'', confidence_level:80, first_seen:'', last_seen:'', tags:[] },
      ],
    })

    const result = normalizeThreatIndicators(sources)
    const byIoc = Object.fromEntries(result.map(r => [r.ioc, r.iocType]))
    expect(byIoc['https://evil.com/x']).toBe('url')
    expect(byIoc['1.2.3.4']).toBe('ip')
    expect(byIoc['evil.example.com']).toBe('domain')
  })
})
