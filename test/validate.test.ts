/**
 * test/validate.test.ts — parseQuery + collectSecrets
 */
import { describe, it, expect } from 'vitest'
import { parseQuery, collectSecrets } from '../lib/validate'

describe('parseQuery', () => {
  // ── IPv4 ────────────────────────────────────────────────────────────────
  it('parses a plain IPv4 address', () => {
    const q = parseQuery('1.2.3.4')
    expect(q).not.toBeNull()
    expect(q?.type).toBe('ip')
    expect(q?.normalised).toBe('1.2.3.4')
  })

  it('strips https:// prefix before matching', () => {
    const q = parseQuery('https://1.2.3.4')
    expect(q?.type).toBe('ip')
    expect(q?.normalised).toBe('1.2.3.4')
  })

  it('strips trailing path from URL-style input', () => {
    const q = parseQuery('https://example.com/some/path?q=1')
    expect(q?.type).toBe('domain')
    expect(q?.normalised).toBe('example.com')
  })

  it('preserves the raw string verbatim', () => {
    const raw = '  8.8.8.8  '
    const q = parseQuery(raw)
    expect(q?.raw).toBe(raw)
  })

  it('rejects an octets-out-of-range IPv4', () => {
    expect(parseQuery('999.1.1.1')).toBeNull()
    expect(parseQuery('1.2.3.256')).toBeNull()
  })

  it('rejects a partial IPv4-looking string with wrong octet count', () => {
    expect(parseQuery('1.2.3')).toBeNull()
  })

  it('rejects IPv4 with leading zeros (ambiguous / RFC 6943)', () => {
    expect(parseQuery('01.2.3.4')).toBeNull()
    expect(parseQuery('01.002.003.004')).toBeNull()
    expect(parseQuery('192.168.001.001')).toBeNull()
  })

  it('accepts single-zero octets (not leading zeros)', () => {
    expect(parseQuery('0.0.0.0')).not.toBeNull()
    expect(parseQuery('10.0.0.0')).not.toBeNull()
    expect(parseQuery('192.168.1.0')).not.toBeNull()
  })

  // ── IPv6 ────────────────────────────────────────────────────────────────
  it('parses a compressed IPv6 address', () => {
    const q = parseQuery('2001:db8::1')
    expect(q?.type).toBe('ip')
    expect(q?.normalised).toBe('2001:db8::1')
  })

  it('parses :: (all-zeros address)', () => {
    const q = parseQuery('::')
    expect(q?.type).toBe('ip')
    expect(q?.normalised).toBe('::')
  })

  it('parses ::1 (loopback)', () => {
    const q = parseQuery('::1')
    expect(q?.type).toBe('ip')
    expect(q?.normalised).toBe('::1')
  })

  it('parses fe80::1 (link-local)', () => {
    const q = parseQuery('fe80::1')
    expect(q?.type).toBe('ip')
    expect(q?.normalised).toBe('fe80::1')
  })

  it('parses 2001:4860:4860::8888 (Google DNS)', () => {
    const q = parseQuery('2001:4860:4860::8888')
    expect(q?.type).toBe('ip')
    expect(q?.normalised).toBe('2001:4860:4860::8888')
  })

  it('parses a full 8-group IPv6 address', () => {
    const q = parseQuery('2001:0db8:0000:0000:0000:0000:0000:0001')
    expect(q?.type).toBe('ip')
  })

  it('rejects IPv6 with zone ID (not supported by OSINT APIs)', () => {
    expect(parseQuery('fe80::1%eth0')).toBeNull()
  })

  it('rejects IPv6 with triple colon', () => {
    expect(parseQuery(':::1')).toBeNull()
  })

  it('rejects IPv6 with two :: separators', () => {
    expect(parseQuery('1::2::3')).toBeNull()
  })

  it('rejects IPv6 with 9 groups and no ::', () => {
    expect(parseQuery('1:2:3:4:5:6:7:8:9')).toBeNull()
  })

  it('rejects IPv6 with invalid hex characters', () => {
    expect(parseQuery('gggg::1')).toBeNull()
  })

  // ── ASN ─────────────────────────────────────────────────────────────────
  it('parses ASN with lowercase prefix', () => {
    const q = parseQuery('as13335')
    expect(q?.type).toBe('asn')
    expect(q?.normalised).toBe('as13335')
  })

  it('parses ASN with uppercase prefix and normalises to lowercase', () => {
    const q = parseQuery('AS15169')
    expect(q?.type).toBe('asn')
    expect(q?.normalised).toBe('as15169')
  })

  // ── Domain ──────────────────────────────────────────────────────────────
  it('parses a simple domain', () => {
    const q = parseQuery('example.com')
    expect(q?.type).toBe('domain')
    expect(q?.normalised).toBe('example.com')
  })

  it('parses a subdomain', () => {
    const q = parseQuery('sub.example.co.uk')
    expect(q?.type).toBe('domain')
    expect(q?.normalised).toBe('sub.example.co.uk')
  })

  it('normalises domain to lowercase', () => {
    const q = parseQuery('EXAMPLE.COM')
    expect(q?.normalised).toBe('example.com')
  })

  it('strips http:// from domain input', () => {
    const q = parseQuery('http://evil.example.org')
    expect(q?.type).toBe('domain')
    expect(q?.normalised).toBe('evil.example.org')
  })

  // ── Rejects ─────────────────────────────────────────────────────────────
  it('returns null for a bare word with no TLD', () => {
    expect(parseQuery('localhost')).toBeNull()
  })

  it('returns null for an empty string', () => {
    expect(parseQuery('')).toBeNull()
  })

  it('returns null for whitespace only', () => {
    expect(parseQuery('   ')).toBeNull()
  })

  it('returns null for a random string', () => {
    expect(parseQuery('not_a_query!!')).toBeNull()
  })
})

describe('collectSecrets', () => {
  it('collects numbered env vars into an array', () => {
    const env = { GHW_KEY_1: 'a', GHW_KEY_2: 'b', GHW_KEY_3: 'c' }
    expect(collectSecrets(env, 'GHW_KEY', 3)).toEqual(['a', 'b', 'c'])
  })

  it('skips missing env vars', () => {
    const env = { GHW_KEY_1: 'a', GHW_KEY_3: 'c' }
    expect(collectSecrets(env, 'GHW_KEY', 3)).toEqual(['a', 'c'])
  })

  it('skips empty-string values', () => {
    const env = { GHW_KEY_1: 'a', GHW_KEY_2: '' }
    expect(collectSecrets(env, 'GHW_KEY', 2)).toEqual(['a'])
  })

  it('returns empty array when env is empty', () => {
    expect(collectSecrets({}, 'GHW_KEY', 5)).toEqual([])
  })

  it('does not exceed the requested count', () => {
    const env = { GHW_KEY_1: 'a', GHW_KEY_2: 'b', GHW_KEY_3: 'c' }
    expect(collectSecrets(env, 'GHW_KEY', 2)).toEqual(['a', 'b'])
  })
})
