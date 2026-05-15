/**
 * test/sources/rdap.test.ts
 *
 * Covers: skipped ASN, cache hit, IP normalisation, domain normalisation,
 * bootstrap routing, exactOptionalPropertyTypes compliance (no undefined values
 * on optional keys).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchRDAP } from '../../worker/sources/rdap'
import type { LookupQuery } from '../../lib/types'

function makeMockKV() {
  const store = new Map<string, string>()
  return {
    store,
    get: vi.fn(async (k: string) => store.get(k) ?? null),
    put: vi.fn(async (k: string, v: string) => { store.set(k, v) }),
    delete: vi.fn(), list: vi.fn(), getWithMetadata: vi.fn(),
  } as unknown as KVNamespace
}

const ipQuery: LookupQuery  = { raw: '8.8.8.8', type: 'ip',     normalised: '8.8.8.8' }
const domQuery: LookupQuery = { raw: 'example.com', type: 'domain', normalised: 'example.com' }
const asnQuery: LookupQuery = { raw: 'as15169', type: 'asn',    normalised: 'as15169' }

const ipRDAPPayload = {
  startAddress: '8.8.8.0',
  name: 'GOOGLE',
  country: 'US',
  status: ['active'],
  entities: [],
  cidr0_cidrs: [{ v4prefix: '8.8.8.0', length: 24 }],
}

const domRDAPPayload = {
  ldhName: 'EXAMPLE.COM',
  events: [
    { eventAction: 'registration', eventDate: '1995-08-14' },
    { eventAction: 'expiration',   eventDate: '2025-08-13' },
    { eventAction: 'last changed', eventDate: '2023-08-14' },
  ],
  nameservers: [
    { ldhName: 'A.IANA-SERVERS.NET' },
    { ldhName: 'B.IANA-SERVERS.NET' },
  ],
  status: ['client delete prohibited'],
  entities: [],
}

// Minimal IANA DNS bootstrap stub
const ianaBootstrapDNS = {
  services: [
    [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
    [['org'],        ['https://rdap.publicinterestregistry.org/rdap/']],
  ],
}

// Minimal IANA IP bootstrap stub
const ianaBootstrapIP = {
  services: [
    [['8.0.0.0/8'], ['https://rdap.arin.net/registry/']],
  ],
}

describe('fetchRDAP', () => {
  let kv: KVNamespace

  beforeEach(() => { kv = makeMockKV() })
  afterEach(() => vi.restoreAllMocks())

  it('skips ASN queries', async () => {
    const r = await fetchRDAP(asnQuery, kv)
    expect(r.status).toBe('skipped')
  })

  it('returns cached IP result without hitting the network', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    const cached = { ip: '8.8.8.8', networkName: 'GOOGLE', country: 'US', contacts: [] }
    kvm.store.set('rdap:ip:8.8.8.8', JSON.stringify(cached))
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const r = await fetchRDAP(ipQuery, kv)
    expect(r.status).toBe('cached')
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('normalises IP RDAP response correctly', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      const u = url.toString()
      if (u.includes('iana.org/rdap/ipv4'))  return new Response(JSON.stringify(ianaBootstrapIP), { status: 200 })
      if (u.includes('rdap.arin.net'))        return new Response(JSON.stringify(ipRDAPPayload),    { status: 200 })
      return new Response('{}', { status: 200 })
    })
    const r = await fetchRDAP(ipQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data?.ip).toBe('8.8.8.0')
    expect(r.data?.country).toBe('US')
    expect(r.data?.networkName).toBe('GOOGLE')
    expect(r.data?.cidr).toBe('8.8.8.0/24')
  })

  it('normalises domain RDAP response correctly', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      const u = url.toString()
      if (u.includes('iana.org/rdap/dns'))    return new Response(JSON.stringify(ianaBootstrapDNS), { status: 200 })
      if (u.includes('verisign') || u.includes('rdap'))
                                               return new Response(JSON.stringify(domRDAPPayload), { status: 200 })
      return new Response('{}', { status: 200 })
    })
    const r = await fetchRDAP(domQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data?.domain).toBe('EXAMPLE.COM')
    expect(r.data?.created).toBe('1995-08-14')
    expect(r.data?.expires).toBe('2025-08-13')
    expect(r.data?.updated).toBe('2023-08-14')
    expect(r.data?.nameservers).toHaveLength(2)
  })

  it('never sets undefined on optional fields (exactOptionalPropertyTypes)', async () => {
    // A minimal RDAP domain payload with no events/entities
    const minimalDomain = { ldhName: 'sparse.com', entities: [], nameservers: [] }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      const u = url.toString()
      if (u.includes('iana.org'))  return new Response(JSON.stringify(ianaBootstrapDNS), { status: 200 })
      return new Response(JSON.stringify(minimalDomain), { status: 200 })
    })
    const r = await fetchRDAP(domQuery, kv)
    expect(r.status).toBe('ok')
    // These optional fields must be ABSENT, not set to undefined
    expect('created'  in (r.data ?? {})).toBe(false)
    expect('expires'  in (r.data ?? {})).toBe(false)
    expect('registrar' in (r.data ?? {})).toBe(false)
  })

  it('returns error on HTTP failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('', { status: 503 }),
    )
    const r = await fetchRDAP(ipQuery, kv)
    expect(r.status).toBe('error')
  })

  it('returns error when fetch throws', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('connection refused'))
    const r = await fetchRDAP(ipQuery, kv)
    expect(r.status).toBe('error')
    expect(r.error).toContain('connection refused')
  })
})
