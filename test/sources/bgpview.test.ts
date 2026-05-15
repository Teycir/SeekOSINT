/**
 * test/sources/bgpview.test.ts
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchBGPView } from '../../worker/sources/bgpview'
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

const ipQuery: LookupQuery   = { raw: '1.1.1.1', type: 'ip',     normalised: '1.1.1.1' }
const asnQuery: LookupQuery  = { raw: 'as13335', type: 'asn',    normalised: 'as13335' }
const domQuery: LookupQuery  = { raw: 'a.com',   type: 'domain', normalised: 'a.com' }

const bgpIPResponse = {
  data: {
    asn: { asn: 13335, name: 'CLOUDFLARENET', description: 'Cloudflare', country_code: 'US', rir_allocation: { rir_name: 'ARIN' } },
    prefixes: { ipv4: [{ prefix: '1.1.1.0/24' }] },
    upstreams: [{ asn: 3356 }],
    peers: [],
  },
}

const bgpASNResponse = {
  data: {
    asn: 13335, name: 'CLOUDFLARENET', description: 'Cloudflare', country_code: 'US',
    rir_allocation: { rir_name: 'ARIN' },
    prefixes: [{ prefix: '1.1.1.0/24' }],
    upstreams: [],
    peers: [{ asn: 174 }],
  },
}

describe('fetchBGPView', () => {
  let kv: KVNamespace

  beforeEach(() => { kv = makeMockKV() })
  afterEach(() => vi.restoreAllMocks())

  it('skips domain queries', async () => {
    const r = await fetchBGPView(domQuery, kv)
    expect(r.status).toBe('skipped')
  })

  it('uses cached result for IP query', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    const cached = { asn: 13335, name: 'CF', description: '', country: 'US', prefixes: [], upstreams: [], peers: [], rir: '' }
    kvm.store.set('bgp:ip:1.1.1.1', JSON.stringify(cached))
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const r = await fetchBGPView(ipQuery, kv)
    expect(r.status).toBe('cached')
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('normalises IP response into BGPViewResult', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(bgpIPResponse), { status: 200 }),
    )
    const r = await fetchBGPView(ipQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data?.asn).toBe(13335)
    expect(r.data?.country).toBe('US')
    expect(r.data?.prefixes).toContain('1.1.1.0/24')
  })

  it('normalises ASN response and strips "as" prefix from URL', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(bgpASNResponse), { status: 200 }),
    )
    const r = await fetchBGPView(asnQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data?.name).toBe('CLOUDFLARENET')
    expect(r.data?.peers).toContain(174)
  })

  it('returns error on HTTP failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response('', { status: 500 }),
    )
    const r = await fetchBGPView(ipQuery, kv)
    expect(r.status).toBe('error')
  })

  it('returns error when fetch throws', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('abort'))
    const r = await fetchBGPView(ipQuery, kv)
    expect(r.status).toBe('error')
    expect(r.error).toContain('abort')
  })
})
