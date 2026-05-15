/**
 * test/sources/robtex.test.ts
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchRobtex } from '../../worker/sources/robtex'
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

const ipQuery: LookupQuery  = { raw: '1.1.1.1', type: 'ip',     normalised: '1.1.1.1' }
const domQuery: LookupQuery = { raw: 'a.com',   type: 'domain', normalised: 'a.com' }
const asnQuery: LookupQuery = { raw: 'as13335', type: 'asn',    normalised: 'as13335' }

const robtexPayload = {
  as: 13335, asname: 'CLOUDFLARENET', whoisdesc: 'Cloudflare',
  routedesc: '', bgproute: '1.1.1.0/24', city: 'San Francisco', country: 'US',
  pas: [{ o: 'one.one.one.one', t: 1700000000 }],
  ras: [],
}

describe('fetchRobtex', () => {
  let kv: KVNamespace
  beforeEach(() => { kv = makeMockKV() })
  afterEach(() => vi.restoreAllMocks())

  it('skips domain queries', async () => {
    expect((await fetchRobtex(domQuery, kv)).status).toBe('skipped')
  })

  it('skips ASN queries', async () => {
    expect((await fetchRobtex(asnQuery, kv)).status).toBe('skipped')
  })

  it('returns cached result without network', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    kvm.store.set('robtex:1.1.1.1', JSON.stringify(robtexPayload))
    const spy = vi.spyOn(globalThis, 'fetch')
    const r = await fetchRobtex(ipQuery, kv)
    expect(r.status).toBe('cached')
    expect(spy).not.toHaveBeenCalled()
  })

  it('normalises response fields correctly', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(robtexPayload), { status: 200 }),
    )
    const r = await fetchRobtex(ipQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data?.asname).toBe('CLOUDFLARENET')
    expect(r.data?.country).toBe('US')
    expect(r.data?.passiveDNS).toHaveLength(1)
    expect(r.data?.passiveDNS[0]?.o).toBe('one.one.one.one')
    expect(r.data?.reverseDNS).toHaveLength(0)
  })

  it('returns error on HTTP failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('', { status: 503 }))
    const r = await fetchRobtex(ipQuery, kv)
    expect(r.status).toBe('error')
  })

  it('returns error when fetch throws', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('reset'))
    const r = await fetchRobtex(ipQuery, kv)
    expect(r.status).toBe('error')
    expect(r.error).toContain('reset')
  })
})
