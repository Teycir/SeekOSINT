/**
 * test/cache.test.ts — CacheKey format contracts + cacheGet/cachePut
 *
 * cacheGet/cachePut require a KVNamespace — we mock the minimal surface.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { CacheKey, TTL, cacheGet, cachePut } from '../lib/cache'

// ─── Minimal KV mock ─────────────────────────────────────────────────────────

function makeMockKV() {
  const store = new Map<string, string>()
  return {
    store,
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    put: vi.fn(async (key: string, value: string, _opts?: unknown) => {
      store.set(key, value)
    }),
    delete: vi.fn(async (key: string) => { store.delete(key) }),
    list:   vi.fn(async () => ({ keys: [], list_complete: true, cursor: '' })),
    getWithMetadata: vi.fn(async () => ({ value: null, metadata: null })),
  } as unknown as KVNamespace
}

// ─── CacheKey shape tests ─────────────────────────────────────────────────────

describe('CacheKey', () => {
  it('prefixes internetdb keys correctly', () => {
    expect(CacheKey.internetdb('1.2.3.4')).toBe('internetdb:1.2.3.4')
  })

  it('prefixes ipapi keys correctly', () => {
    expect(CacheKey.ipapi('5.6.7.8')).toBe('ipapi:5.6.7.8')
  })

  it('prefixes bgp ip vs asn differently', () => {
    const ip  = CacheKey.bgpIP('1.1.1.1')
    const asn = CacheKey.bgpASN('as13335')
    expect(ip).toBe('bgp:ip:1.1.1.1')
    expect(asn).toBe('bgp:asn:as13335')
    expect(ip).not.toBe(asn)
  })

  it('prefixes rdap ip vs domain differently', () => {
    const ip     = CacheKey.rdapIP('8.8.8.8')
    const domain = CacheKey.rdapDomain('example.com')
    expect(ip.startsWith('rdap:ip:')).toBe(true)
    expect(domain.startsWith('rdap:domain:')).toBe(true)
    expect(ip).not.toBe(domain)
  })

  it('returns stable string keys for NVD and OSV', () => {
    expect(CacheKey.nvd('CVE-2021-44228')).toBe('nvd:CVE-2021-44228')
    expect(CacheKey.osv('CVE-2021-44228')).toBe('osv:CVE-2021-44228')
  })

  it('returns a constant for feodo and sslbl blocklists', () => {
    expect(CacheKey.feodoList()).toBe(CacheKey.feodoList())
    expect(CacheKey.sslblList()).toBe(CacheKey.sslblList())
    // They must be distinct
    expect(CacheKey.feodoList()).not.toBe(CacheKey.sslblList())
  })

  it('returns a constant for RDAP bootstrap keys', () => {
    expect(CacheKey.rdapBootDNS()).toBe(CacheKey.rdapBootDNS())
    expect(CacheKey.rdapBootIP()).toBe(CacheKey.rdapBootIP())
    expect(CacheKey.rdapBootDNS()).not.toBe(CacheKey.rdapBootIP())
  })
})

// ─── TTL sanity checks ────────────────────────────────────────────────────────

describe('TTL', () => {
  it('CVE TTL is 30 days', () => {
    expect(TTL.CVE).toBe(60 * 60 * 24 * 30)
  })

  it('longer-lived caches outlast shorter ones', () => {
    expect(TTL.CVE).toBeGreaterThan(TTL.BGP)
    expect(TTL.BGP).toBeGreaterThan(TTL.CORE)
    expect(TTL.CORE).toBeGreaterThan(TTL.ABUSECH)
  })
})

// ─── cacheGet / cachePut ──────────────────────────────────────────────────────

describe('cacheGet', () => {
  let kv: KVNamespace

  beforeEach(() => { kv = makeMockKV() })

  it('returns null on a cache miss', async () => {
    const result = await cacheGet<{ x: number }>(kv, 'missing-key')
    expect(result).toBeNull()
  })

  it('returns parsed value on a cache hit', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    kvm.store.set('hit-key', JSON.stringify({ x: 42 }))
    const result = await cacheGet<{ x: number }>(kv, 'hit-key')
    expect(result).toEqual({ x: 42 })
  })

  it('returns null if stored JSON is malformed', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    kvm.store.set('bad-key', 'not-json{{')
    const result = await cacheGet<unknown>(kv, 'bad-key')
    expect(result).toBeNull()
  })
})

describe('cachePut', () => {
  let kv: KVNamespace

  beforeEach(() => { kv = makeMockKV() })

  it('stores a JSON-serialised value', async () => {
    await cachePut(kv, 'test-key', { hello: 'world' }, 3600)
    const raw = await kv.get('test-key')
    expect(JSON.parse(raw!)).toEqual({ hello: 'world' })
  })

  it('does not throw if KV.put fails', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    kvm.put.mockRejectedValueOnce(new Error('quota exceeded'))
    await expect(cachePut(kv, 'k', {}, 60)).resolves.not.toThrow()
  })

  it('serialises arrays correctly', async () => {
    await cachePut(kv, 'arr', [1, 2, 3], 60)
    const raw = await kv.get('arr')
    expect(JSON.parse(raw!)).toEqual([1, 2, 3])
  })
})
