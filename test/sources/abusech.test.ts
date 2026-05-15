/**
 * test/sources/abusech.test.ts
 *
 * URLhaus, ThreatFox, MalwareBazaar, Feodo, SSLBL
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  fetchURLhaus,
  fetchThreatFox,
  fetchMalwareBazaar,
  fetchFeodo,
  fetchSSLBL,
} from '../../worker/sources/abusech'
import type { LookupQuery, FeodoEntry } from '../../lib/types'

function makeMockKV() {
  const store = new Map<string, string>()
  return {
    store,
    get: vi.fn(async (k: string) => store.get(k) ?? null),
    put: vi.fn(async (k: string, v: string) => { store.set(k, v) }),
    delete: vi.fn(), list: vi.fn(), getWithMetadata: vi.fn(),
  } as unknown as KVNamespace
}

const ipQuery: LookupQuery  = { raw: '1.2.3.4', type: 'ip',     normalised: '1.2.3.4' }
const domQuery: LookupQuery = { raw: 'evil.com', type: 'domain', normalised: 'evil.com' }
const API_KEY = 'test-key'

// ─── URLhaus ──────────────────────────────────────────────────────────────────

describe('fetchURLhaus', () => {
  let kv: KVNamespace
  beforeEach(() => { kv = makeMockKV() })
  afterEach(() => vi.restoreAllMocks())

  it('returns cached result without hitting network', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    kvm.store.set('urlhaus:1.2.3.4', JSON.stringify({ query_status: 'is_host', urls_count: 2 }))
    const spy = vi.spyOn(globalThis, 'fetch')
    const r = await fetchURLhaus(ipQuery, kv, API_KEY)
    expect(r.status).toBe('cached')
    expect(spy).not.toHaveBeenCalled()
  })

  it('returns ok result on network success', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ query_status: 'is_host', urls_count: 1 }), { status: 200 }),
    )
    const r = await fetchURLhaus(ipQuery, kv, API_KEY)
    expect(r.status).toBe('ok')
    expect(r.data?.query_status).toBe('is_host')
  })

  it('returns error on HTTP failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('', { status: 500 }))
    const r = await fetchURLhaus(ipQuery, kv, API_KEY)
    expect(r.status).toBe('error')
  })

  it('returns error when fetch throws', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('abort'))
    const r = await fetchURLhaus(domQuery, kv, API_KEY)
    expect(r.status).toBe('error')
  })
})

// ─── ThreatFox ────────────────────────────────────────────────────────────────

describe('fetchThreatFox', () => {
  let kv: KVNamespace
  beforeEach(() => { kv = makeMockKV() })
  afterEach(() => vi.restoreAllMocks())

  it('returns ok result on success', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ query_status: 'no_results' }), { status: 200 }),
    )
    const r = await fetchThreatFox(ipQuery, kv, API_KEY)
    expect(r.status).toBe('ok')
    expect(r.data?.query_status).toBe('no_results')
  })

  it('returns error on HTTP 429', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('', { status: 429 }))
    const r = await fetchThreatFox(ipQuery, kv, API_KEY)
    expect(r.status).toBe('error')
  })
})

// ─── MalwareBazaar ────────────────────────────────────────────────────────────

describe('fetchMalwareBazaar', () => {
  let kv: KVNamespace
  beforeEach(() => { kv = makeMockKV() })
  afterEach(() => vi.restoreAllMocks())

  it('returns cached result without hitting network', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    kvm.store.set('malwarebazaar:1.2.3.4', JSON.stringify({ query_status: 'ok', data: [] }))
    const spy = vi.spyOn(globalThis, 'fetch')
    const r = await fetchMalwareBazaar(ipQuery, kv, API_KEY)
    expect(r.status).toBe('cached')
    expect(spy).not.toHaveBeenCalled()
  })

  it('searches by tag for IP/domain queries (no hash)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ query_status: 'no_results' }), { status: 200 }),
    )
    const r = await fetchMalwareBazaar(ipQuery, kv, API_KEY)
    expect(r.status).toBe('ok')
    expect(r.data?.query_status).toBe('no_results')
  })

  it('searches by hash when hash is provided', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ query_status: 'ok', data: [] }), { status: 200 }),
    )
    const r = await fetchMalwareBazaar(ipQuery, kv, API_KEY, 'deadbeef')
    expect(r.status).toBe('ok')
  })

  it('returns error on network failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('timeout'))
    const r = await fetchMalwareBazaar(ipQuery, kv, API_KEY, 'deadbeef')
    expect(r.status).toBe('error')
  })
})

// ─── Feodo ────────────────────────────────────────────────────────────────────

const feodoList: FeodoEntry[] = [
  {
    ip_address: '1.2.3.4', port: 4444, status: 'Online',
    hostname: null, as_number: 1234, as_name: 'EVIL-AS',
    country: 'RU', first_seen: '2024-01-01', last_seen: '2024-06-01', malware: 'Emotet',
  },
]

describe('fetchFeodo', () => {
  let kv: KVNamespace
  beforeEach(() => { kv = makeMockKV() })
  afterEach(() => vi.restoreAllMocks())

  it('skips domain queries', async () => {
    const r = await fetchFeodo(domQuery, kv)
    expect(r.status).toBe('skipped')
  })

  it('returns cached blocklist match for known IP', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    kvm.store.set('feodo:blocklist', JSON.stringify(feodoList))
    const r = await fetchFeodo(ipQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data).not.toBeNull()
    expect(r.data?.malware).toBe('Emotet')
  })

  it('returns null data for IP not on blocklist', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    kvm.store.set('feodo:blocklist', JSON.stringify(feodoList))
    const cleanQuery: LookupQuery = { raw: '9.9.9.9', type: 'ip', normalised: '9.9.9.9' }
    const r = await fetchFeodo(cleanQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data).toBeNull()
  })

  it('downloads blocklist on miss and finds matching IP', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(feodoList), { status: 200 }),
    )
    const r = await fetchFeodo(ipQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data?.ip_address).toBe('1.2.3.4')
  })

  it('returns error when blocklist download fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('', { status: 502 }))
    const r = await fetchFeodo(ipQuery, kv)
    expect(r.status).toBe('error')
  })
})

// ─── SSLBL ────────────────────────────────────────────────────────────────────

describe('fetchSSLBL', () => {
  let kv: KVNamespace
  beforeEach(() => { kv = makeMockKV() })
  afterEach(() => vi.restoreAllMocks())

  it('skips domain queries', async () => {
    const r = await fetchSSLBL(domQuery, kv)
    expect(r.status).toBe('skipped')
  })

  it('returns ok with empty array when no DstIP match', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    kvm.store.set('sslbl:blocklist', JSON.stringify([
      { SHA1: 'abc', Listingdate: '2024-01-01', SuspiciousReason: 'Dridex C&C', Listingtime: '12:00:00', DstIP: '9.9.9.9' },
    ]))
    const r = await fetchSSLBL(ipQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data).toHaveLength(0)
  })

  it('returns matching entry when DstIP matches query', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    kvm.store.set('sslbl:blocklist', JSON.stringify([
      { SHA1: 'abc', Listingdate: '2024-01-01', SuspiciousReason: 'Dridex C&C', Listingtime: '12:00:00', DstIP: '1.2.3.4' },
    ]))
    const r = await fetchSSLBL(ipQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data).toHaveLength(1)
    expect(r.data?.[0]?.SHA1).toBe('abc')
  })

  it('downloads blocklist on miss', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ results: [] }), { status: 200 }),
    )
    const r = await fetchSSLBL(ipQuery, kv)
    expect(r.status).toBe('ok')
  })

  it('returns error when download fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('', { status: 500 }))
    const r = await fetchSSLBL(ipQuery, kv)
    expect(r.status).toBe('error')
  })
})
