/**
 * test/sources/internetdb.test.ts
 *
 * fetchInternetDB — caching, 404 handling, error paths, domain/ASN skip.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchInternetDB } from '../../worker/sources/internetdb'
import type { LookupQuery } from '../../lib/types'

// ─── KV mock ─────────────────────────────────────────────────────────────────

function makeMockKV() {
  const store = new Map<string, string>()
  return {
    store,
    get:  vi.fn(async (k: string) => store.get(k) ?? null),
    put:  vi.fn(async (k: string, v: string) => { store.set(k, v) }),
    delete: vi.fn(), list: vi.fn(), getWithMetadata: vi.fn(),
  } as unknown as KVNamespace
}

const ipQuery: LookupQuery = { raw: '1.2.3.4', type: 'ip', normalised: '1.2.3.4' }
const domainQuery: LookupQuery = { raw: 'example.com', type: 'domain', normalised: 'example.com' }
const asnQuery: LookupQuery = { raw: 'as13335', type: 'asn', normalised: 'as13335' }

const mockData = {
  ip: '1.2.3.4',
  ports: [80, 443],
  hostnames: ['host.example.com'],
  tags: ['cdn'],
  vulns: ['CVE-2021-44228'],
  cpes: [],
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('fetchInternetDB', () => {
  let kv: KVNamespace

  beforeEach(() => { kv = makeMockKV() })
  afterEach(() => vi.restoreAllMocks())

  it('skips domain queries', async () => {
    const r = await fetchInternetDB(domainQuery, kv)
    expect(r.status).toBe('skipped')
  })

  it('skips ASN queries', async () => {
    const r = await fetchInternetDB(asnQuery, kv)
    expect(r.status).toBe('skipped')
  })

  it('returns cached result when KV has a hit', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    kvm.store.set(`internetdb:1.2.3.4`, JSON.stringify(mockData))

    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const r = await fetchInternetDB(ipQuery, kv)

    expect(r.status).toBe('cached')
    expect(r.data?.ports).toEqual([80, 443])
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('fetches from network and returns ok result', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockData), { status: 200 }),
    )
    const r = await fetchInternetDB(ipQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data?.vulns).toContain('CVE-2021-44228')
  })

  it('returns empty result on 404 (IP not in Shodan)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response('Not Found', { status: 404 }),
    )
    const r = await fetchInternetDB(ipQuery, kv)
    expect(r.status).toBe('ok')
    expect(r.data?.ports).toEqual([])
    expect(r.data?.vulns).toEqual([])
  })

  it('returns error on non-404 HTTP failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response('', { status: 503 }),
    )
    const r = await fetchInternetDB(ipQuery, kv)
    expect(r.status).toBe('error')
    expect(r.error).toContain('503')
  })

  it('returns error when fetch throws (network failure)', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('timeout'))
    const r = await fetchInternetDB(ipQuery, kv)
    expect(r.status).toBe('error')
    expect(r.error).toContain('timeout')
  })

  it('writes a fresh result to KV', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockData), { status: 200 }),
    )
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    await fetchInternetDB(ipQuery, kv)
    expect(kvm.put).toHaveBeenCalled()
  })
})
