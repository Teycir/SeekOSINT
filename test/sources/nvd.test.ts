/**
 * test/sources/nvd.test.ts
 *
 * fetchCVE — NVD+CIRCL race, OSV fallback, caching, error paths.
 * Validates that parseCIRCL never sets undefined on optional CVEDetail fields.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchCVE, fetchOSV } from '../../worker/sources/nvd'

function makeMockKV() {
  const store = new Map<string, string>()
  return {
    store,
    get: vi.fn(async (k: string) => store.get(k) ?? null),
    put: vi.fn(async (k: string, v: string) => { store.set(k, v) }),
    delete: vi.fn(), list: vi.fn(), getWithMetadata: vi.fn(),
  } as unknown as KVNamespace
}

const CVE_ID = 'CVE-2021-44228'
const NVD_KEY = 'nvd-test-key'

const nvdResponse = {
  vulnerabilities: [{
    cve: {
      id: CVE_ID,
      descriptions: [{ lang: 'en', value: 'Log4Shell RCE vulnerability.' }],
      metrics: {
        cvssMetricV31: [{ cvssData: { baseScore: 10.0, baseSeverity: 'CRITICAL' } }],
      },
      weaknesses: [{ description: [{ value: 'CWE-502' }] }],
      references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' }],
      published: '2021-12-10',
      lastModified: '2023-01-01',
    },
  }],
}

const circlResponse = {
  summary: 'Log4Shell RCE vulnerability.',
  cvss: 10.0,
  cwe: 'CWE-502',
  references: ['https://circl.lu/'],
  Published: '2021-12-10',
  Modified: '2023-01-01',
}

const osvResponse = {
  details: 'Log4Shell details from OSV.',
  database_specific: { cwe_ids: ['CWE-502'] },
  references: [{ url: 'https://osv.dev/' }],
  published: '2021-12-10',
  modified: '2023-01-01',
}

describe('fetchCVE', () => {
  let kv: KVNamespace
  beforeEach(() => { kv = makeMockKV() })
  afterEach(() => vi.restoreAllMocks())

  it('returns cached result without hitting the network', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    const cached = {
      id: CVE_ID, description: 'cached', cvssV3Score: 10, cvssV3Severity: 'CRITICAL',
      source: 'nvd',
    }
    kvm.store.set(`nvd:${CVE_ID}`, JSON.stringify(cached))
    const spy = vi.spyOn(globalThis, 'fetch')
    const r = await fetchCVE(CVE_ID, kv, NVD_KEY)
    expect(r.status).toBe('cached')
    expect(spy).not.toHaveBeenCalled()
  })

  it('returns ok result when NVD responds first', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (url.toString().includes('nvd.nist.gov'))
        return new Response(JSON.stringify(nvdResponse), { status: 200 })
      // CIRCL — make it fail so NVD wins
      return new Response('', { status: 503 })
    })
    const r = await fetchCVE(CVE_ID, kv, NVD_KEY)
    expect(r.status).toBe('ok')
    expect(r.data?.id).toBe(CVE_ID)
    expect(r.data?.cvssV3Score).toBe(10.0)
    expect(r.data?.cvssV3Severity).toBe('CRITICAL')
  })

  it('falls back to CIRCL when NVD fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (url.toString().includes('nvd.nist.gov'))
        return new Response('', { status: 429 })
      return new Response(JSON.stringify(circlResponse), { status: 200 })
    })
    const r = await fetchCVE(CVE_ID, kv, NVD_KEY)
    expect(r.status).toBe('ok')
    expect(r.data?.source).toBe('circl')
    expect(r.data?.description).toBe('Log4Shell RCE vulnerability.')
  })

  it('never has undefined on optional CVEDetail fields (exactOptionalPropertyTypes)', async () => {
    // CIRCL response with no cvss score — should OMIT cvssV3Score, not set it to undefined
    const partialCircl = { summary: 'desc', Published: '2024-01-01', Modified: '2024-01-02' }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (url.toString().includes('nvd.nist.gov'))
        return new Response('', { status: 503 })
      return new Response(JSON.stringify(partialCircl), { status: 200 })
    })
    const r = await fetchCVE(CVE_ID, kv, NVD_KEY)
    expect(r.status).toBe('ok')
    // Must not be present at all, not set to undefined
    if (r.data) {
      expect('cvssV3Score' in r.data).toBe(false)
      expect('cwe' in r.data).toBe(false)
      expect('references' in r.data).toBe(false)
    }
  })

  it('returns error when both NVD and CIRCL fail', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 503 }))
    const r = await fetchCVE(CVE_ID, kv, NVD_KEY)
    expect(r.status).toBe('error')
  })

  it('writes result to KV after a fresh fetch', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(nvdResponse), { status: 200 }),
    )
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    await fetchCVE(CVE_ID, kv, NVD_KEY)
    expect(kvm.put).toHaveBeenCalled()
  })
})

describe('fetchOSV', () => {
  let kv: KVNamespace
  beforeEach(() => { kv = makeMockKV() })
  afterEach(() => vi.restoreAllMocks())

  it('returns cached OSV result', async () => {
    const kvm = kv as unknown as ReturnType<typeof makeMockKV>
    const cached = { id: CVE_ID, description: 'cached-osv', source: 'osv' }
    kvm.store.set(`osv:${CVE_ID}`, JSON.stringify(cached))
    const spy = vi.spyOn(globalThis, 'fetch')
    const r = await fetchOSV(CVE_ID, kv)
    expect(r.status).toBe('cached')
    expect(spy).not.toHaveBeenCalled()
  })

  it('returns ok result from OSV network response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(osvResponse), { status: 200 }),
    )
    const r = await fetchOSV(CVE_ID, kv)
    expect(r.status).toBe('ok')
    expect(r.data?.id).toBe(CVE_ID)
    expect(r.data?.source).toBe('osv')
    expect(r.data?.description).toBe('Log4Shell details from OSV.')
  })

  it('returns error on HTTP failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('', { status: 404 }))
    const r = await fetchOSV(CVE_ID, kv)
    expect(r.status).toBe('error')
  })
})
