import { describe, it, expect, vi, beforeEach } from 'vitest'
import { KeyRing } from '../lib/keyring'

// Minimal mock KV
function mockKV() {
  const store = new Map<string, string>()
  return {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    put: vi.fn(async (key: string, value: string) => { store.set(key, value) }),
    _store: store,
  } as unknown as KVNamespace
}

describe('KeyRing', () => {
  let kv: KVNamespace

  beforeEach(() => {
    kv = mockKV()
  })

  it('returns first healthy key when none are exhausted', async () => {
    const ring = new KeyRing(['key1', 'key2', 'key3'], kv, 'ghw')
    const key = await ring.nextHealthy()
    expect(key).toBe('key1')
  })

  it('skips exhausted keys', async () => {
    const ring = new KeyRing(['key1', 'key2', 'key3'], kv, 'ghw')
    await ring.markExhausted('key1')
    const key = await ring.nextHealthy()
    expect(key).toBe('key2')
  })

  it('returns null when all keys are exhausted', async () => {
    const ring = new KeyRing(['key1', 'key2'], kv, 'ghw')
    await ring.markExhausted('key1')
    await ring.markExhausted('key2')
    const key = await ring.nextHealthy()
    expect(key).toBeNull()
  })

  it('filters empty strings from key list', () => {
    const ring = new KeyRing(['key1', '', 'key2'], kv, 'ghw')
    expect(ring.count).toBe(2)
  })
})
