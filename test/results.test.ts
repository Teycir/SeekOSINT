/**
 * test/results.test.ts — ok, error, skipped, unwrapSettled, unwrap
 */
import { describe, it, expect } from 'vitest'
import { ok, error, skipped, unwrapSettled, unwrap } from '../lib/results'

describe('ok()', () => {
  it('returns status ok when cached=false (default)', () => {
    const r = ok('src', { x: 1 })
    expect(r.status).toBe('ok')
    expect(r.source).toBe('src')
    expect(r.data).toEqual({ x: 1 })
    expect(r.fetchedAt).toBeTypeOf('number')
    expect(r.cachedAt).toBeUndefined()
  })

  it('returns status cached when cached=true', () => {
    const r = ok('src', 42, true)
    expect(r.status).toBe('cached')
    expect(r.cachedAt).toBeTypeOf('number')
    expect(r.fetchedAt).toBeUndefined()
  })

  // Regression: cachedAt and fetchedAt were previously assigned to the wrong branch.
  // Ensure they are mutually exclusive and appear on the correct status.
  it('cachedAt is absent on a live fetch result', () => {
    const r = ok('src', 'live')
    expect('cachedAt' in r).toBe(false)
    expect('fetchedAt' in r).toBe(true)
  })

  it('fetchedAt is absent on a cached result', () => {
    const r = ok('src', 'cached', true)
    expect('fetchedAt' in r).toBe(false)
    expect('cachedAt' in r).toBe(true)
  })
})

describe('error()', () => {
  it('returns status error with null data', () => {
    const r = error('src', 'boom')
    expect(r.status).toBe('error')
    expect(r.data).toBeNull()
    expect(r.error).toBe('boom')
  })
})

describe('skipped()', () => {
  it('returns status skipped with null data', () => {
    const r = skipped('src')
    expect(r.status).toBe('skipped')
    expect(r.data).toBeNull()
  })
})

describe('unwrapSettled()', () => {
  it('passes through a fulfilled SourceResult', () => {
    const inner = ok('s', 99)
    const settled: PromiseFulfilledResult<typeof inner> = {
      status: 'fulfilled',
      value: inner,
    }
    const out = unwrapSettled(settled, 's')
    expect(out.status).toBe('ok')
    expect(out.data).toBe(99)
  })

  it('converts a rejected promise into an error SourceResult', () => {
    const settled: PromiseRejectedResult = {
      status: 'rejected',
      reason: 'network timeout',
    }
    const out = unwrapSettled(settled, 's')
    expect(out.status).toBe('error')
    expect(out.error).toContain('network timeout')
  })

  it('preserves rejection reason that is an Error object', () => {
    const settled: PromiseRejectedResult = {
      status: 'rejected',
      reason: new Error('dns failed'),
    }
    const out = unwrapSettled(settled, 's')
    expect(out.error).toContain('dns failed')
  })
})

describe('unwrap()', () => {
  it('returns inner data from a fulfilled ok result', () => {
    const inner = ok('s', { val: 7 })
    const settled: PromiseFulfilledResult<typeof inner> = {
      status: 'fulfilled',
      value: inner,
    }
    expect(unwrap(settled)).toEqual({ val: 7 })
  })

  it('returns null for a rejected promise', () => {
    const settled: PromiseRejectedResult = { status: 'rejected', reason: 'x' }
    expect(unwrap(settled)).toBeNull()
  })

  it('returns null for a fulfilled error SourceResult', () => {
    const inner = error<number>('s', 'bad')
    const settled: PromiseFulfilledResult<typeof inner> = {
      status: 'fulfilled',
      value: inner,
    }
    expect(unwrap(settled)).toBeNull()
  })

  it('returns null for a fulfilled skipped SourceResult', () => {
    const inner = skipped<string>('s')
    const settled: PromiseFulfilledResult<typeof inner> = {
      status: 'fulfilled',
      value: inner,
    }
    expect(unwrap(settled)).toBeNull()
  })
})
