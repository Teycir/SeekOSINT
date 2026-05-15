import type { SourceResult } from './types'

/**
 * Shared result constructors used by every source module.
 * Import these instead of constructing SourceResult objects inline.
 */

export function ok<T>(source: string, data: T, cached = false): SourceResult<T> {
  return {
    source,
    status: cached ? 'cached' : 'ok',
    data,
    ...(cached
      ? { cachedAt: Date.now() }
      : { fetchedAt: Date.now() }),
  }
}

export function error<T>(source: string, message: string): SourceResult<T> {
  return { source, status: 'error', data: null, error: message }
}

export function skipped<T>(source: string): SourceResult<T> {
  return { source, status: 'skipped', data: null }
}

/**
 * Unwrap a PromiseSettledResult into a SourceResult.
 * A rejected promise produces an error SourceResult so the orchestrator
 * never has to deal with thrown values from Promise.allSettled().
 */
export function unwrapSettled<T>(
  settled: PromiseSettledResult<SourceResult<T>>,
  source: string,
): SourceResult<T> {
  if (settled.status === 'fulfilled') return settled.value
  return error<T>(source, String(settled.reason))
}

/**
 * Extract the inner data value from a PromiseSettledResult<SourceResult<T>>,
 * returning null on any failure. Useful for feeding Layer 1 output into
 * Layer 3 decisions without extra boilerplate.
 */
export function unwrap<T>(
  settled: PromiseSettledResult<SourceResult<T>>,
): T | null {
  if (settled.status === 'fulfilled' && settled.value.status !== 'error') {
    return settled.value.data
  }
  return null
}
