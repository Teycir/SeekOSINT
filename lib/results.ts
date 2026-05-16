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
// NOTE: cachedAt/fetchedAt were previously inverted — now correct:
// cached=true  → cachedAt  (when was this read from cache)
// cached=false → fetchedAt (when was this fetched live)

export function error<T>(source: string, message: string): SourceResult<T> {
  return { source, status: 'error', data: null, error: message }
}

export function skipped<T>(source: string): SourceResult<T> {
  return { source, status: 'skipped', data: null }
}

/**
 * Parse the JSON body of a Response, with optional structural validation.
 *
 * Throws a descriptive Error (never returns undefined/null) so callers
 * can let the surrounding try/catch turn it into an `error()` result.
 *
 * @param res    — a Response whose body has NOT been consumed yet
 * @param guard  — optional predicate; if it returns false the parse is
 *                 treated as malformed and an error is thrown
 * @param label  — human-readable name used in the thrown error message
 *
 * Usage:
 *   const data = await safeJson<InternetDBResult>(res, isInternetDBResult, 'internetdb')
 */
export async function safeJson<T>(
  res: Response,
  guard?: (v: unknown) => v is T,
  label = 'upstream',
): Promise<T> {
  let parsed: unknown
  try {
    parsed = await res.json()
  } catch (err) {
    console.error(`[${label}] JSON parse failed:`, err)
    throw new Error(`${label}: response body is not valid JSON`)
  }
  if (parsed === null || parsed === undefined) {
    throw new Error(`${label}: response body is null or empty`)
  }
  if (guard && !guard(parsed)) {
    throw new Error(`${label}: response shape validation failed`)
  }
  return parsed as T
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
