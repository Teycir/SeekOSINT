/**
 * lib/inflight.ts
 *
 * Batch-scoped in-flight promise coalescer.
 *
 * When multiple concurrent lookups in a single /api/batch request share an
 * upstream fetch (same CVE ID, same BGP ASN, same URLhaus query…) the first
 * caller triggers the real fetch and stores the pending Promise under the
 * cache-key.  Every subsequent caller for the same key receives the *same*
 * Promise — so the upstream is hit exactly once per batch regardless of how
 * many queries would have triggered it.
 *
 * Lifecycle
 * ─────────
 * • One InflightCache instance is created at the top of POST /api/batch.
 * • It is passed into every runLookup() call for that batch.
 * • Because it lives only in the request handler's closure it is
 *   automatically garbage-collected when the stream closes — no explicit
 *   cleanup needed and no cross-request leakage is possible.
 *
 * Error semantics
 * ───────────────
 * Rejected promises are evicted immediately after settlement so that a
 * transient upstream error on query A does not permanently poison the
 * shared slot for query B (which might otherwise wait, get the rejection,
 * and never retry).  The second caller in that case starts a fresh fetch.
 *
 * Usage
 * ─────
 *   const inflight = new InflightCache()
 *   // … inside a source fetcher …
 *   return inflight.dedupe('nvd:CVE-2021-44228', () => fetchFromUpstream(...))
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class InflightCache {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly map = new Map<string, Promise<any>>()

  /**
   * If a promise is already in-flight for `key`, return it.
   * Otherwise call `fn()`, store the resulting promise, and return it.
   *
   * The stored promise is evicted on rejection so the next caller gets a
   * fresh attempt rather than inheriting the failure.
   */
  dedupe<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const existing = this.map.get(key)
    if (existing) return existing as Promise<T>

    const promise = fn().catch((err: unknown) => {
      // Evict on failure — next caller will retry from scratch
      this.map.delete(key)
      throw err
    })

    this.map.set(key, promise)

    // Evict after settlement (success or failure) so the Map does not grow
    // indefinitely during very large batches.  A fulfilled value is only kept
    // for the microseconds between resolution and the `.then` callback running,
    // which is fine — all in-flight waiters have already been handed the same
    // Promise reference and will resolve from it regardless.
    void promise.then(() => this.map.delete(key)).catch(() => {
      // rejection already evicted above; ignore here to avoid unhandled-rejection
    })

    return promise
  }

  /** Number of keys currently in-flight (useful for diagnostics / tests). */
  get size(): number {
    return this.map.size
  }
}
