/**
 * KeyRing — round-robin key rotation with KV-backed exhaustion tracking.
 *
 * When a source returns HTTP 429 or 403, call markExhausted() on the key
 * that triggered it. nextHealthy() will skip it until the TTL expires,
 * transparently rotating to the next available key.
 */
export class KeyRing {
  private keys: string[]
  private kv: KVNamespace
  private source: string

  constructor(keys: string[], kv: KVNamespace, source: string) {
    this.keys = keys.filter(Boolean)
    this.kv = kv
    this.source = source
  }

  /**
   * Returns the first key not currently marked exhausted, or null if all
   * keys are burnt. Callers must treat null as a skip/error condition.
   */
  async nextHealthy(): Promise<string | null> {
    for (const key of this.keys) {
      const burnt = await this.kv.get(this.exhaustedKey(key))
      if (!burnt) return key
    }
    return null
  }

  /**
   * Mark a key as exhausted for `ttlSeconds`. Defaults to 1 hour, which
   * matches most API quota reset windows.
   */
  async markExhausted(key: string, ttlSeconds = 3600): Promise<void> {
    await this.kv.put(this.exhaustedKey(key), '1', {
      expirationTtl: ttlSeconds,
    })
  }

  /** Total number of keys in this ring (including exhausted ones). */
  get count(): number {
    return this.keys.length
  }

  private exhaustedKey(key: string): string {
    return `keyring:${this.source}:exhausted:${key}`
  }
}
