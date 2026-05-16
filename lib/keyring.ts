/**
 * KeyRing — round-robin key rotation with KV-backed exhaustion tracking.
 *
 * When a source returns HTTP 429 or 403, call markExhausted() on the key
 * that triggered it. nextHealthy() will skip it until the TTL expires,
 * transparently rotating to the next available key.
 *
 * Round-robin is implemented by storing a per-ring cursor in KV so that
 * successive requests spread load across all keys rather than always
 * hammering key #1 until it exhausts.
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
   * Returns the next healthy key using round-robin rotation, or null if all
   * keys are currently exhausted. Callers must treat null as a skip/error.
   */
  async nextHealthy(): Promise<string | null> {
    // Read current cursor (default 0)
    const cursorKey = `keyring:${this.source}:cursor`
    const raw = await this.kv.get(cursorKey)
    const startIndex = raw ? (parseInt(raw, 10) % this.keys.length) : 0

    for (let i = 0; i < this.keys.length; i++) {
      const index = (startIndex + i) % this.keys.length
      const key = this.keys[index]
      if (!key) continue
      const burnt = await this.kv.get(this.exhaustedKey(key))
      if (!burnt) {
        // Advance cursor for next call (best-effort, not atomic — acceptable)
        await this.kv.put(cursorKey, String((index + 1) % this.keys.length), {
          expirationTtl: 86400, // reset cursor after 24h idle
        })
        return key
      }
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
    // Hash the raw key value so it doesn't appear verbatim in KV key names,
    // which are visible in the Cloudflare dashboard and audit logs.
    // We use a simple djb2 hash — it's fast, deterministic, and sufficient
    // for a non-cryptographic KV namespace token.
    let h = 5381
    for (let i = 0; i < key.length; i++) {
      h = ((h << 5) + h) ^ key.charCodeAt(i)
    }
    const token = (h >>> 0).toString(16).padStart(8, '0')
    return `keyring:${this.source}:exhausted:${token}`
  }
}
