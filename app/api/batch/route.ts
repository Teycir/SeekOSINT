/**
 * app/api/batch/route.ts
 *
 * POST /api/batch
 * Body: { queries: string[] }   — max 20, each a valid IP/domain/ASN
 *
 * Runs all queries concurrently (same as /api/lookup, just fanned out).
 * Rate limiting counts each query against the caller's per-IP quota.
 * Returns partial results — a failed individual lookup comes back as
 * { query, error } rather than tanking the whole batch.
 *
 * Response: { results: BatchResultItem[], meta: { total, failed, durationMs } }
 */
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { parseQuery } from '../../../lib/validate'
import { sanitizeStringArray, validateQueryInput } from '../../../lib/sanitize'
import { checkRateLimit } from '../../../lib/ratelimit'
import { runLookup } from '../../../worker/lookup'
import { recordSearch } from '../../../lib/searches'
import { errorResponse, ErrorCode } from '../../../lib/errors'
import type { Env, HostResult } from '../../../lib/types'

const MAX_BATCH = 20

interface BatchResultItem {
  query:   string
  result?: HostResult
  error?:  string
}

export async function POST(req: Request): Promise<Response> {
  let body: { queries?: unknown }
  try {
    body = await req.json()
  } catch (err) {
    console.error('[api/batch] JSON parse failed:', err)
    return errorResponse(ErrorCode.INVALID_QUERY, 'request body must be JSON', 400)
  }

  if (!Array.isArray(body.queries) || body.queries.length === 0) {
    return errorResponse(ErrorCode.INVALID_QUERY, 'queries must be a non-empty array', 400)
  }

  // Sanitize array input with limits
  const rawQueries = sanitizeStringArray(body.queries, MAX_BATCH, 500)

  if (rawQueries.length === 0) {
    return errorResponse(ErrorCode.INVALID_QUERY, 'no valid string queries provided', 400)
  }
  
  // Validate each query for injection patterns (query-safe subset)
  for (const q of rawQueries) {
    const validation = validateQueryInput(q)
    if (!validation.valid) {
      console.warn('[api/batch] rejected query:', validation.reason, q.slice(0, 50))
      return errorResponse(ErrorCode.INVALID_QUERY, `invalid input in batch: ${validation.reason}`, 400)
    }
  }

  const { env, ctx } = getCloudflareContext()

  // Rate limit: count each query against the caller's quota
  const ip =
    req.headers.get('CF-Connecting-IP') ??
    req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
    'unknown'

  const rl = await checkRateLimit(ip, (env as unknown as Env).KV, rawQueries.length)

  if (!rl.allowed) {
    return errorResponse(
      ErrorCode.RATE_LIMITED,
      `rate limit exceeded — batch of ${rawQueries.length} would exceed quota`,
      429,
      { resetInSeconds: rl.resetInSeconds },
      {
        'X-RateLimit-Limit':     '100',
        'X-RateLimit-Remaining': String(rl.remaining),
        'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
        'Retry-After':           String(rl.resetInSeconds),
      },
    )
  }

  const started = Date.now()

  // Parse and validate all queries up front
  const parsed = rawQueries.map(raw => ({ raw, query: parseQuery(raw) }))

  // Fan out — all queries in parallel, failures are isolated
  const settled = await Promise.allSettled(
    parsed.map(async ({ raw, query }): Promise<BatchResultItem> => {
      if (!query) return { query: raw, error: 'invalid query — must be IPv4, IPv6, domain, or ASN' }
      try {
        const result = await runLookup(query, env as unknown as Env, ctx)
        const db = (env as unknown as Env).DB
        if (db) {
          ctx.waitUntil(
            recordSearch(db, query.normalised, query.type, JSON.stringify(result), result.meta.durationMs)
              .catch(err => console.error('[api/batch] recordSearch failed', err)),
          )
        }
        return { query: raw, result }
      } catch (err) {
        console.error(`[api/batch] lookup failed for ${raw}`, err)
        return { query: raw, error: 'lookup failed' }
      }
    }),
  )

  const results: BatchResultItem[] = settled.map(s =>
    s.status === 'fulfilled' ? s.value : { query: '?', error: 'internal error' },
  )

  const failed = results.filter(r => r.error).length

  return Response.json(
    {
      results,
      meta: {
        total:      results.length,
        failed,
        durationMs: Date.now() - started,
      },
    },
    {
      headers: {
        'X-RateLimit-Limit':     '100',
        'X-RateLimit-Remaining': String(rl.remaining),
        'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
      },
    },
  )
}
