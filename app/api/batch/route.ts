/**
 * app/api/batch/route.ts
 *
 * POST /api/batch
 * Body: { queries: string[], refresh?: boolean }  — max 20 queries
 *
 * Streams results as NDJSON — each query's result is emitted as soon as
 * its lookup finishes, so a fast cached hit appears immediately without
 * waiting for the slowest NVD fetch in the batch.
 *
 * Wire format (one JSON object per line, Content-Type: application/x-ndjson):
 *
 *   {"type":"result","index":0,"query":"8.8.8.8","data":{...HostResult}}
 *   {"type":"error","index":1,"query":"bad","error":"invalid query — ..."}
 *   {"type":"done","data":{"total":2,"failed":1,"durationMs":3210}}
 *
 * - "index" is the 0-based position of the query in the original array so
 *   clients can correlate out-of-order results back to their input.
 * - Failed individual lookups emit "error" frames — they never abort the
 *   stream or prevent other results from arriving.
 * - The "done" sentinel is always the last line.
 *
 * Rate limiting: the full batch cost (N queries) is charged atomically in
 * one KV write before the stream opens. A batch that would exceed the
 * quota is rejected with 429 before any lookup runs.
 */
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { parseQuery } from '../../../lib/validate'
import { sanitizeStringArray, validateQueryInput } from '../../../lib/sanitize'
import { checkRateLimit } from '../../../lib/ratelimit'
import { runLookup } from '../../../worker/lookup'
import { recordSearch } from '../../../lib/searches'
import { errorResponse, ErrorCode } from '../../../lib/errors'
import { extractCallerIp } from '../../../lib/logger'
import { RATE_LIMIT } from '../../../lib/config'
import type { Env } from '../../../lib/types'

const MAX_BATCH = 20

export async function POST(req: Request): Promise<Response> {
  const started = Date.now()

  // ── Parse request body ──────────────────────────────────────────────────────
  let body: { queries?: unknown; refresh?: unknown }
  try {
    body = await req.json()
  } catch (err) {
    console.error('[api/batch] JSON parse failed:', err)
    return errorResponse(ErrorCode.INVALID_QUERY, 'request body must be JSON', 400)
  }

  if (!Array.isArray(body.queries) || body.queries.length === 0) {
    return errorResponse(ErrorCode.INVALID_QUERY, 'queries must be a non-empty array', 400)
  }

  const forceRefresh = body.refresh === true

  // Sanitize: enforce max batch size and per-item length
  const rawQueries = sanitizeStringArray(body.queries, MAX_BATCH, 500)
  if (rawQueries.length === 0) {
    return errorResponse(ErrorCode.INVALID_QUERY, 'no valid string queries provided', 400)
  }

  // Injection check on every raw string before we do anything else
  for (const q of rawQueries) {
    const validation = validateQueryInput(q)
    if (!validation.valid) {
      console.warn('[api/batch] rejected query:', validation.reason, q.slice(0, 50))
      return errorResponse(ErrorCode.INVALID_QUERY, `invalid input in batch: ${validation.reason}`, 400)
    }
  }

  const { env, ctx } = await getCloudflareContext({ async: true })
  const typedEnv = env as unknown as Env
  const ip = extractCallerIp(req)

  // ── Rate limit — charge the full batch cost atomically ──────────────────────
  const rl = await checkRateLimit(ip, typedEnv.KV, rawQueries.length)
  if (!rl.allowed) {
    return errorResponse(
      ErrorCode.RATE_LIMITED,
      `rate limit exceeded — batch of ${rawQueries.length} would exceed quota`,
      429,
      { resetInSeconds: rl.resetInSeconds },
      {
        'X-RateLimit-Limit':     String(RATE_LIMIT.MAX_REQUESTS),
        'X-RateLimit-Remaining': String(rl.remaining),
        'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
        'Retry-After':           String(rl.resetInSeconds),
      },
    )
  }

  // Pre-parse all queries so invalid ones can emit immediate error frames
  // without spinning up a runLookup worker at all.
  const parsed = rawQueries.map((raw, index) => ({
    raw,
    index,
    query: parseQuery(raw),
  }))

  // ── Open NDJSON stream ──────────────────────────────────────────────────────
  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>()
  const writer = writable.getWriter()
  const enc    = new TextEncoder()

  function writeLine(obj: unknown): Promise<void> {
    return writer.write(enc.encode(JSON.stringify(obj) + '\n'))
  }

  // Fan out all lookups concurrently. Each one writes its frame immediately
  // when it settles — the stream delivers results in arrival order, not
  // input order. The "index" field lets clients re-sort if needed.
  ctx.waitUntil(
    (async () => {
      let failed = 0

      try {
        // Launch every lookup simultaneously. Each promise resolves by writing
        // its own frame to the stream as soon as it's ready.
        await Promise.all(
          parsed.map(async ({ raw, index, query }) => {
            // Invalid query → immediate error frame, no lookup needed
            if (!query) {
              failed++
              await writeLine({
                type:  'error',
                index,
                query: raw,
                error: 'invalid query — must be IPv4, IPv6, domain, or ASN',
              })
              return
            }

            try {
              const result = await runLookup(
                { ...query, forceRefresh },
                typedEnv,
                ctx,
              )

              // Non-blocking D1 persistence — fire-and-forget per result
              if (typedEnv.DB) {
                ctx.waitUntil(
                  recordSearch(
                    typedEnv.DB,
                    query.normalised,
                    query.type,
                    JSON.stringify(result),
                    result.meta.durationMs,
                  ).catch(err => console.error(`[api/batch] recordSearch failed for ${raw}`, err)),
                )
              }

              await writeLine({ type: 'result', index, query: raw, data: result })
            } catch (err) {
              failed++
              console.error(`[api/batch] lookup failed for ${raw}`, err)
              await writeLine({ type: 'error', index, query: raw, error: 'lookup failed' })
            }
          }),
        )
      } finally {
        // Always emit the done sentinel so clients know the stream is complete,
        // even if some lookups panicked or were caught above.
        await writeLine({
          type: 'done',
          data: {
            total:      parsed.length,
            failed,
            durationMs: Date.now() - started,
          },
        })
        await writer.close()
      }
    })(),
  )

  return new Response(readable, {
    headers: {
      'Content-Type':           'application/x-ndjson',
      'Transfer-Encoding':      'chunked',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control':          'no-store',
      'X-RateLimit-Limit':      String(RATE_LIMIT.MAX_REQUESTS),
      'X-RateLimit-Remaining':  String(rl.remaining),
      'X-RateLimit-Reset':      String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
    },
  })
}
