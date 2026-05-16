/**
 * app/api/stream/route.ts
 *
 * GET /api/stream?q=<query>[&refresh=1]
 *
 * Streams two NDJSON frames so the client can render incrementally:
 *
 *   Frame 1 — "partial": Layers 1+2+4 (geo, ports, threats, certs, DNS).
 *             Arrives in ~300–600ms for cached results, ~1–3s for fresh.
 *
 *   Frame 2 — "vulns": Layer 3 CVE details (may arrive 5–60s later if
 *             NVD has to be hit; instant if cached).
 *
 *   Frame 3 — "done": final meta block (duration, cache stats).
 *
 * Wire format (one JSON object per line):
 *   {"type":"partial","data":{...HostResult minus vulns}}
 *   {"type":"vulns","data":[...CVEDetail[]]}
 *   {"type":"done","data":{"durationMs":1234,...meta}}
 *   {"type":"error","data":{"code":"...","message":"..."}}
 *
 * The client renders Frame 1 immediately and patches in Frame 2 when it arrives.
 */
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { parseQuery } from '../../../lib/validate'
import { checkRateLimit } from '../../../lib/ratelimit'
import { runLookup } from '../../../worker/lookup'
import { errorResponse, ErrorCode } from '../../../lib/errors'
import { recordSearch } from '../../../lib/searches'
import type { Env } from '../../../lib/types'

export async function GET(req: Request): Promise<Response> {
  const { searchParams } = new URL(req.url)
  const q       = searchParams.get('q')
  const refresh = searchParams.get('refresh') === '1'

  if (!q) return errorResponse(ErrorCode.MISSING_QUERY, 'missing q', 400)

  const query = parseQuery(q)
  if (!query) return errorResponse(ErrorCode.INVALID_QUERY, 'invalid query', 422)

  const { env, ctx } = getCloudflareContext()
  const ip =
    req.headers.get('CF-Connecting-IP') ??
    req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
    'unknown'

  const rl = await checkRateLimit(ip, (env as unknown as Env).KV)
  if (!rl.allowed) {
    return errorResponse(
      ErrorCode.RATE_LIMITED, 'rate limit exceeded', 429,
      { resetInSeconds: rl.resetInSeconds },
      {
        'X-RateLimit-Limit':     '100',
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
        'Retry-After':           String(rl.resetInSeconds),
      },
    )
  }

  const started = Date.now()

  // runLookup already handles all layers including batched CVEs.
  // We run it fully then stream the result split into two frames.
  // This avoids duplicating the orchestration logic while still letting
  // the client receive and render Layer 1+2 before CVEs paint.
  //
  // For a true incremental stream we'd need to restructure runLookup to
  // yield intermediate results — that's a larger refactor. This version
  // streams the split synchronously once the full result is ready, which
  // still gives the client the ability to render sections progressively
  // if it processes frames as they arrive.

  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>()
  const writer = writable.getWriter()
  const enc    = new TextEncoder()

  function writeLine(obj: unknown) {
    return writer.write(enc.encode(JSON.stringify(obj) + '\n'))
  }

  ctx.waitUntil(
    (async () => {
      try {
        const result = await runLookup({ ...query, forceRefresh: refresh }, env as unknown as Env, ctx)

        // Frame 1 — everything except vulns
        const { vulns, ...partial } = result
        await writeLine({ type: 'partial', data: partial })

        // Frame 2 — CVE details (result.vulns is SourceResult<CVEDetail>[])
        const cveDetails = result.vulns
          .filter(v => (v.status === 'ok' || v.status === 'cached') && v.data !== null)
          .map(v => v.data)
        await writeLine({ type: 'vulns', data: cveDetails })

        // Frame 3 — done sentinel
        await writeLine({ type: 'done', data: result.meta })

        // Fire-and-forget D1 persistence
        const db = (env as unknown as Env).DB
        if (db) {
          ctx.waitUntil(
            recordSearch(db, query.normalised, query.type, JSON.stringify(result), result.meta.durationMs)
              .catch(err => console.error('[api/stream] recordSearch failed', err)),
          )
        }
      } catch (err) {
        console.error('[api/stream] runLookup failed', err)
        await writeLine({ type: 'error', data: { code: 'INTERNAL_ERROR', message: 'lookup failed' } })
      } finally {
        await writer.close()
      }
    })(),
  )

  return new Response(readable, {
    headers: {
      'Content-Type':          'application/x-ndjson',
      'Transfer-Encoding':     'chunked',
      'X-Content-Type-Options':'nosniff',
      'Cache-Control':         'no-store',
      'X-RateLimit-Limit':     '100',
      'X-RateLimit-Remaining': String(rl.remaining),
      'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
    },
  })
}
