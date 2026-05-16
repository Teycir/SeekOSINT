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
import { sanitizeQueryParam, validateQueryInput } from '../../../lib/sanitize'
import { checkRateLimit, acquireConcurrency, releaseConcurrency } from '../../../lib/ratelimit'
import { runLookup } from '../../../worker/lookup'
import { errorResponse, ErrorCode } from '../../../lib/errors'
import { recordSearch } from '../../../lib/searches'
import { RATE_LIMIT } from '../../../lib/config'
import { log, extractCallerIp } from '../../../lib/logger'
import type { Env } from '../../../lib/types'

export async function GET(req: Request): Promise<Response> {
  const started = Date.now()
  const { searchParams } = new URL(req.url)
  const qRaw    = searchParams.get('q')
  const refresh = searchParams.get('refresh') === '1'
  const tsToken = searchParams.get('ts')

  const { env, ctx } = getCloudflareContext()
  const typedEnv = env as unknown as Env
  const ip = extractCallerIp(req)
  const rayId = req.headers.get('CF-Ray') ?? undefined
  const country = req.headers.get('CF-IPCountry') ?? undefined

  if (!qRaw) {
    log.provenance({
      kind: 'inbound',
      callerIp: ip,
      ...(rayId && { rayId }),
      ...(country && { country }),
      query: '',
      queryType: 'unknown',
      method: req.method,
      endpoint: '/api/stream',
      fromCache: false,
      outcome: 'invalid_query',
      statusCode: 400,
      durationMs: Date.now() - started,
    })
    return errorResponse(ErrorCode.MISSING_QUERY, 'missing q', 400)
  }

  // ── Turnstile token verification ───────────────────────────────────────────
  const secretKey = typedEnv.TURNSTILE_SECRET_KEY
  if (secretKey && tsToken) {
    try {
      const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ secret: secretKey, response: tsToken, remoteip: ip }),
      })
      const verifyJson = await verifyRes.json() as { success: boolean }
      if (!verifyJson.success) {
        return errorResponse(ErrorCode.INVALID_QUERY, 'turnstile verification failed', 403)
      }
    } catch (err) {
      console.warn('[api/stream] turnstile verify error (allowing through):', err)
    }
  }

  // Sanitize query parameter
  const q = sanitizeQueryParam(qRaw, 500)
  
  // Validate for injection patterns (query-safe subset)
  const validation = validateQueryInput(q)
  if (!validation.valid) {
    console.warn('[api/stream] rejected query:', validation.reason, q.slice(0, 50))
    log.provenance({
      kind: 'inbound',
      callerIp: ip,
      ...(rayId && { rayId }),
      ...(country && { country }),
      query: q.slice(0, 100),
      queryType: 'unknown',
      method: req.method,
      endpoint: '/api/stream',
      fromCache: false,
      outcome: 'invalid_query',
      statusCode: 400,
      durationMs: Date.now() - started,
    })
    return errorResponse(ErrorCode.INVALID_QUERY, `invalid input: ${validation.reason}`, 400)
  }

  const query = parseQuery(q)
  if (!query) {
    log.provenance({
      kind: 'inbound',
      callerIp: ip,
      ...(rayId && { rayId }),
      ...(country && { country }),
      query: q.slice(0, 100),
      queryType: 'unknown',
      method: req.method,
      endpoint: '/api/stream',
      fromCache: false,
      outcome: 'invalid_query',
      statusCode: 422,
      durationMs: Date.now() - started,
    })
    return errorResponse(ErrorCode.INVALID_QUERY, 'invalid query', 422)
  }

  const rl = await checkRateLimit(ip, typedEnv.KV)
  if (!rl.allowed) {
    log.provenance({
      kind: 'inbound',
      callerIp: ip,
      ...(rayId && { rayId }),
      ...(country && { country }),
      query: query.normalised,
      queryType: query.type,
      method: req.method,
      endpoint: '/api/stream',
      fromCache: false,
      rateLimitRemaining: 0,
      outcome: 'rate_limited',
      statusCode: 429,
      durationMs: Date.now() - started,
    })
    return errorResponse(
      ErrorCode.RATE_LIMITED, 'rate limit exceeded', 429,
      { resetInSeconds: rl.resetInSeconds },
      {
        'X-RateLimit-Limit':     String(RATE_LIMIT.MAX_REQUESTS),
        'X-RateLimit-Remaining': String(rl.remaining),
        'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
        'Retry-After':           String(rl.resetInSeconds),
      },
    )
  }

  // ── Global concurrency cap ──────────────────────────────────────────────────
  const cc = await acquireConcurrency(typedEnv.KV)
  if (!cc.allowed) {
    log.provenance({
      kind: 'inbound',
      callerIp: ip,
      ...(rayId && { rayId }),
      ...(country && { country }),
      query: query.normalised,
      queryType: query.type,
      method: req.method,
      endpoint: '/api/stream',
      fromCache: false,
      rateLimitRemaining: rl.remaining,
      concurrencyActive: cc.active,
      outcome: 'concurrency_limited',
      statusCode: 429,
      durationMs: Date.now() - started,
    })
    return errorResponse(
      ErrorCode.RATE_LIMITED,
      'server busy — too many parallel lookups, please retry in a moment',
      429,
      { retryAfterSeconds: 5 },
      {
        'Retry-After':          '5',
        'X-Concurrency-Limit':  String(cc.limit),
        'X-Concurrency-Active': String(cc.active),
      },
    )
  }

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
        const result = await runLookup({ ...query, forceRefresh: refresh }, typedEnv, ctx)

        log.provenance({
          kind: 'inbound',
          callerIp: ip,
          ...(rayId && { rayId }),
          ...(country && { country }),
          query: query.normalised,
          queryType: query.type,
          method: req.method,
          endpoint: '/api/stream',
          fromCache: result.meta.cacheHits > 0,
          rateLimitRemaining: rl.remaining,
          concurrencyActive: cc.active,
          outcome: 'allowed',
          statusCode: 200,
          durationMs: Date.now() - started,
        })

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
        const db = typedEnv.DB
        if (db) {
          ctx.waitUntil(
            recordSearch(db, query.normalised, query.type, JSON.stringify(result), result.meta.durationMs)
              .catch(err => console.error('[api/stream] recordSearch failed', err)),
          )
        }
      } catch (err) {
        console.error('[api/stream] runLookup failed', err)
        log.provenance({
          kind: 'inbound',
          callerIp: ip,
          ...(rayId && { rayId }),
          ...(country && { country }),
          query: query.normalised,
          queryType: query.type,
          method: req.method,
          endpoint: '/api/stream',
          fromCache: false,
          rateLimitRemaining: rl.remaining,
          outcome: 'error',
          statusCode: 500,
          durationMs: Date.now() - started,
        })
        await writeLine({ type: 'error', data: { code: 'INTERNAL_ERROR', message: 'lookup failed' } })
      } finally {
        await writer.close()
        await releaseConcurrency(typedEnv.KV)
      }
    })(),
  )

  return new Response(readable, {
    headers: {
      'Content-Type':          'application/x-ndjson',
      'Transfer-Encoding':     'chunked',
      'X-Content-Type-Options':'nosniff',
      'Cache-Control':         'no-store',
      'X-RateLimit-Limit':     String(RATE_LIMIT.MAX_REQUESTS),
      'X-RateLimit-Remaining': String(rl.remaining),
      'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
    },
  })
}
