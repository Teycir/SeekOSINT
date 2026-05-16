/**
 * app/api/lookup/route.ts — thin proxy to the Worker.
 *
 * Validates input, enforces per-IP rate limit, delegates to runLookup().
 * Runs on the Node.js runtime via @opennextjs/cloudflare (Workers).
 * NOTE: Do NOT set `export const runtime = 'edge'` — @opennextjs/cloudflare
 * requires the Node.js runtime. The edge runtime breaks getCloudflareContext().
 */
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { parseQuery } from '../../../lib/validate'
import { sanitizeQueryParam, validateQueryInput } from '../../../lib/sanitize'
import { checkRateLimit, acquireConcurrency, releaseConcurrency } from '../../../lib/ratelimit'
import { runLookup } from '../../../worker/lookup'
import { errorResponse, ErrorCode } from '../../../lib/errors'
import { recordSearch } from '../../../lib/searches'
import { verifyTurnstileToken } from '../../../lib/turnstile'
import { RATE_LIMIT } from '../../../lib/config'
import { log, extractCallerIp } from '../../../lib/logger'
import type { Env } from '../../../lib/types'

export async function GET(req: Request): Promise<Response> {
  const started = Date.now()
  const { searchParams } = new URL(req.url)
  const qRaw    = searchParams.get('q')
  const refresh = searchParams.get('refresh') === '1'
  const tsToken = searchParams.get('ts') // Turnstile token

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
      endpoint: '/api/lookup',
      fromCache: false,
      outcome: 'invalid_query',
      statusCode: 400,
      durationMs: Date.now() - started,
    })
    return errorResponse(ErrorCode.MISSING_QUERY, 'missing q', 400)
  }
  
  // Sanitize query parameter
  const q = sanitizeQueryParam(qRaw, 500)
  
  // Validate for injection patterns (query-safe subset — no false positives on domains)
  const validation = validateQueryInput(q)
  if (!validation.valid) {
    console.warn('[api/lookup] rejected query:', validation.reason, q.slice(0, 50))
    log.provenance({
      kind: 'inbound',
      callerIp: ip,
      ...(rayId && { rayId }),
      ...(country && { country }),
      query: q.slice(0, 100),
      queryType: 'unknown',
      method: req.method,
      endpoint: '/api/lookup',
      fromCache: false,
      outcome: 'invalid_query',
      statusCode: 400,
      durationMs: Date.now() - started,
    })
    return errorResponse(ErrorCode.INVALID_QUERY, `invalid input: ${validation.reason}`, 400)
  }

  const { env, ctx } = getCloudflareContext()
  const typedEnv = env as unknown as Env

  // ── Turnstile verification (before parseQuery — prevents format-oracle leakage) ──
  const ts = await verifyTurnstileToken(tsToken, typedEnv.TURNSTILE_SECRET_KEY, ip)
  if (!ts.success) {
    log.provenance({
      kind: 'inbound',
      callerIp: ip,
      ...(rayId && { rayId }),
      ...(country && { country }),
      query: q.slice(0, 100),
      queryType: 'unknown',
      method: req.method,
      endpoint: '/api/lookup',
      fromCache: false,
      turnstilePassed: false,
      outcome: 'bot_blocked',
      statusCode: 403,
      durationMs: Date.now() - started,
    })
    return errorResponse(ErrorCode.RATE_LIMITED, `bot challenge failed: ${ts.reason}`, 403)
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
      endpoint: '/api/lookup',
      fromCache: false,
      turnstilePassed: true,
      outcome: 'invalid_query',
      statusCode: 422,
      durationMs: Date.now() - started,
    })
    return errorResponse(ErrorCode.INVALID_QUERY, 'invalid query — provide a valid IPv4, IPv6, domain, or ASN', 422)
  }

  // ── Per-IP rate limiting ────────────────────────────────────────────────────
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
      endpoint: '/api/lookup',
      fromCache: false,
      turnstilePassed: true,
      rateLimitRemaining: 0,
      outcome: 'rate_limited',
      statusCode: 429,
      durationMs: Date.now() - started,
    })
    return errorResponse(
      ErrorCode.RATE_LIMITED,
      'rate limit exceeded',
      429,
      { resetInSeconds: rl.resetInSeconds },
      {
        'X-RateLimit-Limit':     String(RATE_LIMIT.MAX_REQUESTS),
        'X-RateLimit-Remaining': '0',
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
      endpoint: '/api/lookup',
      fromCache: false,
      turnstilePassed: true,
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
        'Retry-After':         '5',
        'X-Concurrency-Limit': String(cc.limit),
        'X-Concurrency-Active': String(cc.active),
      },
    )
  }

  // ── Lookup ──────────────────────────────────────────────────────────────────
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
      endpoint: '/api/lookup',
      fromCache: result.meta.cacheHits > 0,
      turnstilePassed: true,
      rateLimitRemaining: rl.remaining,
      concurrencyActive: cc.active,
      outcome: 'allowed',
      statusCode: 200,
      durationMs: Date.now() - started,
    })

    // Fire-and-forget: persist search to D1 (does not block the response)
    const db = typedEnv.DB
    if (db) {
      ctx.waitUntil(
        recordSearch(db, query.normalised, query.type, JSON.stringify(result), result.meta.durationMs)
          .catch(err => console.error('[api/lookup] recordSearch failed', err)),
      )
    }

    return Response.json(result, {
      headers: {
        'X-RateLimit-Limit':     String(RATE_LIMIT.MAX_REQUESTS),
        'X-RateLimit-Remaining': String(rl.remaining),
        'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
      },
    })
  } catch (err) {
    console.error('[api/lookup] unhandled error', err)
    log.provenance({
      kind: 'inbound',
      callerIp: ip,
      ...(rayId && { rayId }),
      ...(country && { country }),
      query: query.normalised,
      queryType: query.type,
      method: req.method,
      endpoint: '/api/lookup',
      fromCache: false,
      turnstilePassed: true,
      rateLimitRemaining: rl.remaining,
      outcome: 'error',
      statusCode: 500,
      durationMs: Date.now() - started,
    })
    return errorResponse(ErrorCode.INTERNAL_ERROR, 'internal server error', 500)
  } finally {
    await releaseConcurrency(typedEnv.KV)
  }
}
