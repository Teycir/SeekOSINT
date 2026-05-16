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
import { checkRateLimit } from '../../../lib/ratelimit'
import { runLookup } from '../../../worker/lookup'
import { errorResponse, ErrorCode } from '../../../lib/errors'
import { recordSearch } from '../../../lib/searches'
import { verifyTurnstileToken } from '../../../lib/turnstile'
import type { Env } from '../../../lib/types'

export async function GET(req: Request): Promise<Response> {
  const { searchParams } = new URL(req.url)
  const q       = searchParams.get('q')
  const refresh = searchParams.get('refresh') === '1'
  const tsToken = searchParams.get('ts') // Turnstile token

  if (!q) {
    return errorResponse(ErrorCode.MISSING_QUERY, 'missing q', 400)
  }

  const query = parseQuery(q)
  if (!query) {
    return errorResponse(ErrorCode.INVALID_QUERY, 'invalid query — provide a valid IPv4, IPv6, domain, or ASN', 422)
  }

  const { env, ctx } = getCloudflareContext()
  const typedEnv = env as unknown as Env

  // ── Turnstile verification ──────────────────────────────────────────────────
  const ip =
    req.headers.get('CF-Connecting-IP') ??
    req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
    'unknown'

  const ts = await verifyTurnstileToken(tsToken, typedEnv.TURNSTILE_SECRET_KEY, ip)
  if (!ts.success) {
    return errorResponse(ErrorCode.RATE_LIMITED, `bot challenge failed: ${ts.reason}`, 403)
  }

  // ── Per-IP rate limiting ────────────────────────────────────────────────────
  const rl = await checkRateLimit(ip, typedEnv.KV)

  if (!rl.allowed) {
    return errorResponse(
      ErrorCode.RATE_LIMITED,
      'rate limit exceeded',
      429,
      { resetInSeconds: rl.resetInSeconds },
      {
        'X-RateLimit-Limit':     '100',
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
        'Retry-After':           String(rl.resetInSeconds),
      },
    )
  }

  // ── Lookup ──────────────────────────────────────────────────────────────────
  try {
    const result = await runLookup({ ...query, forceRefresh: refresh }, typedEnv, ctx)

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
        'X-RateLimit-Limit':     '100',
        'X-RateLimit-Remaining': String(rl.remaining),
        'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
      },
    })
  } catch (err) {
    console.error('[api/lookup] unhandled error', err)
    return errorResponse(ErrorCode.INTERNAL_ERROR, 'internal server error', 500)
  }
}
