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
import type { Env } from '../../../lib/types'

export async function GET(req: Request): Promise<Response> {
  const { searchParams } = new URL(req.url)
  const q       = searchParams.get('q')
  const refresh = searchParams.get('refresh') === '1'

  if (!q) {
    return errorResponse(ErrorCode.MISSING_QUERY, 'missing q', 400)
  }

  const query = parseQuery(q)
  if (!query) {
    return errorResponse(ErrorCode.INVALID_QUERY, 'invalid query — provide a valid IPv4, IPv6, domain, or ASN', 422)
  }

  const { env, ctx } = getCloudflareContext()

  // ── Per-IP rate limiting ────────────────────────────────────────────────────
  // Cloudflare sets CF-Connecting-IP; fall back to X-Forwarded-For then unknown.
  const ip =
    req.headers.get('CF-Connecting-IP') ??
    req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
    'unknown'

  const rl = await checkRateLimit(ip, (env as unknown as Env).KV)

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
    const result = await runLookup({ ...query, forceRefresh: refresh }, env as unknown as Env, ctx)
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
