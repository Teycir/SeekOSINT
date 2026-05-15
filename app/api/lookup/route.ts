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
import type { Env } from '../../../lib/types'

export async function GET(req: Request): Promise<Response> {
  const { searchParams } = new URL(req.url)
  const q = searchParams.get('q')

  if (!q) {
    return Response.json({ error: 'missing q' }, { status: 400 })
  }

  const query = parseQuery(q)
  if (!query) {
    return Response.json(
      { error: 'invalid query — provide a valid IPv4, IPv6, domain, or ASN' },
      { status: 422 },
    )
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
    return Response.json(
      { error: 'rate limit exceeded', resetInSeconds: rl.resetInSeconds },
      {
        status: 429,
        headers: {
          'X-RateLimit-Limit':     '100',
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
          'Retry-After':           String(rl.resetInSeconds),
        },
      },
    )
  }

  // ── Lookup ──────────────────────────────────────────────────────────────────
  try {
    const result = await runLookup(query, env as unknown as Env, ctx)
    return Response.json(result, {
      headers: {
        'X-RateLimit-Limit':     '100',
        'X-RateLimit-Remaining': String(rl.remaining),
        'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + rl.resetInSeconds),
      },
    })
  } catch (err) {
    console.error('[api/lookup] unhandled error', err)
    return Response.json({ error: 'internal server error' }, { status: 500 })
  }
}
