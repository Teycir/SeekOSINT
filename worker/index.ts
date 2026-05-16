/**
 * Worker entry point — routes requests to the lookup orchestrator.
 *
 * Only GET /lookup?q= is handled. Everything else returns 404.
 * Uses @cloudflare/next-on-pages compatibility — the Next.js API route
 * at app/api/lookup/route.ts proxies through to this Worker.
 */
import type { Env } from '../lib/types'
import { parseQuery } from '../lib/validate'
import { runLookup }  from './lookup'
import { checkRateLimit } from '../lib/ratelimit'

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url)

    if (req.method !== 'GET' || !url.pathname.endsWith('/lookup')) {
      return new Response('Not found', { status: 404 })
    }

    // ── Per-IP rate limiting (100 req/hour) ────────────────────────────────
    const clientIP =
      req.headers.get('CF-Connecting-IP') ??
      req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
      'unknown'

    const rl = await checkRateLimit(clientIP, env.KV)
    if (!rl.allowed) {
      return Response.json(
        { error: 'rate limit exceeded — max 100 requests per hour' },
        {
          status: 429,
          headers: {
            'Retry-After':           String(rl.resetInSeconds),
            'X-RateLimit-Limit':     '100',
            'X-RateLimit-Remaining': String(rl.remaining),
          },
        },
      )
    }

    const q = url.searchParams.get('q')
    if (!q) {
      return Response.json({ error: 'missing q parameter' }, { status: 400 })
    }

    const query = parseQuery(q)
    if (!query) {
      return Response.json(
        { error: 'invalid query — provide a valid IPv4, IPv6, domain, or ASN' },
        { status: 422 },
      )
    }

    try {
      const result = await runLookup(query, env, ctx)
      return Response.json(result, {
        headers: {
          'Cache-Control':         'public, max-age=300', // 5 min browser cache
          'X-RateLimit-Limit':     '100',
          'X-RateLimit-Remaining': String(rl.remaining),
        },
      })
    } catch (err) {
      console.error('[worker] unhandled error', err)
      return Response.json(
        { error: 'internal server error' },
        { status: 500 },
      )
    }
  },
} satisfies ExportedHandler<Env>
