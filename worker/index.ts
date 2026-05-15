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

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url)

    if (req.method !== 'GET' || !url.pathname.endsWith('/lookup')) {
      return new Response('Not found', { status: 404 })
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
          'Cache-Control': 'public, max-age=300', // 5 min browser cache
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
