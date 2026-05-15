/**
 * app/api/lookup/route.ts — thin edge proxy to the Worker.
 *
 * Validates input, delegates to runLookup(), returns JSON.
 * Runs on the Cloudflare edge runtime via @cloudflare/next-on-pages.
 */
export const runtime = 'edge'

import { getRequestContext } from '@cloudflare/next-on-pages'
import { parseQuery } from '../../../lib/validate'
import { runLookup }  from '../../../worker/lookup'
import type { Env }   from '../../../lib/types'

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

  const { env, ctx } = getRequestContext()

  try {
    const result = await runLookup(query, env as unknown as Env, ctx)
    return Response.json(result)
  } catch (err) {
    console.error('[api/lookup] unhandled error', err)
    return Response.json({ error: 'internal server error' }, { status: 500 })
  }
}
