/**
 * app/api/recent/route.ts — returns last 10 distinct searches from D1.
 *
 * GET /api/recent          → { searches: RecentSearch[] } (default 5)
 * GET /api/recent?limit=3  → at most 3 rows
 */
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { getRecentSearches } from '../../../lib/searches'
import { sanitizeInteger } from '../../../lib/sanitize'
import type { Env } from '../../../lib/types'

export async function GET(req: Request): Promise<Response> {
  const { searchParams } = new URL(req.url)
  const limitParam = searchParams.get('limit')
  const limit = sanitizeInteger(limitParam, 5, 1, 50)

  try {
    const { env } = getCloudflareContext()
    const db = (env as unknown as Env).DB

    if (!db) {
      return Response.json({ searches: [] })
    }

    const searches = await getRecentSearches(db, limit)
    return Response.json({ searches }, {
      headers: { 'Cache-Control': 'no-store' },
    })
  } catch (err) {
    console.error('[api/recent] error', err)
    return Response.json({ searches: [] })
  }
}
