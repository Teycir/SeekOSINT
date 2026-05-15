/**
 * app/api/recent/route.ts — returns last 10 distinct searches from D1.
 *
 * GET /api/recent          → { searches: RecentSearch[] }
 * GET /api/recent?limit=5  → at most 5 rows
 */
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { getRecentSearches } from '../../../lib/searches'
import type { Env } from '../../../lib/types'

export async function GET(req: Request): Promise<Response> {
  const { searchParams } = new URL(req.url)
  const limit = Math.min(Number(searchParams.get('limit') ?? 10), 50)

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
