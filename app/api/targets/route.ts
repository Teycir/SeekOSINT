/**
 * app/api/targets/route.ts
 *
 * GET  /api/targets  — list all saved targets (newest first)
 * POST /api/targets  — save a target { query, label?, notes? }
 */
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { parseQuery } from '../../../lib/validate'
import { saveTarget, listTargets } from '../../../lib/targets'
import { errorResponse, ErrorCode } from '../../../lib/errors'
import type { Env } from '../../../lib/types'

export async function GET(): Promise<Response> {
  try {
    const { env } = getCloudflareContext()
    const db = (env as unknown as Env).DB
    if (!db) return errorResponse(ErrorCode.INTERNAL_ERROR, 'D1 not available', 503)
    const targets = await listTargets(db)
    return Response.json({ targets })
  } catch (err) {
    console.error('[api/targets] GET failed', err)
    return errorResponse(ErrorCode.INTERNAL_ERROR, 'internal server error', 500)
  }
}

export async function POST(req: Request): Promise<Response> {
  let body: { query?: unknown; label?: unknown; notes?: unknown }
  try {
    body = await req.json()
  } catch {
    return errorResponse(ErrorCode.INVALID_QUERY, 'request body must be JSON', 400)
  }

  if (typeof body.query !== 'string' || !body.query.trim()) {
    return errorResponse(ErrorCode.INVALID_QUERY, 'query is required', 400)
  }

  const parsed = parseQuery(body.query)
  if (!parsed) {
    return errorResponse(ErrorCode.INVALID_QUERY, 'invalid query — must be IPv4, IPv6, domain, or ASN', 422)
  }

  const label = typeof body.label === 'string' ? body.label.slice(0, 100) : null
  const notes = typeof body.notes === 'string' ? body.notes.slice(0, 500) : null

  try {
    const { env } = getCloudflareContext()
    const db = (env as unknown as Env).DB
    if (!db) return errorResponse(ErrorCode.INTERNAL_ERROR, 'D1 not available', 503)

    const id = await saveTarget(db, parsed.normalised, label, notes)
    return Response.json({ id, query: parsed.normalised }, { status: 201 })
  } catch (err) {
    console.error('[api/targets] POST failed', err)
    return errorResponse(ErrorCode.INTERNAL_ERROR, 'internal server error', 500)
  }
}
