/**
 * app/api/admin/reset-breaker/route.ts
 *
 * POST /api/admin/reset-breaker
 *
 * Manually resets a circuit breaker that is stuck open.
 * Clears the :open flag and the :window_reqs / :window_fails counters
 * in KV so the next request to that source probes through immediately.
 *
 * Auth: Bearer token checked against ADMIN_TOKEN env var.
 *
 * Body:  { source: string }          — reset one breaker
 *        { source: "*" }             — reset ALL breakers
 *
 * Response 200: { reset: string[] }  — list of sources that were reset
 *
 * Errors:
 *   401  missing or invalid Authorization header
 *   400  missing / invalid body
 *   503  KV not available
 */
import { getCloudflareContext }      from '@opennextjs/cloudflare'
import { resetBreaker }              from '../../../../lib/ratelimit'
import { errorResponse, ErrorCode }  from '../../../../lib/errors'
import type { Env }                  from '../../../../lib/types'

// ─── Known sources — used when source === "*" ─────────────────────────────────

const ALL_SOURCES = [
  'internetdb',
  'ipapi',
  'bgpview',
  'rdap',
  'certsh',
  'passivedns',
  'robtex',
  'urlhaus',
  'threatfox',
  'malwarebazaar',
  'feodo',
  'sslbl',
  'nvd',
  'circl',
  'grayhatwarfare',
  'wayback',
] as const

// ─── Auth helper ──────────────────────────────────────────────────────────────

function checkAuth(req: Request, adminToken: string | undefined): boolean {
  if (!adminToken) return false   // ADMIN_TOKEN not set → always reject
  const header = req.headers.get('Authorization') ?? ''
  const [scheme, token] = header.split(' ')
  return scheme === 'Bearer' && token === adminToken
}

// ─── Route handler ────────────────────────────────────────────────────────────

export async function POST(req: Request): Promise<Response> {
  const { env }    = getCloudflareContext()
  const typedEnv   = env as unknown as Env

  // ── Auth ──────────────────────────────────────────────────────────────────
  const adminToken = typedEnv.ADMIN_TOKEN as string | undefined
  if (!checkAuth(req, adminToken)) {
    return errorResponse(ErrorCode.UNAUTHORIZED, 'valid Bearer token required', 401)
  }

  // ── KV ────────────────────────────────────────────────────────────────────
  const kv = typedEnv.KV
  if (!kv) return errorResponse(ErrorCode.INTERNAL_ERROR, 'KV not available', 503)

  // ── Body ──────────────────────────────────────────────────────────────────
  let body: { source?: unknown }
  try {
    body = await req.json()
  } catch {
    return errorResponse(ErrorCode.INVALID_QUERY, 'request body must be JSON', 400)
  }

  if (typeof body.source !== 'string' || !body.source.trim()) {
    return errorResponse(
      ErrorCode.INVALID_QUERY,
      'body.source is required — pass a source name or "*" to reset all',
      400,
    )
  }

  const source = body.source.trim()

  // ── Reset ─────────────────────────────────────────────────────────────────
  try {
    let reset: string[]

    if (source === '*') {
      await Promise.all(ALL_SOURCES.map(s => resetBreaker(s, kv)))
      reset = [...ALL_SOURCES]
    } else {
      await resetBreaker(source, kv)
      reset = [source]
    }

    console.log(`[admin] reset-breaker: reset ${reset.join(', ')}`)
    return Response.json({ reset }, { status: 200 })
  } catch (err) {
    console.error('[admin] reset-breaker failed', err)
    return errorResponse(ErrorCode.INTERNAL_ERROR, 'internal server error', 500)
  }
}
