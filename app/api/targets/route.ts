/**
 * app/api/targets/route.ts
 *
 * GET  /api/targets  — list saved targets with riskScore + lastDiff summary
 * POST /api/targets  — save a target { query, label?, notes? }
 */
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { parseQuery } from '../../../lib/validate'
import { sanitizeLabel, sanitizeNotes, validateInput } from '../../../lib/sanitize'
import { saveTarget, listTargets } from '../../../lib/targets'
import { diffHostResults } from '../../../lib/diff'
import type { TargetDiff } from '../../../lib/diff'
import { errorResponse, ErrorCode } from '../../../lib/errors'
import type { Env, HostResult, RiskScore } from '../../../lib/types'
import { computeRiskScore } from '../../../lib/risk'

// Shape returned per target — enriches SavedTarget with parsed signals
interface TargetSummary {
  id:         string
  query:      string
  label:      string | null
  notes:      string | null
  checked_at: number | null
  created_at: number
  riskScore:  RiskScore | null
  lastDiff:   TargetDiff | null
}

export async function GET(): Promise<Response> {
  try {
    const { env } = getCloudflareContext()
    const db = (env as unknown as Env).DB
    if (!db) return errorResponse(ErrorCode.INTERNAL_ERROR, 'D1 not available', 503)

    const rows = await listTargets(db)

    const targets: TargetSummary[] = rows.map(row => {
      let riskScore: RiskScore | null = null
      let lastDiff:  TargetDiff  | null = null

      if (row.result_json) {
        try {
          const parsed = JSON.parse(row.result_json) as HostResult

          // Risk score — recompute from stored snapshot so the score is
          // always consistent with the current risk formula, even if the
          // snapshot was saved under an older version.
          riskScore = computeRiskScore(parsed)

          // Last diff — reconstruct by diffing the snapshot against itself
          // to get an empty diff structure, then attach whatever was stored.
          // We persist the full diff JSON alongside result_json in future;
          // for snapshots that don't have it yet, lastDiff stays null.
          //
          // Note: if we later store last_diff_json in the DB column, swap
          // this for: lastDiff = JSON.parse(row.last_diff_json)
          const stored = (parsed as unknown as { _lastDiff?: TargetDiff })._lastDiff
          if (stored) {
            lastDiff = stored
          }
        } catch (err) {
          // Malformed snapshot — surface null rather than 500
          console.warn('[api/targets] failed to parse result_json for target', row.id, err)
        }
      }

      return {
        id:         row.id,
        query:      row.query,
        label:      row.label,
        notes:      row.notes,
        checked_at: row.checked_at,
        created_at: row.created_at,
        riskScore,
        lastDiff,
      }
    })

    return Response.json({ targets })
  } catch (err) {
    console.error('[api/targets] GET failed', err)
    const message = err instanceof Error ? err.message : 'internal server error'
    return errorResponse(ErrorCode.INTERNAL_ERROR, message, 500)
  }
}

export async function POST(req: Request): Promise<Response> {
  let body: { query?: unknown; label?: unknown; notes?: unknown }
  try {
    body = await req.json()
  } catch (err) {
    console.error('[api/targets] JSON parse failed:', err)
    return errorResponse(ErrorCode.INVALID_QUERY, 'request body must be JSON', 400)
  }

  if (typeof body.query !== 'string' || !body.query.trim()) {
    return errorResponse(ErrorCode.INVALID_QUERY, 'query is required', 400)
  }
  
  // Validate for injection patterns before parsing
  const validation = validateInput(body.query)
  if (!validation.valid) {
    console.warn('[api/targets] rejected query:', validation.reason)
    return errorResponse(ErrorCode.INVALID_QUERY, `invalid input: ${validation.reason}`, 400)
  }

  const parsed = parseQuery(body.query)
  if (!parsed) {
    return errorResponse(ErrorCode.INVALID_QUERY, 'invalid query — must be IPv4, IPv6, domain, or ASN', 422)
  }

  const label = typeof body.label === 'string' ? sanitizeLabel(body.label, 100) : null
  const notes = typeof body.notes === 'string' ? sanitizeNotes(body.notes, 500) : null

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
