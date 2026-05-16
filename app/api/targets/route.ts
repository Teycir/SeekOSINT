/**
 * app/api/targets/route.ts
 *
 * GET    /api/targets  — list saved targets with riskScore + lastDiff summary
 * POST   /api/targets  — save a target { query, label?, notes? }
 *                        auto-prunes oldest entries when count > TARGETS_SOFT_CAP
 * DELETE /api/targets  — purge ALL saved targets
 */
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { parseQuery } from '../../../lib/validate'
import { sanitizeLabel, sanitizeNotes, validateQueryInput, validateInput } from '../../../lib/sanitize'
import { saveTarget, listTargets, purgeAllTargets, countTargets, purgeOldestTargets } from '../../../lib/targets'
import { diffHostResults } from '../../../lib/diff'
import type { TargetDiff } from '../../../lib/diff'
import { errorResponse, ErrorCode } from '../../../lib/errors'
import type { Env, HostResult, RiskScore } from '../../../lib/types'
import { computeRiskScore } from '../../../lib/risk'

/**
 * Soft cap on saved targets per user (browser-local, single-tenant deployment).
 * When POST would push the count above this, the oldest entries are pruned
 * automatically so the list never balloons unboundedly.
 *
 * Warn threshold  — shown in the UI as a yellow banner (TARGETS_WARN_THRESHOLD)
 * Hard prune at   — TARGETS_SOFT_CAP; oldest entries are culled to keep it at cap
 */
export const TARGETS_SOFT_CAP       = 100
export const TARGETS_WARN_THRESHOLD = 75

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

    return Response.json({
      targets,
      meta: {
        count:         targets.length,
        softCap:       TARGETS_SOFT_CAP,
        warnThreshold: TARGETS_WARN_THRESHOLD,
        nearingCap:    targets.length >= TARGETS_WARN_THRESHOLD,
      },
    })
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
  
  // Validate query for injection patterns (query-safe subset, not free-text rules)
  const validation = validateQueryInput(body.query)
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

  // Validate free-text fields for injection (full check, not query-safe subset)
  if (label) {
    const labelCheck = validateInput(label)
    if (!labelCheck.valid) {
      return errorResponse(ErrorCode.INVALID_QUERY, `invalid label: ${labelCheck.reason}`, 400)
    }
  }
  if (notes) {
    const notesCheck = validateInput(notes)
    if (!notesCheck.valid) {
      return errorResponse(ErrorCode.INVALID_QUERY, `invalid notes: ${notesCheck.reason}`, 400)
    }
  }

  try {
    const { env } = getCloudflareContext()
    const db = (env as unknown as Env).DB
    if (!db) return errorResponse(ErrorCode.INTERNAL_ERROR, 'D1 not available', 503)

    // ── Auto-prune: keep the list at or below the soft cap ─────────────────
    // Count BEFORE saving (the new row hasn't been inserted yet).
    // If we're already at the cap, prune the oldest to make room.
    let prunedIds: string[] = []
    const currentCount = await countTargets(db)
    if (currentCount >= TARGETS_SOFT_CAP) {
      // Prune enough to drop to cap - 1, then the new save brings it back to cap.
      const excess = currentCount - TARGETS_SOFT_CAP + 1
      prunedIds = await purgeOldestTargets(db, excess)
    }

    const id = await saveTarget(db, parsed.normalised, label, notes)
    return Response.json(
      { id, query: parsed.normalised, prunedIds },
      { status: 201 },
    )
  } catch (err) {
    console.error('[api/targets] POST failed', err)
    return errorResponse(ErrorCode.INTERNAL_ERROR, 'internal server error', 500)
  }
}

export async function DELETE(): Promise<Response> {
  try {
    const { env } = getCloudflareContext()
    const db = (env as unknown as Env).DB
    if (!db) return errorResponse(ErrorCode.INTERNAL_ERROR, 'D1 not available', 503)

    const deleted = await purgeAllTargets(db)
    return Response.json({ deleted })
  } catch (err) {
    console.error('[api/targets] DELETE failed', err)
    return errorResponse(ErrorCode.INTERNAL_ERROR, 'internal server error', 500)
  }
}
