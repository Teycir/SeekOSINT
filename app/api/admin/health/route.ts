/**
 * app/api/admin/health/route.ts
 *
 * GET /api/admin/health
 *
 * Operational health snapshot — circuit breakers, rate-limit activity,
 * D1 row counts, and blocklist freshness.
 *
 * Auth: Bearer token checked against ADMIN_TOKEN env var.
 *
 * Response 200:
 * {
 *   timestamp:   number          // unix ms
 *   breakers: {
 *     summary: { open: n, halfOpen: n, closed: n }
 *     sources: BreakerStatus[]   // per-source detail
 *   }
 *   rateLimit: {
 *     activeIPs:  number         // IPs with a live KV counter (sampled)
 *   }
 *   db: {
 *     searches:     number       // total rows
 *     savedTargets: number       // total rows
 *     recentHour:   number       // searches in the last 60 min
 *   }
 *   blocklists: {
 *     feodo: { fresh: boolean; cachedAt: number | null }
 *     sslbl: { fresh: boolean; cachedAt: number | null }
 *   }
 * }
 */
import { getCloudflareContext }     from '@opennextjs/cloudflare'
import { getAllBreakerStatuses }    from '../../../../lib/ratelimit'
import { errorResponse, ErrorCode } from '../../../../lib/errors'
import type { Env }                 from '../../../../lib/types'

// Must match the source list in worker/lookup.ts
const ALL_SOURCES = [
  'internetdb', 'ipapi', 'bgpview', 'rdap', 'crtsh',
  'passivedns', 'robtex',
  'urlhaus', 'threatfox', 'malwarebazaar', 'feodo', 'sslbl',
  'nvd', 'ghw', 'wayback',
] as const

function checkAuth(req: Request, adminToken: string | undefined): boolean {
  if (!adminToken) return false
  const header = req.headers.get('Authorization') ?? ''
  const [scheme, token] = header.split(' ')
  return scheme === 'Bearer' && token === adminToken
}

export async function GET(req: Request): Promise<Response> {
  const { env } = getCloudflareContext()
  const typedEnv = env as unknown as Env

  if (!checkAuth(req, typedEnv.ADMIN_TOKEN)) {
    return errorResponse(ErrorCode.UNAUTHORIZED, 'valid Bearer token required', 401)
  }

  const kv = typedEnv.KV
  const db = typedEnv.DB

  if (!kv) return errorResponse(ErrorCode.INTERNAL_ERROR, 'KV not available', 503)

  // ── Breakers ───────────────────────────────────────────────────────────────
  const breakerStatuses = await getAllBreakerStatuses([...ALL_SOURCES], kv)
  const breakerSummary = breakerStatuses.reduce(
    (acc, b) => {
      if (b.state === 'open')      acc.open++
      else if (b.state === 'half-open') acc.halfOpen++
      else acc.closed++
      return acc
    },
    { open: 0, halfOpen: 0, closed: 0 },
  )

  // ── D1 stats ───────────────────────────────────────────────────────────────
  type CountRow = { n: number }
  const hourAgo = Math.floor(Date.now() / 1000) - 3600

  const dbStats = { searches: 0, savedTargets: 0, recentHour: 0 }
  if (db) {
    try {
      const [total, targets, recent] = await Promise.all([
        db.prepare('SELECT COUNT(*) AS n FROM searches').first<CountRow>(),
        db.prepare('SELECT COUNT(*) AS n FROM saved_targets').first<CountRow>(),
        db.prepare('SELECT COUNT(*) AS n FROM searches WHERE created_at >= ?')
          .bind(hourAgo).first<CountRow>(),
      ])
      dbStats.searches     = total?.n   ?? 0
      dbStats.savedTargets = targets?.n ?? 0
      dbStats.recentHour   = recent?.n  ?? 0
    } catch (err) {
      console.error('[health] D1 query failed', err)
    }
  }

  // ── Blocklist freshness (KV meta keys written by cron) ────────────────────
  type BlocklistMeta = { cachedAt: number }
  const ttlOneHour = 3600 * 1000

  async function checkBlocklist(key: string) {
    try {
      const raw = await kv.get(key, 'text')
      if (!raw) return { fresh: false, cachedAt: null }
      const meta = JSON.parse(raw) as BlocklistMeta
      const age  = Date.now() - meta.cachedAt
      return { fresh: age < ttlOneHour, cachedAt: meta.cachedAt }
    } catch (err) {
      console.warn('[health] blocklist meta parse failed for', key, err)
      return { fresh: false, cachedAt: null }
    }
  }

  const [feodoBl, sslblBl] = await Promise.all([
    checkBlocklist('blocklist_meta:feodo'),
    checkBlocklist('blocklist_meta:sslbl'),
  ])

  // ── Response ───────────────────────────────────────────────────────────────
  return Response.json({
    timestamp: Date.now(),
    breakers: {
      summary: breakerSummary,
      sources: breakerStatuses,
    },
    db: dbStats,
    blocklists: {
      feodo: feodoBl,
      sslbl: sslblBl,
    },
  }, {
    headers: { 'Cache-Control': 'no-store' },
  })
}
