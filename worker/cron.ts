/**
 * worker/cron.ts — two scheduled jobs in one Worker.
 *
 * 1. Blocklist refresh (runs on every trigger)
 *    Downloads Feodo and SSLBL from abuse.ch, upserts into D1 tables.
 *    Skips each list if refreshed within the last hour (blocklist_meta).
 *
 * 2. Saved-target sweep (runs on every trigger)
 *    Re-queries all saved targets, diffs results, fires webhook on changes.
 *    Safe to run hourly — runLookup respects KV cache so upstream is only
 *    hit when forceRefresh=true and the KV TTL has expired.
 */

import { listTargets, updateTargetSnapshot } from '../lib/targets'
import { runLookup } from './lookup'
import { parseQuery } from '../lib/validate'
import { safeJson } from '../lib/results'
import { diffHostResults, summariseDiff } from '../lib/diff'
import type { TargetDiff } from '../lib/diff'
import type { Env, FeodoEntry, HostResult, SSLBLEntry } from '../lib/types'

// ─── Blocklist refresh ────────────────────────────────────────────────────────

const BLOCKLIST_REFRESH_INTERVAL = 60 * 60  // 1 hour in seconds

async function shouldRefresh(db: D1Database, name: string): Promise<boolean> {
  try {
    const row = await db
      .prepare(`SELECT refreshed_at FROM blocklist_meta WHERE name = ?`)
      .bind(name)
      .first<{ refreshed_at: number }>()
    if (!row) return true
    return (Math.floor(Date.now() / 1000) - row.refreshed_at) > BLOCKLIST_REFRESH_INTERVAL
  } catch (err) {
    console.error('[cron] shouldRefresh query failed for', name, err)
    return true  // assume stale on error
  }
}

async function markRefreshed(db: D1Database, name: string): Promise<void> {
  await db
    .prepare(
      `INSERT INTO blocklist_meta (name, refreshed_at) VALUES (?, ?)
       ON CONFLICT(name) DO UPDATE SET refreshed_at = excluded.refreshed_at`,
    )
    .bind(name, Math.floor(Date.now() / 1000))
    .run()
}


async function refreshFeodo(db: D1Database): Promise<void> {
  if (!(await shouldRefresh(db, 'feodo'))) {
    console.log('[cron] feodo: fresh — skipping')
    return
  }

  const res = await fetch(
    'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
    { signal: AbortSignal.timeout(20000) },
  )
  if (!res.ok) throw new Error(`feodo download HTTP ${res.status}`)

  const list = await safeJson<FeodoEntry[]>(
    res,
    (v): v is FeodoEntry[] => Array.isArray(v),
    'feodo-blocklist',
  )

  const CHUNK = 100
  for (let i = 0; i < list.length; i += CHUNK) {
    const chunk = list.slice(i, i + CHUNK)
    await db.batch(
      chunk.map(e =>
        db.prepare(
          `INSERT INTO feodo_blocklist
             (ip_address, port, status, hostname, as_number, as_name,
              country, first_seen, last_seen, malware)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(ip_address) DO UPDATE SET
             port=excluded.port, status=excluded.status,
             hostname=excluded.hostname, as_number=excluded.as_number,
             as_name=excluded.as_name, country=excluded.country,
             first_seen=excluded.first_seen, last_seen=excluded.last_seen,
             malware=excluded.malware`,
        ).bind(
          e.ip_address, e.port ?? null, e.status ?? null,
          e.hostname ?? null, e.as_number ?? null, e.as_name ?? null,
          e.country ?? null, e.first_seen ?? null, e.last_seen ?? null,
          e.malware ?? null,
        ),
      ),
    )
  }

  await markRefreshed(db, 'feodo')
  console.log(`[cron] feodo: upserted ${list.length} entries`)
}

async function refreshSSLBL(db: D1Database): Promise<void> {
  if (!(await shouldRefresh(db, 'sslbl'))) {
    console.log('[cron] sslbl: fresh — skipping')
    return
  }

  const res = await fetch(
    'https://sslbl.abuse.ch/blacklist/sslblacklist.json',
    { signal: AbortSignal.timeout(20000) },
  )
  if (!res.ok) throw new Error(`sslbl download HTTP ${res.status}`)

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const json = await safeJson<any>(
    res,
    (v): v is Record<string, unknown> => typeof v === 'object' && v !== null,
    'sslbl-blocklist',
  )
  const list = (json.results ?? json) as SSLBLEntry[]

  const CHUNK = 100
  for (let i = 0; i < list.length; i += CHUNK) {
    const chunk = list.slice(i, i + CHUNK)
    await db.batch(
      chunk.map(e =>
        db.prepare(
          `INSERT INTO sslbl_blocklist
             (sha1, listing_date, listing_time, suspicious_reason,
              dst_ip, dst_port, subject)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(sha1) DO UPDATE SET
             listing_date=excluded.listing_date,
             listing_time=excluded.listing_time,
             suspicious_reason=excluded.suspicious_reason,
             dst_ip=excluded.dst_ip, dst_port=excluded.dst_port,
             subject=excluded.subject`,
        ).bind(
          e.SHA1, e.Listingdate ?? null, e.Listingtime ?? null,
          e.SuspiciousReason ?? null,
          (e as unknown as { DstIP?: string }).DstIP ?? null,
          (e as unknown as { DstPort?: number }).DstPort ?? null,
          (e as unknown as { Subject?: string }).Subject ?? null,
        ),
      ),
    )
  }

  await markRefreshed(db, 'sslbl')
  console.log(`[cron] sslbl: upserted ${list.length} entries`)
}

async function refreshBlocklists(db: D1Database): Promise<void> {
  await Promise.allSettled([
    refreshFeodo(db).catch(err => console.error('[cron] feodo refresh failed', err)),
    refreshSSLBL(db).catch(err => console.error('[cron] sslbl refresh failed', err)),
  ])
}


// ─── Typed change event (replaces the old string-based ChangeEvent) ───────────

interface ChangeEvent {
  targetId:   string
  query:      string
  checkedAt:  number
  summary:    string       // human-readable for logs / Slack relay
  diff:       TargetDiff   // structured — consumers can branch on change types
}

// ─── Webhook dispatch ─────────────────────────────────────────────────────────

/**
 * POST change events to WEBHOOK_URL.
 *
 * Generic payload shape — structured diff is included so consumers can
 * branch on specific change types without parsing string lines.
 *
 *   { sentAt: number, events: ChangeEvent[] }
 *
 * Slack / Discord users should set up a small relay or use a workflow tool
 * (Zapier, Make, n8n) to reformat; the `summary` field on each event
 * contains the human-readable text for that purpose.
 *
 * Errors here are non-fatal — the snapshot is already persisted.
 */
async function dispatchWebhook(
  webhookUrl: string,
  events:     ChangeEvent[],
): Promise<void> {
  try {
    const payload = {
      sentAt: Math.floor(Date.now() / 1000),
      events,
    }

    const res = await fetch(webhookUrl, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    })

    if (!res.ok) {
      console.error(`[cron] webhook POST failed: HTTP ${res.status}`)
    } else {
      console.log(`[cron] webhook dispatched — ${events.length} change event(s)`)
    }
  } catch (err) {
    console.error('[cron] webhook dispatch error', err)
  }
}

// ─── Cron handler ─────────────────────────────────────────────────────────────

export default {
  async scheduled(
    _event:   ScheduledEvent,
    env:      Env,
    ctx:      ExecutionContext,
  ): Promise<void> {
    const started = Date.now()
    console.log('[cron] starting')

    // ── 1. Blocklist refresh ───────────────────────────────────────────────
    await refreshBlocklists(env.DB)

    // ── 2. Saved-target sweep ─────────────────────────────────────────────
    const targets = await listTargets(env.DB).catch(err => {
      console.error('[cron] listTargets failed', err)
      return []
    })

    if (targets.length === 0) {
      console.log('[cron] no saved targets — nothing to do')
      return
    }

    console.log(`[cron] checking ${targets.length} targets`)

    const changeEvents: ChangeEvent[] = []

    // Process sequentially to avoid hammering upstream APIs
    for (const target of targets) {
      try {
        const query = parseQuery(target.query)
        if (!query) {
          console.warn(`[cron] skipping unparseable query: ${target.query}`)
          continue
        }

        const nextResult = await runLookup({ ...query, forceRefresh: true }, env, ctx)
        const nextJson   = JSON.stringify(nextResult)

        // Diff against stored snapshot if one exists
        if (target.result_json) {
          try {
            const prevResult = JSON.parse(target.result_json) as HostResult
            const diff       = diffHostResults(prevResult, nextResult)

            if (diff.hasChanges) {
              const event: ChangeEvent = {
                targetId: target.id,
                query:    target.query,
                checkedAt: diff.diffedAt,
                summary:  summariseDiff(diff, target.query),
                diff,
              }
              changeEvents.push(event)
              // Structured log — can be picked up by Cloudflare Log Push
              console.log('[cron] change detected', JSON.stringify({
                targetId: target.id,
                query:    target.query,
                ports:    diff.ports.length,
                cves:     diff.cves.length,
                threats:  diff.threats.length,
                geo:      diff.geo.length,
                certExpiry: diff.certExpiry.length,
                riskDelta:  diff.risk?.delta ?? null,
              }))
            }
          } catch (parseErr) {
            console.warn(`[cron] could not parse stored snapshot for ${target.query}`, parseErr)
          }
        }

        // Persist fresh snapshot regardless of diff outcome
        await updateTargetSnapshot(env.DB, target.id, nextJson)
        console.log(`[cron] updated snapshot for ${target.query}`)
      } catch (err) {
        console.error(`[cron] lookup failed for ${target.query}`, err)
      }
    }

    // ── Webhook dispatch ───────────────────────────────────────────────────
    if (changeEvents.length > 0 && env.WEBHOOK_URL) {
      // ctx.waitUntil so the Worker doesn't terminate before the POST completes
      ctx.waitUntil(dispatchWebhook(env.WEBHOOK_URL, changeEvents))
    }

    console.log(
      `[cron] sweep complete — ${targets.length} targets, ` +
      `${changeEvents.length} with changes, ${Date.now() - started}ms`,
    )
  },
}
