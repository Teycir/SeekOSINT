/**
 * worker/cron.ts — Cloudflare Worker for daily saved-target re-queries.
 *
 * Deployed separately from the Pages app via wrangler.cron.toml.
 * Triggered by a cron schedule (0 3 * * * = 03:00 UTC daily).
 *
 * For each saved target:
 *   1. Re-runs the full lookup (forceRefresh=true to bypass KV cache).
 *   2. Diffs the new result against the stored snapshot.
 *   3. Persists the new snapshot and updated checked_at.
 *   4. If meaningful changes found → dispatches a webhook POST to WEBHOOK_URL
 *      (set the secret with `wrangler secret put WEBHOOK_URL`).
 *      Slack incoming webhooks, Discord webhooks, and any generic HTTPS
 *      endpoint that accepts application/json are all supported.
 *
 * Change detection covers:
 *   - New open ports / closed ports
 *   - New CVE IDs
 *   - New threat feed hits (URLhaus, ThreatFox, Feodo)
 *   - ASN change
 *   - Geo country change
 */

import { listTargets, updateTargetSnapshot } from '../lib/targets'
import { runLookup } from './lookup'
import { parseQuery } from '../lib/validate'
import type { Env, HostResult } from '../lib/types'

// ─── Change detection ─────────────────────────────────────────────────────────

interface ChangeEvent {
  targetId:   string
  query:      string
  checkedAt:  number
  changes:    string[]   // human-readable diff lines
}

function diffResults(prev: HostResult, next: HostResult): string[] {
  const changes: string[] = []

  // Ports
  const prevPorts = new Set(prev.core.internetdb.data?.ports ?? [])
  const nextPorts = new Set(next.core.internetdb.data?.ports ?? [])
  const newPorts  = [...nextPorts].filter(p => !prevPorts.has(p))
  const gонePorts = [...prevPorts].filter(p => !nextPorts.has(p))
  if (newPorts.length)  changes.push(`new open ports: ${newPorts.join(', ')}`)
  if (gонePorts.length) changes.push(`closed ports: ${gонePorts.join(', ')}`)

  // CVEs
  const prevCves = new Set(prev.vulns.map(v => v.data?.id).filter(Boolean))
  const nextCves = new Set(next.vulns.map(v => v.data?.id).filter(Boolean))
  const newCves  = [...nextCves].filter(c => !prevCves.has(c))
  if (newCves.length) changes.push(`new CVEs: ${newCves.join(', ')}`)

  // Threat intel
  const prevUrlhaus  = prev.threat.urlhaus.data?.query_status  === 'is_host'
  const nextUrlhaus  = next.threat.urlhaus.data?.query_status  === 'is_host'
  if (!prevUrlhaus && nextUrlhaus) changes.push('now listed in URLhaus')

  const prevFeodo = prev.threat.feodo.data !== null && prev.threat.feodo.status === 'ok'
  const nextFeodo = next.threat.feodo.data !== null && next.threat.feodo.status === 'ok'
  if (!prevFeodo && nextFeodo) changes.push('now listed in Feodo C2 tracker')

  const prevTfCount = prev.threat.threatfox.data?.data?.length ?? 0
  const nextTfCount = next.threat.threatfox.data?.data?.length ?? 0
  if (nextTfCount > prevTfCount) changes.push(`ThreatFox IOC count increased: ${prevTfCount} → ${nextTfCount}`)

  // ASN
  if (prev.core.bgp.data?.asn && next.core.bgp.data?.asn &&
      prev.core.bgp.data.asn !== next.core.bgp.data.asn) {
    changes.push(`ASN changed: AS${prev.core.bgp.data.asn} → AS${next.core.bgp.data.asn}`)
  }

  // Country
  if (prev.core.geo.data?.country && next.core.geo.data?.country &&
      prev.core.geo.data.country !== next.core.geo.data.country) {
    changes.push(`geo country changed: ${prev.core.geo.data.country} → ${next.core.geo.data.country}`)
  }

  return changes
}

// ─── Webhook dispatch ─────────────────────────────────────────────────────────

/**
 * POST change events to WEBHOOK_URL.
 *
 * Payload shape (works with Slack, Discord, and generic HTTP endpoints):
 *
 *   Slack / Discord compatible:
 *     { text: "…", attachments: [{…}] }
 *
 *   Generic:
 *     { events: ChangeEvent[], sentAt: number }
 *
 * We send the generic shape.  Slack / Discord users should set up a small
 * relay or use a workflow tool (Zapier, Make, n8n) to reformat it.
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
    console.log('[cron] starting saved-target sweep')

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
            const changes    = diffResults(prevResult, nextResult)
            if (changes.length > 0) {
              const event: ChangeEvent = {
                targetId:  target.id,
                query:     target.query,
                checkedAt: Math.floor(Date.now() / 1000),
                changes,
              }
              changeEvents.push(event)
              // Structured log — can be picked up by Cloudflare Log Push / Workers Analytics
              console.log('[cron] change detected', JSON.stringify(event))
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
