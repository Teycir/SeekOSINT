/**
 * lib/diff.ts — typed change detection between two HostResult snapshots.
 *
 * Produces a TargetDiff that is:
 *  - Structured: consumers can branch on specific change types
 *  - Serialisable: safe to JSON.stringify into D1 or a webhook payload
 *  - Deterministic: same inputs always produce the same output
 *
 * Called by the cron after each re-query; the result is stored in
 * saved_targets.last_diff and emitted to WEBHOOK_URL when non-empty.
 */

import type { HostResult } from './types'
import { computeRiskScore } from './risk'

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PortChange {
  port:      number
  direction: 'opened' | 'closed'
}

export interface CveChange {
  id:        string
  direction: 'appeared' | 'resolved'
  severity?: string   // CRITICAL | HIGH | MEDIUM | LOW | NONE
  score?:    number
}

export interface ThreatChange {
  feed:      'urlhaus' | 'feodo' | 'threatfox' | 'sslbl'
  direction: 'appeared' | 'resolved'
  detail?:   string   // malware family, IOC count change, etc.
}

export interface GeoChange {
  field: 'country' | 'asn' | 'hostname'
  prev:  string
  next:  string
}

export interface CertExpiryChange {
  commonName: string
  notAfter:   string  // ISO date string from crt.sh
  daysLeft:   number  // negative = already expired
}

export interface RiskChange {
  prev:     number
  next:     number
  delta:    number   // next - prev (negative = improved)
}

export interface TargetDiff {
  /** Unix seconds when this diff was computed */
  diffedAt:    number
  hasChanges:  boolean
  ports:       PortChange[]
  cves:        CveChange[]
  threats:     ThreatChange[]
  geo:         GeoChange[]
  certExpiry:  CertExpiryChange[]
  risk:        RiskChange | null  // null when both snapshots lack a score
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ok<T>(r: { status: string; data: T | null }): r is { status: string; data: T } {
  return (r.status === 'ok' || r.status === 'cached') && r.data !== null
}

const CERT_EXPIRY_WARN_DAYS = 30

/** Days until a certificate expires (negative if already past). */
function daysUntil(isoDate: string): number {
  const expiry = new Date(isoDate).getTime()
  return Math.floor((expiry - Date.now()) / 86_400_000)
}

// ─── Main diff function ───────────────────────────────────────────────────────

export function diffHostResults(prev: HostResult, next: HostResult): TargetDiff {
  const ports:      PortChange[]       = []
  const cves:       CveChange[]        = []
  const threats:    ThreatChange[]     = []
  const geo:        GeoChange[]        = []
  const certExpiry: CertExpiryChange[] = []

  // ── Ports ─────────────────────────────────────────────────────────────────

  const prevPorts = new Set(prev.core.internetdb.data?.ports ?? [])
  const nextPorts = new Set(next.core.internetdb.data?.ports ?? [])

  for (const p of nextPorts) {
    if (!prevPorts.has(p)) ports.push({ port: p, direction: 'opened' })
  }
  for (const p of prevPorts) {
    if (!nextPorts.has(p)) ports.push({ port: p, direction: 'closed' })
  }

  // ── CVEs ──────────────────────────────────────────────────────────────────

  const prevCveMap = new Map(
    prev.vulns
      .filter(v => ok(v) && v.data.id)
      .map(v => [v.data!.id, v.data!]),
  )
  const nextCveMap = new Map(
    next.vulns
      .filter(v => ok(v) && v.data.id)
      .map(v => [v.data!.id, v.data!]),
  )

  for (const [id, cve] of nextCveMap) {
    if (!prevCveMap.has(id)) {
      cves.push({
        id,
        direction: 'appeared',
        ...(cve.cvssV3Severity && { severity: cve.cvssV3Severity }),
        ...(cve.cvssV3Score !== undefined && { score: cve.cvssV3Score }),
      })
    }
  }
  for (const [id] of prevCveMap) {
    if (!nextCveMap.has(id)) {
      cves.push({ id, direction: 'resolved' })
    }
  }

  // ── Threat intel ──────────────────────────────────────────────────────────

  // URLhaus
  const prevUH = prev.threat.urlhaus.data?.query_status === 'is_host'
  const nextUH = next.threat.urlhaus.data?.query_status === 'is_host'
  if (!prevUH && nextUH) threats.push({ feed: 'urlhaus', direction: 'appeared' })
  if (prevUH && !nextUH) threats.push({ feed: 'urlhaus', direction: 'resolved' })

  // Feodo
  const prevFeodo = ok(prev.threat.feodo) && prev.threat.feodo.data !== null
  const nextFeodo = ok(next.threat.feodo) && next.threat.feodo.data !== null
  if (!prevFeodo && nextFeodo) {
    threats.push({
      feed: 'feodo',
      direction: 'appeared',
      detail: next.threat.feodo.data?.malware ?? undefined,
    })
  }
  if (prevFeodo && !nextFeodo) threats.push({ feed: 'feodo', direction: 'resolved' })

  // SSLBL
  const prevSSL = ok(prev.threat.sslbl) && prev.threat.sslbl.data.length > 0
  const nextSSL = ok(next.threat.sslbl) && next.threat.sslbl.data.length > 0
  if (!prevSSL && nextSSL) threats.push({ feed: 'sslbl', direction: 'appeared' })
  if (prevSSL && !nextSSL) threats.push({ feed: 'sslbl', direction: 'resolved' })

  // ThreatFox — track count changes
  const prevTF = prev.threat.threatfox.data?.data?.length ?? 0
  const nextTF = next.threat.threatfox.data?.data?.length ?? 0
  if (nextTF > prevTF) {
    threats.push({
      feed: 'threatfox',
      direction: 'appeared',
      detail: `IOC count ${prevTF} → ${nextTF}`,
    })
  }
  if (prevTF > 0 && nextTF === 0) {
    threats.push({ feed: 'threatfox', direction: 'resolved' })
  }

  // ── Geo / network ─────────────────────────────────────────────────────────

  const prevGeo = prev.core.geo.data
  const nextGeo = next.core.geo.data
  if (prevGeo && nextGeo) {
    if (prevGeo.country !== nextGeo.country) {
      geo.push({ field: 'country', prev: prevGeo.country, next: nextGeo.country })
    }
  }

  const prevAsn = prev.core.bgp.data?.asn
  const nextAsn = next.core.bgp.data?.asn
  if (prevAsn && nextAsn && prevAsn !== nextAsn) {
    geo.push({ field: 'asn', prev: `AS${prevAsn}`, next: `AS${nextAsn}` })
  }

  // Primary hostname (first from InternetDB hostnames list)
  const prevHost = prev.core.internetdb.data?.hostnames?.[0]
  const nextHost = next.core.internetdb.data?.hostnames?.[0]
  if (prevHost && nextHost && prevHost !== nextHost) {
    geo.push({ field: 'hostname', prev: prevHost, next: nextHost })
  }

  // ── Certificate expiry ────────────────────────────────────────────────────

  // Surface certs that are expiring soon (≤ CERT_EXPIRY_WARN_DAYS) or have
  // just expired. We only check the *next* snapshot — this is a point-in-time
  // alert, not a transition. Avoids double-alerting on certs already flagged.
  const prevCertNames = new Set(
    (ok(prev.core.certs) ? prev.core.certs.data : [])
      ?.map(c => c.commonName) ?? [],
  )
  const nextCerts = ok(next.core.certs) ? (next.core.certs.data ?? []) : []
  for (const cert of nextCerts) {
    const days = daysUntil(cert.notAfter)
    // Warn if: expiring within threshold OR newly expired (wasn't flagged before)
    if (days <= CERT_EXPIRY_WARN_DAYS) {
      // Only emit if this cert wasn't already seen in the prev snapshot
      // (so we don't re-alert every hour on an already-known near-expiry)
      if (!prevCertNames.has(cert.commonName)) {
        certExpiry.push({ commonName: cert.commonName, notAfter: cert.notAfter, daysLeft: days })
      }
    }
  }

  // ── Risk score delta ──────────────────────────────────────────────────────

  // If the stored snapshot predates the risk score feature, prev.riskScore
  // may be undefined — handle gracefully.
  const prevScore = (prev as { riskScore?: { score: number } }).riskScore?.score
  const nextScore = computeRiskScore(next).score

  const risk: RiskChange | null = prevScore !== undefined
    ? { prev: prevScore, next: nextScore, delta: nextScore - prevScore }
    : null

  // ── Assemble ──────────────────────────────────────────────────────────────

  const hasChanges =
    ports.length > 0 || cves.length > 0 || threats.length > 0 || geo.length > 0 ||
    certExpiry.length > 0 ||
    (risk !== null && Math.abs(risk.delta) >= 5)  // only surface risk shift ≥ 5 points

  return {
    diffedAt: Math.floor(Date.now() / 1000),
    hasChanges,
    ports,
    cves,
    threats,
    geo,
    certExpiry,
    risk,
  }
}

// ─── Human-readable summary (for logs / webhook text fields) ─────────────────

export function summariseDiff(diff: TargetDiff, query: string): string {
  if (!diff.hasChanges) return `${query}: no changes`
  const lines: string[] = [`${query}:`]
  for (const p of diff.ports) {
    lines.push(`  port ${p.port} ${p.direction}`)
  }
  for (const c of diff.cves) {
    const sev = c.severity ? ` [${c.severity}${c.score !== undefined ? ` ${c.score}` : ''}]` : ''
    lines.push(`  CVE ${c.id} ${c.direction}${sev}`)
  }
  for (const t of diff.threats) {
    const detail = t.detail ? ` (${t.detail})` : ''
    lines.push(`  ${t.feed} ${t.direction}${detail}`)
  }
  for (const g of diff.geo) {
    lines.push(`  ${g.field}: ${g.prev} → ${g.next}`)
  }
  for (const c of diff.certExpiry) {
    const status = c.daysLeft <= 0 ? 'EXPIRED' : `expires in ${c.daysLeft}d`
    lines.push(`  cert ${c.commonName} ${status} (${c.notAfter})`)
  }
  if (diff.risk && Math.abs(diff.risk.delta) >= 5) {
    const arrow = diff.risk.delta > 0 ? '▲' : '▼'
    lines.push(`  risk score: ${diff.risk.prev} → ${diff.risk.next} ${arrow}${Math.abs(diff.risk.delta)}`)
  }
  return lines.join('\n')
}
