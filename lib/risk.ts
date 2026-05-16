/**
 * lib/risk.ts — Host risk score (0–100)
 *
 * A single number that aggregates signal across all HostResult layers.
 * Designed to be a triage aid, not a verdict — always show the breakdown.
 *
 * Scoring model (additive, capped at 100):
 *
 * BLOCKLISTS (hard ceiling signals)              max  35
 *   Feodo Online                                  35
 *   Feodo Offline                                 20
 *   SSLBL hit                                     25
 *
 * THREAT INTEL                                   max  30
 *   URLhaus is_host                               15
 *   ThreatFox hit (per IOC, up to 2)           10+10
 *   MalwareBazaar hit                             10
 *
 * VULNERABILITY EXPOSURE                         max  25
 *   CVSS 9–10 (CRITICAL)                      15/CVE
 *   CVSS 7–8.9 (HIGH)                          8/CVE
 *   CVSS 4–6.9 (MEDIUM)                        4/CVE
 *   CVSS < 4 (LOW/NONE)                        1/CVE
 *
 * ATTACK SURFACE (open ports)                   max  15
 *   High-risk ports (22,23,445,3389,5900…)     4/port (max 12)
 *   Any other port                              1/port (max  5)
 *
 * NETWORK FLAGS                                  max  10
 *   ip-api proxy flag                              5
 *   ip-api hosting flag                            3
 *   Shodan "honeypot" tag                          5
 *   Shodan "scanner" tag                           3
 *
 * DOMAIN REGISTRATION (RDAP, domain queries)    max  15
 *   Newly registered < 30 days old              +15
 *   Expired domain                              +10
 *   Privacy-protected registrant                 +5
 *   No nameservers                               +8
 *
 * Maximum raw score before cap: ~130 — ensures cap is reached only on
 * genuinely multi-signal hosts.
 *
 * Severity bands:
 *   0–24   LOW     (green)
 *   25–49  MEDIUM  (amber)
 *   50–74  HIGH    (orange)
 *   75–100 CRITICAL(red)
 */

import type {
  HostResult,
  SourceResult,
  InternetDBResult,
  IPAPIResult,
  URLhausResult,
  ThreatFoxResult,
  MalwareBazaarResult,
  FeodoEntry,
  SSLBLEntry,
  CVEDetail,
  RDAPResult,
} from './types'

// ─── High-risk port list ───────────────────────────────────────────────────────
// Ports that indicate directly exploitable or commonly abused services.

const HIGH_RISK_PORTS = new Set([
  21,   // FTP
  22,   // SSH
  23,   // Telnet
  25,   // SMTP (open relay potential)
  53,   // DNS (open resolver potential)
  135,  // RPC
  139,  // NetBIOS
  445,  // SMB — EternalBlue etc.
  1433, // MSSQL
  1723, // PPTP VPN
  3306, // MySQL
  3389, // RDP
  4444, // Metasploit default / Feodo C2
  4899, // Radmin
  5432, // PostgreSQL
  5900, // VNC
  6379, // Redis (no-auth default)
  8080, // Alt HTTP (proxy/admin panels)
  8443, // Alt HTTPS
  9200, // Elasticsearch (no-auth default)
  11211,// Memcached
  27017,// MongoDB (no-auth default)
])

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ok<T>(r: SourceResult<T>): r is SourceResult<T> & { data: T } {
  return (r.status === 'ok' || r.status === 'cached') && r.data !== null
}

function clamp(v: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, v))
}

// ─── Score breakdown ──────────────────────────────────────────────────────────

export interface RiskBreakdown {
  blocklists:         number
  threatIntel:        number
  vulns:              number
  ports:              number
  networkFlags:       number
  domainRegistration: number
  total:              number       // capped 0–100
}

export type RiskSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface RiskScore {
  score:    number         // 0–100
  severity: RiskSeverity
  breakdown: RiskBreakdown
}

// ─── Main scorer ──────────────────────────────────────────────────────────────

export function computeRiskScore(result: HostResult): RiskScore {
  let blocklists          = 0
  let threatIntel         = 0
  let vulnsScore          = 0
  let portsScore          = 0
  let networkFlags        = 0
  let domainRegistration  = 0

  // ── Blocklists ───────────────────────────────────────────────────────────

  const feodo = result.threat.feodo
  if (ok(feodo) && feodo.data !== null) {
    blocklists += feodo.data.status === 'Online' ? 35 : 20
  }

  const sslbl = result.threat.sslbl
  if (ok(sslbl) && sslbl.data.length > 0) {
    blocklists += 25
  }

  // ── Threat intel ─────────────────────────────────────────────────────────

  const urlhaus = result.threat.urlhaus
  if (ok(urlhaus) && (urlhaus.data as URLhausResult).query_status === 'is_host') {
    threatIntel += 15
  }

  const threatfox = result.threat.threatfox
  if (ok(threatfox)) {
    const iocs = (threatfox.data as ThreatFoxResult).data ?? []
    threatIntel += clamp(iocs.length * 10, 0, 20)
  }

  const mb = result.threat.malwarebazaar
  if (ok(mb) && (mb.data as MalwareBazaarResult).query_status === 'ok') {
    threatIntel += 10
  }

  // ── Vulnerabilities ───────────────────────────────────────────────────────

  for (const v of result.vulns) {
    if (!ok(v)) continue
    const cve = v.data as CVEDetail
    const score = cve.cvssV3Score ?? cve.cvssV2Score
    if (score === undefined) {
      vulnsScore += 2
    } else if (score >= 9) {
      vulnsScore += 15
    } else if (score >= 7) {
      vulnsScore += 8
    } else if (score >= 4) {
      vulnsScore += 4
    } else {
      vulnsScore += 1
    }
  }

  // ── Open ports ────────────────────────────────────────────────────────────

  const idb = result.core.internetdb
  if (ok(idb)) {
    let highRisk = 0
    let lowRisk  = 0
    for (const p of (idb.data as InternetDBResult).ports) {
      if (HIGH_RISK_PORTS.has(p)) highRisk++
      else lowRisk++
    }
    portsScore += clamp(highRisk * 4, 0, 12)
    portsScore += clamp(lowRisk  * 1, 0,  5)
  }

  // ── Network flags ─────────────────────────────────────────────────────────

  const geo = result.core.geo
  if (ok(geo)) {
    const g = geo.data as IPAPIResult
    if (g.proxy)   networkFlags += 5
    if (g.hosting) networkFlags += 3
  }

  if (ok(idb)) {
    const tags = (idb.data as InternetDBResult).tags.map(t => t.toLowerCase())
    if (tags.includes('honeypot')) networkFlags += 5
    if (tags.includes('scanner'))  networkFlags += 3
  }

  // ── Domain registration signals (RDAP, domain queries only) ─────────────
  // Primary phishing/typosquatting indicators: newly registered, expired,
  // privacy-protected registrant, or missing nameservers.

  const rdap = result.core.rdap
  if (ok(rdap)) {
    const r = rdap.data as RDAPResult
    if (r.domain) {
      // Newly registered domain (< 30 days) — top phishing signal
      if (r.created) {
        const ageMs = Date.now() - new Date(r.created).getTime()
        const ageDays = ageMs / (1000 * 60 * 60 * 24)
        if (ageDays < 30) domainRegistration += 15
      }

      // Expired domain — could be parked or hijacked
      if (r.expires) {
        if (new Date(r.expires).getTime() < Date.now()) domainRegistration += 10
      }

      // Privacy-protected registrant — redacted contact details
      const hasPrivacyContact = r.contacts?.some(c =>
        c.org?.toLowerCase().includes('privacy') ||
        c.org?.toLowerCase().includes('redacted') ||
        c.email?.toLowerCase().includes('privacy'),
      )
      if (hasPrivacyContact) domainRegistration += 5

      // No nameservers — domain not properly delegated / parked
      if (!r.nameservers || r.nameservers.length === 0) domainRegistration += 8
    }
  }

  // ── Totals ────────────────────────────────────────────────────────────────

  const breakdown: RiskBreakdown = {
    blocklists:         clamp(blocklists,         0, 35),
    threatIntel:        clamp(threatIntel,         0, 30),
    vulns:              clamp(vulnsScore,          0, 25),
    ports:              clamp(portsScore,          0, 15),
    networkFlags:       clamp(networkFlags,        0, 10),
    domainRegistration: clamp(domainRegistration,  0, 15),
    total: 0,
  }

  const raw = breakdown.blocklists + breakdown.threatIntel +
              breakdown.vulns      + breakdown.ports       +
              breakdown.networkFlags + breakdown.domainRegistration

  breakdown.total = clamp(raw, 0, 100)

  const severity: RiskSeverity =
    breakdown.total >= 75 ? 'CRITICAL' :
    breakdown.total >= 50 ? 'HIGH'     :
    breakdown.total >= 25 ? 'MEDIUM'   : 'LOW'

  return { score: breakdown.total, severity, breakdown }
}
