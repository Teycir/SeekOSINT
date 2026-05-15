/**
 * Results page — SSR, calls runLookup() directly (no self-fetch).
 * Each layer is a collapsible card. Failed/skipped sources render
 * a subtle "unavailable" placeholder, never a broken layout.
 *
 * Next 15+: params is a Promise — must be awaited.
 */
import { notFound } from 'next/navigation'
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { parseQuery } from '../../../lib/validate'
import { runLookup } from '../../../worker/lookup'
import type { Env, HostResult, SourceResult } from '../../../lib/types'

// ─── Data fetching — direct call, no HTTP round-trip ─────────────────────────

async function fetchResult(rawQuery: string): Promise<HostResult | null> {
  try {
    const query = parseQuery(rawQuery)
    if (!query) return null
    const { env, ctx } = getCloudflareContext()
    return await runLookup(query, env as unknown as Env, ctx)
  } catch (err) {
    console.error('[fetchResult] runLookup failed:', err)
    return null
  }
}

// ─── Small UI primitives ──────────────────────────────────────────────────────

function Badge({
  label,
  variant = 'default',
}: {
  label: string
  variant?: 'default' | 'danger' | 'warn' | 'ok' | 'muted'
}) {
  const styles: Record<string, string> = {
    default: 'bg-neutral-800 text-neutral-300',
    danger:  'bg-red-900/60 text-red-300',
    warn:    'bg-amber-900/60 text-amber-300',
    ok:      'bg-green-900/60 text-green-300',
    muted:   'bg-neutral-800/40 text-neutral-500',
  }
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${styles[variant]}`}>
      {label}
    </span>
  )
}

function SourceUnavailable({ source }: { source: string }) {
  return (
    <p className="text-xs text-neutral-600 italic">{source} unavailable</p>
  )
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <details
      className="rounded-xl border border-neutral-800 bg-neutral-900 overflow-hidden"
      open
    >
      <summary className="cursor-pointer select-none px-5 py-4 text-sm font-semibold
                          text-neutral-200 hover:text-white list-none flex items-center
                          justify-between">
        {title}
        <span className="text-neutral-600 text-xs">▾</span>
      </summary>
      <div className="border-t border-neutral-800 px-5 py-4 text-sm text-neutral-300">
        {children}
      </div>
    </details>
  )
}

function sourceOk<T>(r: SourceResult<T>): r is SourceResult<T> & { data: T } {
  return (r.status === 'ok' || r.status === 'cached') && r.data !== null
}

// ─── Section renderers ────────────────────────────────────────────────────────

function OverviewSection({ result }: { result: HostResult }) {
  const geo = result.core.geo
  const idb = result.core.internetdb
  const bgp = result.core.bgp
  return (
    <Card title="Overview">
      <dl className="grid grid-cols-2 gap-x-8 gap-y-2 sm:grid-cols-3">
        <div>
          <dt className="text-xs text-neutral-500 uppercase tracking-wide">IP</dt>
          <dd className="font-mono">{result.resolvedIP ?? '—'}</dd>
        </div>
        <div>
          <dt className="text-xs text-neutral-500 uppercase tracking-wide">Domain</dt>
          <dd className="font-mono">{result.resolvedDomain ?? '—'}</dd>
        </div>
        {sourceOk(geo) && (
          <>
            <div>
              <dt className="text-xs text-neutral-500 uppercase tracking-wide">Location</dt>
              <dd>{geo.data.city}, {geo.data.country}</dd>
            </div>
            <div>
              <dt className="text-xs text-neutral-500 uppercase tracking-wide">Org</dt>
              <dd>{geo.data.org}</dd>
            </div>
            <div>
              <dt className="text-xs text-neutral-500 uppercase tracking-wide">Timezone</dt>
              <dd>{geo.data.timezone}</dd>
            </div>
            <div className="flex gap-1 flex-wrap pt-1">
              {geo.data.proxy   && <Badge label="Proxy"   variant="warn" />}
              {geo.data.hosting && <Badge label="Hosting" variant="warn" />}
              {geo.data.mobile  && <Badge label="Mobile"  />}
            </div>
          </>
        )}
        {sourceOk(bgp) && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide">ASN</dt>
            <dd>AS{bgp.data.asn} — {bgp.data.name}</dd>
          </div>
        )}
        {sourceOk(idb) && idb.data.tags.length > 0 && (
          <div className="col-span-full flex gap-1 flex-wrap">
            {idb.data.tags.map(t => <Badge key={t} label={t} />)}
          </div>
        )}
      </dl>
    </Card>
  )
}

function PortsSection({ result }: { result: HostResult }) {
  const idb = result.core.internetdb
  if (!sourceOk(idb) || idb.data.ports.length === 0) return null
  return (
    <Card title={`Open ports (${idb.data.ports.length})`}>
      <div className="flex flex-wrap gap-2">
        {idb.data.ports.map(p => (
          <span key={p} className="font-mono rounded bg-neutral-800 px-2 py-1 text-xs">{p}</span>
        ))}
      </div>
      {idb.data.cpes.length > 0 && (
        <div className="mt-3 space-y-1">
          <p className="text-xs text-neutral-500 uppercase tracking-wide">CPEs</p>
          {idb.data.cpes.map(c => (
            <p key={c} className="font-mono text-xs text-neutral-400">{c}</p>
          ))}
        </div>
      )}
    </Card>
  )
}

function VulnsSection({ result }: { result: HostResult }) {
  if (result.vulns.length === 0) return null
  const severityVariant = (s?: string): 'danger' | 'warn' | 'ok' | 'default' => {
    if (s === 'CRITICAL' || s === 'HIGH') return 'danger'
    if (s === 'MEDIUM') return 'warn'
    if (s === 'LOW' || s === 'NONE') return 'ok'
    return 'default'
  }
  return (
    <Card title={`Vulnerabilities (${result.vulns.length})`}>
      <div className="space-y-3">
        {result.vulns.map((v, i) => {
          if (!sourceOk(v)) return <SourceUnavailable key={i} source={`CVE ${i}`} />
          const cve = v.data
          return (
            <div key={cve.id} className="space-y-1 rounded-lg bg-neutral-800/50 px-3 py-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono font-semibold text-white">{cve.id}</span>
                {cve.cvssV3Score !== undefined && (
                  <Badge label={`CVSS ${cve.cvssV3Score}`} variant={severityVariant(cve.cvssV3Severity)} />
                )}
                {cve.cvssV3Severity && (
                  <Badge label={cve.cvssV3Severity} variant={severityVariant(cve.cvssV3Severity)} />
                )}
                <Badge label={cve.source} variant="muted" />
              </div>
              <p className="text-xs text-neutral-400 leading-relaxed line-clamp-3">{cve.description}</p>
            </div>
          )
        })}
      </div>
    </Card>
  )
}

function CertsSection({ result }: { result: HostResult }) {
  const certs = result.core.certs
  if (!sourceOk(certs)) return <Card title="Certificates"><SourceUnavailable source="crt.sh" /></Card>
  return (
    <Card title={`Certificates (${certs.data.length})`}>
      <div className="space-y-2 max-h-80 overflow-y-auto">
        {certs.data.slice(0, 50).map(c => (
          <div key={c.id} className="font-mono text-xs text-neutral-400 border-b border-neutral-800 pb-1">
            <span className="text-neutral-200">{c.commonName}</span>
            <span className="ml-2 text-neutral-600">expires {c.notAfter.slice(0, 10)}</span>
          </div>
        ))}
      </div>
    </Card>
  )
}

function DNSSection({ result }: { result: HostResult }) {
  const pdns = result.core.passivedns
  if (!sourceOk(pdns) || pdns.data.length === 0) {
    return <Card title="DNS history"><SourceUnavailable source="CIRCL Passive DNS" /></Card>
  }
  return (
    <Card title={`DNS history (${pdns.data.length} records)`}>
      <div className="overflow-x-auto">
        <table className="w-full text-xs text-neutral-400">
          <thead>
            <tr className="text-neutral-500 uppercase text-left">
              <th className="pb-2 pr-4">Name</th>
              <th className="pb-2 pr-4">Type</th>
              <th className="pb-2 pr-4">Value</th>
              <th className="pb-2">Last seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-800">
            {pdns.data.slice(0, 30).map((r, i) => (
              <tr key={i}>
                <td className="py-1 pr-4 font-mono">{r.rrname}</td>
                <td className="py-1 pr-4">{r.rrtype}</td>
                <td className="py-1 pr-4 font-mono">{r.rdata}</td>
                <td className="py-1">{new Date(r.time_last * 1000).toISOString().slice(0, 10)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function ThreatSection({ result }: { result: HostResult }) {
  const { urlhaus, threatfox, feodo } = result.threat
  const hasThreats =
    (sourceOk(urlhaus) && urlhaus.data.query_status === 'is_host') ||
    (sourceOk(threatfox) && threatfox.data.query_status === 'ok' && (threatfox.data.data?.length ?? 0) > 0) ||
    (sourceOk(feodo) && feodo.data !== null)
  return (
    <Card title={`Threat intelligence${hasThreats ? ' ⚠' : ''}`}>
      <div className="space-y-4">
        {sourceOk(urlhaus) && urlhaus.data.query_status === 'is_host' ? (
          <div>
            <p className="text-xs text-neutral-500 uppercase tracking-wide mb-1">URLhaus</p>
            <Badge label={`${urlhaus.data.urls_count ?? 0} URLs found`} variant="danger" />
          </div>
        ) : (
          <p className="text-xs text-neutral-600">URLhaus — no results</p>
        )}
        {sourceOk(threatfox) && threatfox.data.query_status === 'ok' && (threatfox.data.data?.length ?? 0) > 0 ? (
          <div>
            <p className="text-xs text-neutral-500 uppercase tracking-wide mb-1">ThreatFox IOCs</p>
            {threatfox.data.data!.slice(0, 5).map(ioc => (
              <div key={ioc.id} className="text-xs text-neutral-400">
                {ioc.malware} — {ioc.threat_type} <Badge label={`${ioc.confidence_level}%`} variant="warn" />
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-neutral-600">ThreatFox — no IOCs</p>
        )}
        {sourceOk(feodo) && feodo.data !== null && (
          <div>
            <p className="text-xs text-neutral-500 uppercase tracking-wide mb-1">Feodo C2</p>
            <Badge label={`${feodo.data.malware} — ${feodo.data.status}`} variant="danger" />
          </div>
        )}
      </div>
    </Card>
  )
}

function BucketsSection({ result }: { result: HostResult }) {
  const buckets = result.recon.buckets
  if (buckets.status === 'skipped' || !sourceOk(buckets) || buckets.data.length === 0) return null
  return (
    <Card title={`Exposed buckets (${buckets.data.length})`}>
      <div className="space-y-2">
        {buckets.data.map(b => (
          <div key={b.bucket} className="flex items-center justify-between text-xs">
            <span className="font-mono text-neutral-200">{b.bucket}</span>
            <div className="flex items-center gap-2">
              <Badge label={b.provider.toUpperCase()} />
              <span className="text-neutral-500">{b.fileCount} files</span>
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}

function WaybackSection({ result }: { result: HostResult }) {
  const wb = result.recon.wayback
  if (wb.status === 'skipped' || !sourceOk(wb) || wb.data.length === 0) return null
  return (
    <Card title={`Web archive (${wb.data.length} snapshots)`}>
      <div className="space-y-1 max-h-60 overflow-y-auto">
        {wb.data.slice(0, 20).map((s, i) => (
          <div key={i} className="flex justify-between text-xs font-mono">
            <span className="text-neutral-400 truncate max-w-xs">{s.url}</span>
            <span className="text-neutral-600 ml-2 shrink-0">{s.timestamp.slice(0, 8)}</span>
          </div>
        ))}
      </div>
    </Card>
  )
}

function MetaBar({ result }: { result: HostResult }) {
  const { meta } = result
  return (
    <p className="text-xs text-neutral-600 text-right">
      {meta.sourcesQueried} sources queried · {meta.cacheHits} cached · {meta.sourcesFailed} failed · {meta.durationMs}ms
    </p>
  )
}

// ─── Page — params is a Promise in Next 15+ ───────────────────────────────────

export default async function HostPage({
  params,
}: {
  params: Promise<{ query: string }>
}) {
  const { query: rawQuery } = await params
  const result = await fetchResult(decodeURIComponent(rawQuery))

  if (!result) notFound()

  return (
    <main className="min-h-screen bg-neutral-950 px-4 py-10">
      <div className="mx-auto max-w-3xl space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="font-mono text-xl font-semibold text-white">{result.query.normalised}</h1>
            <p className="text-xs text-neutral-500 uppercase tracking-wide">{result.query.type}</p>
          </div>
          <a href="/" className="text-sm text-neutral-500 hover:text-white">← New search</a>
        </div>
        <OverviewSection result={result} />
        <PortsSection result={result} />
        <VulnsSection result={result} />
        <ThreatSection result={result} />
        <CertsSection result={result} />
        <DNSSection result={result} />
        <BucketsSection result={result} />
        <WaybackSection result={result} />
        <MetaBar result={result} />
      </div>
    </main>
  )
}
