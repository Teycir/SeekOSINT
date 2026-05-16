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
import { ExportButton } from '../../components/ExportButton'
import { CopyButton } from '../../components/CopyButton'
import { ShareButton } from '../../components/ShareButton'
import { SaveButton } from '../../components/SaveButton'
import { VulnsStream } from '../../components/VulnsStream'

// ─── Data fetching ────────────────────────────────────────────────────────────

async function fetchResult(rawQuery: string, forceRefresh = false): Promise<HostResult | null> {
  try {
    const query = parseQuery(rawQuery)
    if (!query) return null
    const { env, ctx } = getCloudflareContext()
    return await runLookup({ ...query, forceRefresh }, env as unknown as Env, ctx)
  } catch (err) {
    console.error('[fetchResult] runLookup failed:', err)
    return null
  }
}

// ─── UI primitives ────────────────────────────────────────────────────────────

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
  return <p className="text-xs text-neutral-600 italic">{source} unavailable</p>
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

/** Copyable monospace value — renders value + copy button inline */
function Mono({ value }: { value: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className="font-mono">{value}</span>
      <CopyButton value={value} />
    </span>
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
      <dl className="grid grid-cols-2 gap-x-8 gap-y-3 sm:grid-cols-3">
        {result.resolvedIP && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">IP</dt>
            <dd><Mono value={result.resolvedIP} /></dd>
          </div>
        )}
        {result.resolvedDomain && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Domain</dt>
            <dd><Mono value={result.resolvedDomain} /></dd>
          </div>
        )}
        {sourceOk(geo) && (
          <>
            <div>
              <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Location</dt>
              <dd className="inline-flex items-center gap-1">
                {geo.data.city}, {geo.data.country}
                <CopyButton value={`${geo.data.city}, ${geo.data.country}`} label="Copy location" />
              </dd>
            </div>
            <div>
              <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">ISP / Org</dt>
              <dd className="inline-flex items-center gap-1">
                <span>{geo.data.org}</span>
                <CopyButton value={geo.data.org} label="Copy org" />
              </dd>
            </div>
            <div>
              <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Timezone</dt>
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
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">ASN</dt>
            <dd><Mono value={`AS${bgp.data.asn}`} /> <span className="text-neutral-500 text-xs">— {bgp.data.name}</span></dd>
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
          <span key={p} className="inline-flex items-center gap-0.5 font-mono rounded
                                   bg-neutral-800 px-2 py-1 text-xs">
            {p}
            <CopyButton value={String(p)} label={`Copy port ${p}`} />
          </span>
        ))}
      </div>
      {idb.data.cpes.length > 0 && (
        <div className="mt-4 space-y-1.5">
          <p className="text-xs text-neutral-500 uppercase tracking-wide">CPEs</p>
          {idb.data.cpes.map(c => (
            <div key={c} className="inline-flex items-center gap-1">
              <span className="font-mono text-xs text-neutral-400">{c}</span>
              <CopyButton value={c} label="Copy CPE" />
            </div>
          ))}
        </div>
      )}
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
          <div key={c.id} className="flex items-center justify-between text-xs
                                     border-b border-neutral-800 pb-1 gap-2">
            <div className="flex items-center gap-1 min-w-0">
              <span className="font-mono text-neutral-200 truncate">{c.commonName}</span>
              <CopyButton value={c.commonName} label="Copy domain" />
            </div>
            <span className="text-neutral-600 shrink-0">expires {c.notAfter.slice(0, 10)}</span>
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
                <td className="py-1 pr-4">
                  <span className="inline-flex items-center gap-1 font-mono">
                    {r.rrname}<CopyButton value={r.rrname} />
                  </span>
                </td>
                <td className="py-1 pr-4">{r.rrtype}</td>
                <td className="py-1 pr-4">
                  <span className="inline-flex items-center gap-1 font-mono">
                    {r.rdata}<CopyButton value={r.rdata} />
                  </span>
                </td>
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
            {urlhaus.data.urlhaus_reference && (
              <a
                href={urlhaus.data.urlhaus_reference}
                target="_blank"
                rel="noopener noreferrer"
                className="ml-2 text-xs text-neon-red/60 hover:text-neon-red font-mono"
              >
                view ↗
              </a>
            )}
          </div>
        ) : (
          <p className="text-xs text-neutral-600">URLhaus — no results</p>
        )}
        {sourceOk(threatfox) && threatfox.data.query_status === 'ok' && (threatfox.data.data?.length ?? 0) > 0 ? (
          <div>
            <p className="text-xs text-neutral-500 uppercase tracking-wide mb-1">ThreatFox IOCs</p>
            <div className="space-y-1">
              {threatfox.data.data!.slice(0, 5).map(ioc => (
                <div key={ioc.id} className="flex items-center gap-2 text-xs text-neutral-400">
                  <span className="inline-flex items-center gap-1 font-mono">
                    {ioc.ioc}<CopyButton value={ioc.ioc} label="Copy IOC" />
                  </span>
                  <span className="text-neutral-600">·</span>
                  <span>{ioc.malware} — {ioc.threat_type}</span>
                  <Badge label={`${ioc.confidence_level}%`} variant="warn" />
                </div>
              ))}
            </div>
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
            <span className="inline-flex items-center gap-1 font-mono text-neutral-200">
              {b.bucket}
              <CopyButton value={b.bucket} label="Copy bucket name" />
            </span>
            <div className="flex items-center gap-2">
              <Badge label={b.provider.toUpperCase()} />
              <a
                href={b.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-neutral-500 hover:text-white font-mono transition-colors"
              >
                ↗
              </a>
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
          <div key={i} className="flex justify-between text-xs font-mono gap-2">
            <a
              href={`https://web.archive.org/web/${s.timestamp}/${s.url}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-neutral-400 hover:text-neon-red truncate max-w-xs transition-colors"
            >
              {s.url}
            </a>
            <span className="text-neutral-600 shrink-0">{s.timestamp.slice(0, 8)}</span>
          </div>
        ))}
      </div>
    </Card>
  )
}

function MetaBar({ result }: { result: HostResult }) {
  const { meta } = result
  return (
    <p className="text-xs text-neutral-600 text-right font-mono">
      {meta.sourcesQueried} sources · {meta.cacheHits} cached · {meta.sourcesFailed} failed · {meta.durationMs}ms
    </p>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default async function HostPage({
  params,
  searchParams,
}: {
  params: Promise<{ query: string }>
  searchParams: Promise<{ refresh?: string; ts?: string }>
}) {
  const [{ query: rawQuery }, sp] = await Promise.all([params, searchParams])
  const forceRefresh = sp.refresh === '1'
  const tsToken = sp.ts
  const result = await fetchResult(decodeURIComponent(rawQuery), forceRefresh)

  if (!result) notFound()

  return (
    <main className="min-h-screen bg-neutral-950 px-4 py-10">
      <div className="mx-auto max-w-3xl space-y-4">

        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="font-mono text-xl font-semibold text-white truncate">
                {result.query.normalised}
              </h1>
              <CopyButton value={result.query.normalised} label="Copy query" className="text-sm" />
            </div>
            <p className="text-xs text-neutral-500 uppercase tracking-wide">{result.query.type}</p>
          </div>
          <div className="flex items-center gap-3 shrink-0 flex-wrap justify-end">
            <SaveButton query={result.query.normalised} />
            <ShareButton query={result.query.normalised} />
            <ExportButton
              resultJson={JSON.stringify(result, null, 2)}
              filename={`seekosint-${result.query.normalised}.json`}
            />
            <a
              href={`/host/${encodeURIComponent(result.query.normalised)}?refresh=1`}
              className="text-xs text-neutral-500 hover:text-neon-red font-mono transition-colors"
              title="Bypass cache and re-fetch all sources"
            >
              ↺ refresh
            </a>
            <a href="/" className="text-sm text-neutral-500 hover:text-white transition-colors">
              ← back
            </a>
          </div>
        </div>

        <OverviewSection result={result} />
        <PortsSection result={result} />
        {/* VulnsStream fetches CVE details client-side so NVD latency doesn't
            block the initial paint — geo/ports/threats all SSR above this. */}
        <VulnsStream
          cveIds={result.core.internetdb.data?.vulns ?? []}
          query={result.query.normalised}
          refresh={forceRefresh}
          turnstileToken={tsToken}
        />
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
