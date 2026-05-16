/**
 * app/components/VulnsStream.tsx
 *
 * Client component — fetches CVE details progressively via /api/stream
 * and renders the vulnerability card as data arrives.
 *
 * The SSR results page passes the CVE IDs already known from InternetDB.
 * If cveIds is empty, renders nothing. If the stream has cached CVE data
 * it renders almost immediately; if NVD has to be hit, the card shows a
 * pulsing skeleton until the batch completes.
 *
 * This decouples the NVD latency from the page's initial render —
 * geo/ports/threats/certs are all SSR and paint in <1s regardless.
 */
'use client'

import { useEffect, useState } from 'react'
import { CveDrawerList } from './CveDrawer'
import type { CVEDetail } from '../../lib/types'

interface VulnsStreamProps {
  /** CVE IDs from InternetDB — passed in by the SSR page */
  cveIds: string[]
  /** The normalised query string — used to call /api/stream */
  query: string
  /** Pass through ?refresh=1 if present */
  refresh?: boolean
}

type LoadState = 'idle' | 'loading' | 'done' | 'error'

function PulsingCard({ count }: { count: number }) {
  return (
    <details
      className="rounded-xl border border-neutral-800 bg-neutral-900 overflow-hidden"
      open
    >
      <summary className="cursor-default select-none px-5 py-4 text-sm font-semibold
                          text-neutral-200 list-none flex items-center justify-between">
        <span>
          Vulnerabilities ({count})
          <span className="ml-2 text-[10px] font-normal text-neutral-600 font-mono animate-pulse">
            loading CVE details…
          </span>
        </span>
        <span className="text-neutral-600 text-xs">▾</span>
      </summary>
      <div className="border-t border-neutral-800 px-5 py-4 space-y-2">
        {Array.from({ length: Math.min(count, 5) }).map((_, i) => (
          <div key={i} className="h-9 rounded-lg bg-neutral-800/60 animate-pulse" />
        ))}
      </div>
    </details>
  )
}

export function VulnsStream({ cveIds, query, refresh = false }: VulnsStreamProps) {
  const [vulns,  setVulns]  = useState<CVEDetail[]>([])
  const [status, setStatus] = useState<LoadState>('idle')

  useEffect(() => {
    if (cveIds.length === 0) return
    setStatus('loading')

    const url = `/api/stream?q=${encodeURIComponent(query)}${refresh ? '&refresh=1' : ''}`
    const controller = new AbortController()

    ;(async () => {
      try {
        const res = await fetch(url, { signal: controller.signal })
        if (!res.ok || !res.body) { setStatus('error'); return }

        const reader  = res.body.getReader()
        const decoder = new TextDecoder()
        let   buf     = ''

        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          const lines = buf.split('\n')
          buf = lines.pop() ?? ''

          for (const line of lines) {
            if (!line.trim()) continue
            try {
              const frame = JSON.parse(line) as { type: string; data: unknown }
              if (frame.type === 'vulns') {
                setVulns(frame.data as CVEDetail[])
              } else if (frame.type === 'done') {
                setStatus('done')
              } else if (frame.type === 'error') {
                setStatus('error')
              }
            } catch { /* skip malformed */ }
          }
        }
        setStatus(s => s === 'loading' ? 'done' : s)
      } catch (err: unknown) {
        if ((err as { name?: string }).name !== 'AbortError') setStatus('error')
      }
    })()

    return () => controller.abort()
  }, [cveIds, query, refresh])

  if (cveIds.length === 0) return null
  if (status === 'idle' || status === 'loading') return <PulsingCard count={cveIds.length} />
  if (status === 'error' || vulns.length === 0) {
    return (
      <details className="rounded-xl border border-neutral-800 bg-neutral-900 overflow-hidden" open>
        <summary className="cursor-pointer select-none px-5 py-4 text-sm font-semibold
                            text-neutral-200 list-none flex items-center justify-between">
          Vulnerabilities ({cveIds.length})
          <span className="text-neutral-600 text-xs">▾</span>
        </summary>
        <div className="border-t border-neutral-800 px-5 py-4">
          <p className="text-xs text-neutral-600 italic">CVE details unavailable — check NVD directly</p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {cveIds.map(id => (
              <a
                key={id}
                href={`https://nvd.nist.gov/vuln/detail/${id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-neutral-800
                           text-neutral-400 hover:text-white transition-colors"
              >
                {id} ↗
              </a>
            ))}
          </div>
        </div>
      </details>
    )
  }

  return (
    <details className="rounded-xl border border-neutral-800 bg-neutral-900 overflow-hidden" open>
      <summary className="cursor-pointer select-none px-5 py-4 text-sm font-semibold
                          text-neutral-200 hover:text-white list-none flex items-center
                          justify-between">
        Vulnerabilities ({vulns.length})
        <span className="text-neutral-600 text-xs">▾</span>
      </summary>
      <div className="border-t border-neutral-800 px-5 py-4 text-sm text-neutral-300">
        <CveDrawerList vulns={vulns} />
      </div>
    </details>
  )
}
