/**
 * app/components/CveDrawer.tsx
 *
 * Renders the vulnerability list with expandable drawers per CVE.
 * Clicking a CVE row reveals the full NVD record inline —
 * description, CVSS breakdown, CWEs, references.
 * All data is already in the result — zero additional fetches.
 */
'use client'

import { useState } from 'react'
import { CopyButton } from './CopyButton'
import type { CVEDetail } from '../../lib/types'

function severityClass(s?: string) {
  if (s === 'CRITICAL') return 'text-red-400 bg-red-900/30'
  if (s === 'HIGH')     return 'text-orange-400 bg-orange-900/30'
  if (s === 'MEDIUM')   return 'text-amber-400 bg-amber-900/30'
  if (s === 'LOW')      return 'text-green-400 bg-green-900/30'
  return 'text-neutral-400 bg-neutral-800'
}

function CvssBar({ score }: { score: number }) {
  const pct = (score / 10) * 100
  const color =
    score >= 9   ? 'bg-red-500' :
    score >= 7   ? 'bg-orange-500' :
    score >= 4   ? 'bg-amber-500' :
                   'bg-green-500'
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-24 rounded-full bg-neutral-700 overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-neutral-300">{score.toFixed(1)}</span>
    </div>
  )
}

function CveRow({ cve }: { cve: CVEDetail }) {
  const [open, setOpen] = useState(false)

  return (
    <div className="rounded-lg border border-neutral-800 overflow-hidden">
      {/* Header row — always visible */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-3 py-2.5 text-left
                   hover:bg-neutral-800/50 transition-colors"
      >
        <span className="font-mono font-semibold text-white text-sm shrink-0">
          {cve.id}
        </span>
        <CopyButton value={cve.id} label={`Copy ${cve.id}`} />
        {cve.cvssV3Severity && (
          <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded uppercase ${severityClass(cve.cvssV3Severity)}`}>
            {cve.cvssV3Severity}
          </span>
        )}
        {cve.cvssV3Score !== undefined && (
          <span className="text-xs font-mono text-neutral-400">
            {cve.cvssV3Score.toFixed(1)}
          </span>
        )}
        <span className="flex-1 text-xs text-neutral-500 truncate ml-1">
          {cve.description}
        </span>
        <span className="text-neutral-600 text-xs shrink-0 ml-2">
          {open ? '▴' : '▾'}
        </span>
      </button>

      {/* Expanded drawer */}
      {open && (
        <div className="border-t border-neutral-800 bg-neutral-900/50 px-4 py-3 space-y-3">
          {/* Description */}
          <p className="text-xs text-neutral-300 leading-relaxed">{cve.description}</p>

          {/* CVSS scores */}
          {(cve.cvssV3Score !== undefined || cve.cvssV2Score !== undefined) && (
            <div className="space-y-1.5">
              <p className="text-[10px] text-neutral-500 uppercase tracking-wide">CVSS Scores</p>
              {cve.cvssV3Score !== undefined && (
                <div className="flex items-center gap-3">
                  <span className="text-xs text-neutral-500 w-12">v3.x</span>
                  <CvssBar score={cve.cvssV3Score} />
                  {cve.cvssV3Severity && (
                    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded uppercase ${severityClass(cve.cvssV3Severity)}`}>
                      {cve.cvssV3Severity}
                    </span>
                  )}
                </div>
              )}
              {cve.cvssV2Score !== undefined && (
                <div className="flex items-center gap-3">
                  <span className="text-xs text-neutral-500 w-12">v2.0</span>
                  <CvssBar score={cve.cvssV2Score} />
                </div>
              )}
            </div>
          )}

          {/* CWEs */}
          {cve.cwe && cve.cwe.length > 0 && (
            <div>
              <p className="text-[10px] text-neutral-500 uppercase tracking-wide mb-1">Weakness</p>
              <div className="flex flex-wrap gap-1.5">
                {cve.cwe.map(c => (
                  <a
                    key={c}
                    href={`https://cwe.mitre.org/data/definitions/${c.replace('CWE-', '')}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-neutral-800
                               text-neutral-400 hover:text-white transition-colors"
                  >
                    {c}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* References */}
          {cve.references && cve.references.length > 0 && (
            <div>
              <p className="text-[10px] text-neutral-500 uppercase tracking-wide mb-1">References</p>
              <ul className="space-y-0.5">
                {cve.references.slice(0, 5).map(ref => (
                  <li key={ref}>
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[10px] font-mono text-neon-red/60 hover:text-neon-red
                                 truncate block transition-colors"
                    >
                      {ref}
                    </a>
                  </li>
                ))}
                {cve.references.length > 5 && (
                  <li className="text-[10px] text-neutral-600">
                    +{cve.references.length - 5} more references
                  </li>
                )}
              </ul>
            </div>
          )}

          {/* Footer meta */}
          <div className="flex items-center gap-4 pt-1 border-t border-neutral-800">
            {cve.publishedDate && (
              <span className="text-[10px] text-neutral-600">
                Published {cve.publishedDate.slice(0, 10)}
              </span>
            )}
            <span className="text-[10px] text-neutral-600">via {cve.source}</span>
            <a
              href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[10px] font-mono text-neutral-500 hover:text-white
                         ml-auto transition-colors"
            >
              NVD ↗
            </a>
          </div>
        </div>
      )}
    </div>
  )
}

export function CveDrawerList({ vulns }: { vulns: CVEDetail[] }) {
  if (vulns.length === 0) return null
  return (
    <div className="space-y-2">
      {vulns.map(cve => <CveRow key={cve.id} cve={cve} />)}
    </div>
  )
}
