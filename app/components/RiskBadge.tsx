'use client'

/**
 * RiskBadge — displays the host risk score with colour coding and a
 * tooltip breakdown of contributing categories.
 */
import type { RiskScore } from '../../lib/types'

const SEVERITY_STYLES: Record<string, string> = {
  LOW:      'bg-green-900/50 text-green-300 border-green-800',
  MEDIUM:   'bg-amber-900/50 text-amber-300 border-amber-800',
  HIGH:     'bg-orange-900/50 text-orange-300 border-orange-800',
  CRITICAL: 'bg-red-900/50 text-red-300 border-red-800',
}

const SEVERITY_DOT: Record<string, string> = {
  LOW:      'bg-green-400',
  MEDIUM:   'bg-amber-400',
  HIGH:     'bg-orange-400',
  CRITICAL: 'bg-red-400',
}

const CATEGORY_LABELS: Record<string, string> = {
  blocklists:   'Blocklists',
  threatIntel:  'Threat intel',
  vulns:        'Vulnerabilities',
  ports:        'Port exposure',
  networkFlags: 'Network flags',
}

const CATEGORY_MAX: Record<string, number> = {
  blocklists:   35,
  threatIntel:  30,
  vulns:        25,
  ports:        15,
  networkFlags: 10,
}

export function RiskBadge({ risk }: { risk: RiskScore }) {
  const { score, severity, breakdown } = risk
  const badgeStyle = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.LOW
  const dotStyle   = SEVERITY_DOT[severity]   ?? SEVERITY_DOT.LOW

  return (
    <div className="group relative inline-block">
      {/* Badge */}
      <span
        className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1
                    text-xs font-semibold font-mono cursor-default select-none
                    ${badgeStyle}`}
        title="Click to see score breakdown"
      >
        <span className={`w-1.5 h-1.5 rounded-full ${dotStyle}`} />
        Risk {score} · {severity}
      </span>

      {/* Tooltip breakdown — shown on hover */}
      <div
        className="absolute right-0 top-full mt-2 z-50 w-56 rounded-lg border
                   border-neutral-700 bg-neutral-900 p-3 shadow-xl
                   opacity-0 pointer-events-none group-hover:opacity-100
                   group-hover:pointer-events-auto transition-opacity duration-150"
      >
        <p className="text-xs font-semibold text-neutral-300 mb-2">Score breakdown</p>
        <div className="space-y-1.5">
          {(Object.keys(CATEGORY_LABELS) as (keyof typeof CATEGORY_LABELS)[]).map(key => {
            const val = breakdown[key as keyof typeof breakdown]
            if (typeof val !== 'number') return null
            const max = CATEGORY_MAX[key] ?? 100
            const pct = Math.round((val / max) * 100)
            return (
              <div key={key}>
                <div className="flex justify-between text-xs text-neutral-400 mb-0.5">
                  <span>{CATEGORY_LABELS[key]}</span>
                  <span className="font-mono text-neutral-300">{val}/{max}</span>
                </div>
                <div className="h-1 w-full rounded-full bg-neutral-800">
                  <div
                    className={`h-1 rounded-full transition-all ${
                      pct >= 80 ? 'bg-red-500' :
                      pct >= 50 ? 'bg-orange-500' :
                      pct >= 25 ? 'bg-amber-500' : 'bg-neutral-600'
                    }`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            )
          })}
        </div>
        <p className="mt-2.5 text-xs text-neutral-600 leading-tight">
          Score is a triage signal, not a verdict. Check sources for context.
        </p>
      </div>
    </div>
  )
}
