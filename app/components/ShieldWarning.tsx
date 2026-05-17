'use client'

import { useEffect, useState } from 'react'

/**
 * Detects common browser shields/extensions that break the app and shows
 * a dismissible banner with actionable guidance.
 *
 * Detection strategy:
 * - Brave: navigator.brave (async API)
 * - Generic shield: CSP nonce mismatch — if a nonce was injected by the
 *   browser that doesn't match ours, inline scripts fail silently.
 * - Covers: Brave Shields, uBlock Origin, Privacy Badger, etc.
 */
export function ShieldWarning() {
  const [show, setShow] = useState(false)
  const [dismissed, setDismissed] = useState(false)
  const [isBrave, setIsBrave] = useState(false)

  useEffect(() => {
    if (dismissed) return

    async function detect() {
      // 1. Brave detection
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const brave = (navigator as any).brave
        if (brave && typeof brave.isBrave === 'function') {
          const result = await brave.isBrave()
          if (result) {
            setIsBrave(true)
            setShow(true)
            return
          }
        }
      } catch { /* not Brave */ }

      // 2. Generic: test whether an inline script ran (blocked by injected nonces/CSPs)
      try {
        const probe = document.createElement('script')
        let ran = false
        probe.textContent = 'window.__cspProbe=true'
        document.head.appendChild(probe)
        document.head.removeChild(probe)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        ran = !!(window as any).__cspProbe
        if (!ran) {
          setShow(true)
        }
      } catch { /* can't probe */ }
    }

    detect()
  }, [dismissed])

  if (!show || dismissed) return null

  return (
    <div className="fixed top-0 inset-x-0 z-50 bg-amber-900/95 backdrop-blur-sm border-b border-amber-600/40 px-4 py-3">
      <div className="max-w-3xl mx-auto flex items-start gap-3">
        <span className="text-amber-400 text-lg shrink-0 mt-0.5">⚠</span>
        <div className="flex-1 text-sm text-amber-100 space-y-1">
          <p className="font-semibold">
            {isBrave ? 'Brave Shields are blocking this page' : 'A browser shield or extension is blocking this page'}
          </p>
          <p className="text-amber-200/80 text-xs leading-relaxed">
            {isBrave
              ? <>Click the <strong>Brave shield icon</strong> (🦁) in your address bar → set Shields to <strong>Off</strong> for this site, then reload.</>
              : <>Disable your ad blocker or privacy extension for this site, or try a different browser.</>
            }
            {' '}Lookups use only official public APIs — no tracking, no ads.
          </p>
        </div>
        <button
          onClick={() => { setShow(false); setDismissed(true) }}
          className="text-amber-400/70 hover:text-amber-200 text-lg leading-none shrink-0 transition-colors"
          aria-label="Dismiss"
        >
          ✕
        </button>
      </div>
    </div>
  )
}
