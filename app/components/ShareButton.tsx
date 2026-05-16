/**
 * app/components/ShareButton.tsx
 *
 * Copies the current page URL to clipboard.
 * Falls back to navigator.share() on mobile if available.
 */
'use client'

import { useState } from 'react'
import { Tooltip } from './Tooltip'

export function ShareButton({ query }: { query: string }) {
  const [copied, setCopied] = useState(false)

  async function share() {
    const url = `${window.location.origin}/host/${encodeURIComponent(query)}`

    if (navigator.share) {
      try {
        await navigator.share({ title: `seekosint — ${query}`, url })
        return
      } catch (err) {
        console.debug('[ShareButton] share cancelled or failed:', err)
      }
    }

    try {
      await navigator.clipboard.writeText(url)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.warn('[ShareButton] clipboard write failed:', err)
    }
  }

  return (
    <Tooltip label={copied ? 'Link copied!' : 'Copy link to this result'}>
      <button
        onClick={share}
        className={`text-xs font-mono transition-colors duration-150
                    ${copied
                      ? 'text-green-400'
                      : 'text-neutral-500 hover:text-white'
                    }`}
      >
        {copied ? '✓ copied' : '⎘ share'}
      </button>
    </Tooltip>
  )
}
