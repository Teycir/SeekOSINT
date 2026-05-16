/**
 * app/components/CopyButton.tsx
 *
 * Inline copy-to-clipboard button. Renders as a small icon next to any value.
 * Shows a ✓ tick for 1.5s after copying, then resets.
 *
 * Usage:
 *   <CopyButton value="1.1.1.1" />
 *   <CopyButton value="AS13335" label="copy ASN" />
 */
'use client'

import { useState } from 'react'

interface CopyButtonProps {
  value: string
  label?: string
  className?: string
}

export function CopyButton({ value, label, className = '' }: CopyButtonProps) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch (err) {
      // clipboard API unavailable — silently ignore
      console.warn('[CopyButton] clipboard write failed:', err)
    }
  }

  return (
    <button
      onClick={copy}
      title={label ?? `Copy ${value}`}
      aria-label={label ?? `Copy ${value}`}
      className={`inline-flex items-center justify-center rounded px-1 py-0.5
                  text-[10px] font-mono transition-colors duration-150 select-none
                  ${copied
                    ? 'text-green-400'
                    : 'text-neutral-600 hover:text-neutral-300'
                  } ${className}`}
    >
      {copied ? '✓' : '⎘'}
    </button>
  )
}
