/**
 * app/components/Tooltip.tsx
 *
 * Lightweight CSS-only tooltip — red label on black, matching the seekosint theme.
 * Wraps any trigger element; the tooltip appears above on hover/focus.
 *
 * Usage:
 *   <Tooltip label="Copy link to this result">
 *     <button>⎘ share</button>
 *   </Tooltip>
 */
'use client'

import type { ReactNode } from 'react'

interface TooltipProps {
  label:    string
  children: ReactNode
  /** 'top' (default) | 'bottom' */
  side?: 'top' | 'bottom'
}

export function Tooltip({ label, children, side = 'top' }: TooltipProps) {
  const above = side === 'top'
  return (
    <span className="relative inline-flex group">
      {children}
      <span
        role="tooltip"
        className={[
          // positioning
          'pointer-events-none absolute left-1/2 -translate-x-1/2 z-50 whitespace-nowrap',
          above ? 'bottom-full mb-2' : 'top-full mt-2',
          // appearance
          'rounded border border-neon-red/40 bg-black px-2 py-1',
          'text-[10px] font-mono text-neon-red',
          // transition
          'opacity-0 scale-95 transition-all duration-150 origin-bottom',
          'group-hover:opacity-100 group-hover:scale-100',
          'group-focus-within:opacity-100 group-focus-within:scale-100',
        ].join(' ')}
      >
        {label}
        {/* arrow */}
        <span
          className={[
            'absolute left-1/2 -translate-x-1/2 border-4 border-transparent',
            above
              ? 'top-full border-t-neon-red/40'
              : 'bottom-full border-b-neon-red/40',
          ].join(' ')}
        />
      </span>
    </span>
  )
}
