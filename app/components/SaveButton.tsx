/**
 * app/components/SaveButton.tsx
 *
 * Saves the current query to /api/targets (D1 saved_targets table).
 * Three states: idle → saving → saved (persists until page navigation).
 * Re-clicking a saved target is idempotent on the server (UPSERT).
 */
'use client'

import { useState } from 'react'
import { Tooltip } from './Tooltip'

interface SaveButtonProps {
  query: string
  label?: string
}

type State = 'idle' | 'saving' | 'saved' | 'error'

export function SaveButton({ query, label }: SaveButtonProps) {
  const [state, setState] = useState<State>('idle')

  async function save() {
    if (state === 'saving' || state === 'saved') return
    setState('saving')
    try {
      const res = await fetch('/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, label: label ?? null }),
      })
      setState(res.ok ? 'saved' : 'error')
      if (!res.ok) setTimeout(() => setState('idle'), 3000)
    } catch (err) {
      setState('error')
      console.error('[SaveButton] save failed:', err)
      setTimeout(() => setState('idle'), 3000)
    }
  }

  const text: Record<State, string> = {
    idle:   '☆ save',
    saving: '…',
    saved:  '★ saved',
    error:  '✕ failed',
  }

  const colorClass: Record<State, string> = {
    idle:   'border-neutral-700 text-neutral-400 hover:border-neutral-500 hover:text-white hover:bg-neutral-800',
    saving: 'border-neutral-700 text-neutral-500 cursor-wait',
    saved:  'border-amber-500/50 text-amber-400 bg-amber-500/10',
    error:  'border-red-500/50 text-red-400',
  }

  const tooltipLabel: Record<State, string> = {
    idle:   `Save ${query} to watched targets`,
    saving: 'Saving…',
    saved:  'Saved — manage in /saved',
    error:  'Save failed — retry?',
  }

  return (
    <Tooltip label={tooltipLabel[state]}>
      <button
        onClick={save}
        disabled={state === 'saving'}
        className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5
                    text-sm font-mono transition-all duration-150 ${colorClass[state]}`}
      >
        {text[state]}
      </button>
    </Tooltip>
  )
}
