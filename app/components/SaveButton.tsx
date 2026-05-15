/**
 * app/components/SaveButton.tsx
 *
 * Saves the current query to /api/targets (D1 saved_targets table).
 * Three states: idle → saving → saved (persists until page navigation).
 * Re-clicking a saved target is idempotent on the server (UPSERT).
 *
 * Usage:
 *   <SaveButton query="1.1.1.1" />
 *   <SaveButton query="example.com" label="Prod server" />
 */
'use client'

import { useState } from 'react'

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
    } catch {
      setState('error')
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
    idle:   'text-neutral-500 hover:text-white',
    saving: 'text-neutral-500 cursor-wait',
    saved:  'text-amber-400',
    error:  'text-red-400',
  }

  return (
    <button
      onClick={save}
      disabled={state === 'saving'}
      title={state === 'saved' ? 'Already saved — click to re-save' : `Save ${query} to watched targets`}
      className={`text-xs font-mono transition-colors duration-150 ${colorClass[state]}`}
    >
      {text[state]}
    </button>
  )
}
