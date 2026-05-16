/**
 * app/components/SavedList.tsx
 *
 * Client component for the /saved page.
 * Features:
 *   - optimistic delete
 *   - inline label editing (click pencil → input → confirm/cancel)
 *   - risk badge from stored snapshot
 *   - last-checked timestamp
 *   - navigate to result page
 */
'use client'

import { useState, useRef } from 'react'
import type { SavedTarget } from '../../lib/targets'
import { Tooltip } from './Tooltip'

// ── Risk badge (mirrors RiskBadge but self-contained for the list) ────────────
function RiskPill({ score }: { score: number | null }) {
  if (score === null) return <span className="text-xs text-neutral-600 font-mono">—</span>
  const color =
    score >= 70 ? 'text-red-400 border-red-800' :
    score >= 35 ? 'text-amber-400 border-amber-800' :
                  'text-green-400 border-green-800'
  const label =
    score >= 70 ? 'HIGH' :
    score >= 35 ? 'MED'  : 'LOW'
  return (
    <span className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-mono ${color}`}>
      {score} · {label}
    </span>
  )
}

// ── Relative time helper ──────────────────────────────────────────────────────
function relTime(unixSec: number | null): string {
  if (!unixSec) return 'never'
  const diff = Math.floor((Date.now() / 1000) - unixSec)
  if (diff < 60)          return 'just now'
  if (diff < 3600)        return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400)       return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

// ── Row component ─────────────────────────────────────────────────────────────
function TargetRow({
  target,
  onDelete,
  onRelabel,
}: {
  target: SavedTarget & { riskScore?: number | null }
  onDelete: (id: string) => void
  onRelabel: (id: string, label: string) => Promise<void>
}) {
  const [editing,   setEditing]   = useState(false)
  const [labelVal,  setLabelVal]  = useState(target.label ?? '')
  const [saving,    setSaving]    = useState(false)
  const [deleting,  setDeleting]  = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  async function confirmLabel() {
    setSaving(true)
    await onRelabel(target.id, labelVal.trim())
    setSaving(false)
    setEditing(false)
  }

  function cancelLabel() {
    setLabelVal(target.label ?? '')
    setEditing(false)
  }

  async function handleDelete() {
    setDeleting(true)
    await fetch(`/api/targets/${target.id}`, { method: 'DELETE' })
    onDelete(target.id)
  }

  return (
    <div
      className={`rounded-xl border border-neutral-800 bg-neutral-900 px-5 py-4
                  transition-opacity duration-300 ${deleting ? 'opacity-40 pointer-events-none' : ''}`}
    >
      {/* top row: query + risk + checked */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <a
          href={`/host/${encodeURIComponent(target.query)}`}
          className="font-mono text-sm text-white hover:text-neon-red transition-colors"
        >
          {target.query}
        </a>
        <div className="flex items-center gap-3 shrink-0">
          <RiskPill score={target.riskScore ?? null} />
          <span className="text-[10px] text-neutral-600 font-mono">
            checked {relTime(target.checked_at)}
          </span>
        </div>
      </div>

      {/* label row */}
      <div className="mt-2 flex items-center gap-2 min-h-[24px]">
        {editing ? (
          <>
            <input
              ref={inputRef}
              value={labelVal}
              onChange={e => setLabelVal(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') confirmLabel()
                if (e.key === 'Escape') cancelLabel()
              }}
              maxLength={100}
              placeholder="Add a label…"
              autoFocus
              className="flex-1 bg-neutral-800 border border-neutral-700 rounded px-2 py-0.5
                         text-xs font-mono text-white placeholder-neutral-600
                         focus:outline-none focus:border-neon-red/60"
            />
            <button
              onClick={confirmLabel}
              disabled={saving}
              className="text-[10px] font-mono text-green-400 hover:text-green-300 disabled:opacity-50"
            >
              {saving ? '…' : '✓'}
            </button>
            <button
              onClick={cancelLabel}
              className="text-[10px] font-mono text-neutral-500 hover:text-white"
            >
              ✕
            </button>
          </>
        ) : (
          <>
            <span className="text-xs text-neutral-500 font-mono flex-1">
              {target.label ?? <span className="italic text-neutral-700">no label</span>}
            </span>
            <Tooltip label="Edit label">
              <button
                onClick={() => { setEditing(true); setTimeout(() => inputRef.current?.focus(), 0) }}
                className="text-[10px] text-neutral-600 hover:text-neon-red font-mono transition-colors"
              >
                ✎
              </button>
            </Tooltip>
            <Tooltip label="Delete target">
              <button
                onClick={handleDelete}
                className="text-[10px] text-neutral-600 hover:text-red-400 font-mono transition-colors"
              >
                ✕
              </button>
            </Tooltip>
            <Tooltip label="Open result">
              <a
                href={`/host/${encodeURIComponent(target.query)}`}
                className="text-[10px] text-neutral-600 hover:text-neon-red font-mono transition-colors"
              >
                →
              </a>
            </Tooltip>
          </>
        )}
      </div>
    </div>
  )
}

// ── Main list ─────────────────────────────────────────────────────────────────
export function SavedList({
  initialTargets,
}: {
  initialTargets: (SavedTarget & { riskScore?: number | null })[]
}) {
  const [targets, setTargets] = useState(initialTargets)

  function handleDelete(id: string) {
    setTargets(prev => prev.filter(t => t.id !== id))
  }

  async function handleRelabel(id: string, label: string) {
    const target = targets.find(t => t.id === id)
    if (!target) return
    // Re-POST the same query with the new label (upsert is idempotent)
    await fetch('/api/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: target.query, label: label || null }),
    })
    setTargets(prev =>
      prev.map(t => t.id === id ? { ...t, label: label || null } : t),
    )
  }

  if (targets.length === 0) {
    return (
      <div className="rounded-xl border border-neutral-800 bg-neutral-900 px-5 py-12 text-center">
        <p className="text-sm text-neutral-500 font-mono">No saved targets yet.</p>
        <p className="text-xs text-neutral-700 mt-1 font-mono">
          Hit <span className="text-neutral-500">☆ save</span> on any result page.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {targets.map(t => (
        <TargetRow
          key={t.id}
          target={t}
          onDelete={handleDelete}
          onRelabel={handleRelabel}
        />
      ))}
    </div>
  )
}
