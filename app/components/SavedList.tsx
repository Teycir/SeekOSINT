/**
 * app/components/SavedList.tsx
 *
 * Client component for the /saved page.
 * Features:
 *   - optimistic delete (single row)
 *   - purge all — with inline confirm step
 *   - inline label editing (click pencil → input → confirm/cancel)
 *   - risk badge from stored snapshot
 *   - last-checked timestamp
 *   - threshold warning banner (≥ 75 targets)
 *   - auto-prune toast (shown when POST trims oldest entries)
 *   - navigate to result page
 */
'use client'

import { useState, useRef, useEffect } from 'react'
import type { SavedTarget } from '../../lib/targets'
import { Tooltip } from './Tooltip'

const WARN_THRESHOLD = 75
const SOFT_CAP       = 100

// ── Risk badge ────────────────────────────────────────────────────────────────
function RiskPill({ score }: { score: number | null }) {
  if (score === null) return <span className="text-xs text-neutral-600 font-mono">—</span>
  const color =
    score >= 70 ? 'text-red-400 border-red-800' :
    score >= 35 ? 'text-amber-400 border-amber-800' :
                  'text-green-400 border-green-800'
  const label = score >= 70 ? 'HIGH' : score >= 35 ? 'MED' : 'LOW'
  return (
    <span className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-mono ${color}`}>
      {score} · {label}
    </span>
  )
}

// ── Relative time ─────────────────────────────────────────────────────────────
function relTime(unixSec: number | null): string {
  if (!unixSec) return 'never'
  const diff = Math.floor(Date.now() / 1000 - unixSec)
  if (diff < 60)    return 'just now'
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function Toast({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 5000)
    return () => clearTimeout(t)
  }, [onDismiss])
  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50
                    flex items-center gap-3 rounded-lg border border-amber-700/50
                    bg-neutral-900 px-4 py-3 shadow-xl text-sm font-mono text-amber-300
                    animate-in fade-in slide-in-from-bottom-2 duration-200">
      <span>⚠</span>
      <span>{message}</span>
      <button
        onClick={onDismiss}
        className="text-neutral-500 hover:text-white transition-colors ml-2"
      >
        ✕
      </button>
    </div>
  )
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
  const [editing,  setEditing]  = useState(false)
  const [labelVal, setLabelVal] = useState(target.label ?? '')
  const [saving,   setSaving]   = useState(false)
  const [deleting, setDeleting] = useState(false)
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
      {/* top row */}
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

// ── Purge confirm button ──────────────────────────────────────────────────────
function PurgeAllButton({ onPurge }: { onPurge: () => Promise<void> }) {
  const [phase,    setPhase]    = useState<'idle' | 'confirm' | 'purging'>('idle')
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  function requestConfirm() {
    setPhase('confirm')
    // Auto-cancel the confirm step after 4 s if the user doesn't click through.
    timerRef.current = setTimeout(() => setPhase('idle'), 4000)
  }

  function cancel() {
    if (timerRef.current) clearTimeout(timerRef.current)
    setPhase('idle')
  }

  async function confirm() {
    if (timerRef.current) clearTimeout(timerRef.current)
    setPhase('purging')
    await onPurge()
    setPhase('idle')
  }

  if (phase === 'confirm') {
    return (
      <div className="flex items-center gap-2 animate-in fade-in duration-150">
        <span className="text-xs font-mono text-red-400">Delete all?</span>
        <button
          onClick={confirm}
          className="text-xs font-mono text-red-400 hover:text-red-300
                     border border-red-800/60 rounded px-2 py-0.5 transition-colors"
        >
          yes, purge
        </button>
        <button
          onClick={cancel}
          className="text-xs font-mono text-neutral-500 hover:text-white transition-colors"
        >
          cancel
        </button>
      </div>
    )
  }

  return (
    <Tooltip label="Delete all saved targets">
      <button
        onClick={requestConfirm}
        disabled={phase === 'purging'}
        className="text-xs font-mono text-neutral-600 hover:text-red-400
                   border border-neutral-800 hover:border-red-800/50
                   rounded px-3 py-1 transition-colors disabled:opacity-40"
      >
        {phase === 'purging' ? 'purging…' : 'purge all'}
      </button>
    </Tooltip>
  )
}

// ── Threshold warning banner ──────────────────────────────────────────────────
function ThresholdBanner({ count }: { count: number }) {
  const pct   = Math.round((count / SOFT_CAP) * 100)
  const atCap = count >= SOFT_CAP

  return (
    <div
      className={`rounded-lg border px-4 py-3 text-xs font-mono space-y-1
                  ${atCap
                    ? 'border-red-800/50 bg-red-950/20 text-red-300'
                    : 'border-amber-800/40 bg-amber-950/15 text-amber-400'}`}
    >
      <div className="flex items-center justify-between gap-2">
        <span>
          {atCap
            ? `⚠ Cap reached (${count}/${SOFT_CAP}) — oldest entries auto-pruned when you save new targets.`
            : `⚠ ${count}/${SOFT_CAP} targets saved (${pct}%) — oldest will be pruned after ${SOFT_CAP}.`}
        </span>
      </div>
      {/* progress bar */}
      <div className="h-1 w-full rounded-full bg-neutral-800 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500
                      ${atCap ? 'bg-red-500' : 'bg-amber-500'}`}
          style={{ width: `${Math.min(pct, 100)}%` }}
        />
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
  const [toast,   setToast]   = useState<string | null>(null)

  function handleDelete(id: string) {
    setTargets(prev => prev.filter(t => t.id !== id))
  }

  async function handleRelabel(id: string, label: string) {
    const target = targets.find(t => t.id === id)
    if (!target) return
    await fetch('/api/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: target.query, label: label || null }),
    })
    setTargets(prev =>
      prev.map(t => t.id === id ? { ...t, label: label || null } : t),
    )
  }

  async function handlePurgeAll() {
    await fetch('/api/targets', { method: 'DELETE' })
    setTargets([])
    setToast(null)
  }

  const nearingCap = targets.length >= WARN_THRESHOLD

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
    <>
      {/* threshold banner */}
      {nearingCap && <ThresholdBanner count={targets.length} />}

      {/* list header with count + purge all */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-neutral-600 font-mono">
          {targets.length} {targets.length === 1 ? 'target' : 'targets'}
          {nearingCap && (
            <span className={targets.length >= SOFT_CAP ? ' text-red-400' : ' text-amber-500'}>
              {' '}/ {SOFT_CAP} cap
            </span>
          )}
        </span>
        <PurgeAllButton onPurge={handlePurgeAll} />
      </div>

      {/* rows */}
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

      {/* toast */}
      {toast && <Toast message={toast} onDismiss={() => setToast(null)} />}
    </>
  )
}
