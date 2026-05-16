/**
 * app/components/RecentSearches.tsx
 *
 * Client component — fetches /api/recent on mount and renders a clickable
 * list of recent queries. Hidden when empty or on fetch error.
 */
'use client'

import { useEffect, useState, useRef } from 'react'
import { useRouter } from 'next/navigation'

interface RecentSearch {
  query:      string
  query_type: 'ip' | 'domain' | 'asn'
  created_at: number
}

const TYPE_ICON: Record<string, string> = {
  ip:     '⬡',
  domain: '◈',
  asn:    '◎',
}

export function RecentSearches() {
  const router = useRouter()
  const [searches, setSearches] = useState<RecentSearch[]>([])
  const [navigating, setNavigating] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/recent?limit=5')
      .then(r => r.json())
      .then((d: unknown) => setSearches((d as { searches: RecentSearch[] }).searches ?? []))
      .catch(() => {/* silent — no DB in dev is fine */})
  }, [])

  if (searches.length === 0) return null

  function handleClick(query: string) {
    setNavigating(query)
    router.push(`/host/${encodeURIComponent(query)}`)
  }

  return (
    <div className="w-full space-y-2">
      <p className="text-[10px] uppercase tracking-widest text-neon-red/30 font-mono text-center">
        recent
      </p>
      <ul className="flex flex-col gap-1">
        {searches.map(s => (
          <li key={s.query}>
            <button
              onClick={() => handleClick(s.query)}
              disabled={navigating !== null}
              className="w-full flex items-center gap-2 rounded px-3 py-1.5
                         font-mono text-sm text-neon-red/50
                         hover:text-neon-red hover:bg-neon-red/5
                         transition-colors duration-150 text-left
                         disabled:cursor-not-allowed"
            >
              <span className="text-neon-red/25 select-none" aria-hidden>
                {navigating === s.query
                  ? <span className="inline-block h-3 w-3 animate-spin rounded-full border border-neon-red/30 border-t-neon-red/70" />
                  : TYPE_ICON[s.query_type] ?? '·'
                }
              </span>
              <span className={`flex-1 truncate ${navigating === s.query ? 'text-neon-red/80' : ''}`}>
                {s.query}
              </span>
              <span className="text-[10px] text-neon-red/20 shrink-0">
                {s.query_type}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}
