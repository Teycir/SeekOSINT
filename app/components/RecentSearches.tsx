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
    fetch('/api/recent?limit=3')
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
    <div className="w-full space-y-3">
      <p className="text-[10px] uppercase tracking-widest text-neon-red/30 font-mono text-center">
        recent
      </p>
      <ul className="flex flex-col gap-2">
        {searches.map(s => (
          <li key={s.query}>
            <button
              onClick={() => handleClick(s.query)}
              disabled={navigating !== null}
              className="w-full flex items-center gap-3 rounded-lg px-4 py-3
                         font-mono text-left
                         border border-neon-red/10
                         hover:border-neon-red/30 hover:bg-neon-red/5
                         transition-all duration-150
                         disabled:cursor-not-allowed"
            >
              <span className="text-neon-red/30 select-none text-base shrink-0" aria-hidden>
                {navigating === s.query
                  ? <span className="inline-block h-3 w-3 animate-spin rounded-full border border-neon-red/30 border-t-neon-red/70" />
                  : TYPE_ICON[s.query_type] ?? '·'
                }
              </span>
              <span className="flex-1 min-w-0">
                <span className={`block truncate text-sm ${navigating === s.query ? 'text-neon-red/80' : 'text-neon-red/70 group-hover:text-neon-red'}`}>
                  {s.query}
                </span>
                <span className="block text-[10px] text-neon-red/25 mt-0.5 uppercase tracking-wider">
                  {s.query_type}
                </span>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}
