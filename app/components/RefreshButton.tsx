/**
 * app/components/RefreshButton.tsx
 *
 * Client button that navigates to ?refresh=1 and shows a spinner
 * while the SSR page loads — prevents the dead-click feeling on slow connections.
 *
 * After the refresh completes, the ?refresh=1 param is stripped from the URL
 * via router.replace() so bookmarks / shares don't force a cache bypass.
 */
'use client'

import { useState, useEffect, useRef } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Tooltip } from './Tooltip'

export function RefreshButton({ query }: { query: string }) {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [loading, setLoading] = useState(false)
  const didRefresh = useRef(false)

  useEffect(() => {
    if (!didRefresh.current) return
    didRefresh.current = false
    setLoading(false)
    router.replace(`/host/${encodeURIComponent(query)}`)
  }, [searchParams, query, router])

  function handleRefresh() {
    didRefresh.current = true
    setLoading(true)
    router.push(`/host/${encodeURIComponent(query)}?refresh=1`)
  }

  return (
    <Tooltip label={loading ? 'Refreshing…' : 'Bypass cache and re-fetch all sources'}>
      <button
        onClick={handleRefresh}
        disabled={loading}
        title="Bypass cache and re-fetch all sources"
        className="inline-flex items-center gap-1.5 text-xs text-neutral-500
                   hover:text-neon-red font-mono transition-colors
                   disabled:cursor-not-allowed disabled:opacity-50"
      >
        {loading ? (
          <span className="inline-block h-3 w-3 animate-spin rounded-full
                           border border-neon-red/30 border-t-neon-red/70" />
        ) : (
          <span>↺</span>
        )}
        refresh
      </button>
    </Tooltip>
  )
}
