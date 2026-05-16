/**
 * app/components/RefreshButton.tsx
 *
 * Client button that navigates to ?refresh=1 and shows a spinner
 * while the SSR page loads — prevents the dead-click feeling on slow connections.
 */
'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'

export function RefreshButton({ query }: { query: string }) {
  const router = useRouter()
  const [loading, setLoading] = useState(false)

  function handleRefresh() {
    setLoading(true)
    router.push(`/host/${encodeURIComponent(query)}?refresh=1`)
  }

  return (
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
  )
}
