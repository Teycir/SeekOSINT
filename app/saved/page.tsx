/**
 * app/saved/page.tsx
 *
 * Saved targets manager — lists all entries from D1, allows:
 *   • navigate to the result page
 *   • inline label editing (re-POST with new label)
 *   • delete (DELETE /api/targets/:id)
 *
 * SSR shell + client interactivity via the SavedList component.
 */
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { listTargets } from '../../lib/targets'
import type { Env } from '../../lib/types'
import type { Metadata } from 'next'
import { SavedList } from '../components/SavedList'

export const metadata: Metadata = {
  title: 'Saved targets — seekosint',
  description: 'Manage your watched hosts and domains',
}

export default async function SavedPage() {
  let targets: Awaited<ReturnType<typeof listTargets>> = []
  try {
    const { env } = getCloudflareContext()
    const db = (env as unknown as Env).DB
    if (db) targets = await listTargets(db)
  } catch (err) {
    console.error('[SavedPage] listTargets failed:', err)
  }

  return (
    <main className="min-h-screen bg-neutral-950 px-4 pt-14 pb-10 sm:pt-10">
      <div className="mx-auto max-w-3xl space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="font-mono text-xl font-semibold text-white">Saved targets</h1>
            <p className="text-xs text-neutral-500 mt-1">
              {targets.length} {targets.length === 1 ? 'target' : 'targets'} watched
            </p>
          </div>
          <a
            href="/"
            className="text-sm text-neutral-500 hover:text-white font-mono transition-colors"
          >
            ← back
          </a>
        </div>
        <SavedList initialTargets={targets} />
      </div>
    </main>
  )
}
