/**
 * lib/searches.ts — D1 helpers for the `searches` table.
 *
 * recordSearch   — insert a completed lookup row (fire-and-forget safe)
 * getRecentSearches — last N distinct queries ordered by recency
 */
import type { D1Database } from '@cloudflare/workers-types'
import type { QueryType } from './types'

export interface RecentSearch {
  query:      string
  query_type: QueryType
  created_at: number   // unix seconds
}

/**
 * Insert a search record.  Safe to call inside ctx.waitUntil().
 * result_json is stored for potential future "last result" fast-path.
 */
export async function recordSearch(
  db:         D1Database,
  query:      string,
  queryType:  QueryType,
  resultJson: string,
  durationMs: number,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO searches (query, query_type, result_json, duration_ms, created_at)
       VALUES (?, ?, ?, ?, unixepoch())`,
    )
    .bind(query, queryType, resultJson, durationMs)
    .run()
}

/**
 * Return the `limit` most-recent distinct queries (deduplicated — keep newest).
 * Uses a subquery so we get one row per canonical query value.
 */
export async function getRecentSearches(
  db:    D1Database,
  limit: number = 10,
): Promise<RecentSearch[]> {
  const { results } = await db
    .prepare(
      `SELECT query, query_type, MAX(created_at) AS created_at
       FROM searches
       GROUP BY query
       ORDER BY created_at DESC
       LIMIT ?`,
    )
    .bind(limit)
    .all<RecentSearch>()

  return results ?? []
}
