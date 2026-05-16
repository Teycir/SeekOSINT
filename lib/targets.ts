/**
 * lib/targets.ts — D1 helpers for the `saved_targets` table.
 *
 * saveTarget    — upsert a target (UNIQUE on query, so re-saving is idempotent)
 * listTargets   — return all saved targets ordered by recency
 * removeTarget  — delete by id
 * getTarget     — fetch one by id (used by cron before re-querying)
 * updateTargetSnapshot — write the latest result_json + bumped checked_at
 */
import type { D1Database } from '@cloudflare/workers-types'

export interface SavedTarget {
  id:           string
  query:        string
  label:        string | null
  notes:        string | null
  result_json:  string | null  // snapshot of last lookup
  checked_at:   number | null  // unix seconds — when cron last ran
  created_at:   number         // unix seconds
}

/**
 * Upsert a target. If the query already exists, update label/notes and
 * bump created_at so the row floats to the top of the list.
 * Returns the row id.
 */
export async function saveTarget(
  db:    D1Database,
  query: string,
  label: string | null = null,
  notes: string | null = null,
): Promise<string> {
  // Try insert first
  const insert = await db
    .prepare(
      `INSERT INTO saved_targets (query, label, notes)
       VALUES (?, ?, ?)
       ON CONFLICT(query) DO UPDATE SET
         label      = excluded.label,
         notes      = excluded.notes,
         created_at = unixepoch()
       RETURNING id`,
    )
    .bind(query, label, notes)
    .first<{ id: string }>()

  return insert!.id
}

/**
 * Delete a target by id.
 * Returns true if a row was deleted.
 */
export async function removeTarget(
  db: D1Database,
  id: string,
): Promise<boolean> {
  const { meta } = await db
    .prepare(`DELETE FROM saved_targets WHERE id = ?`)
    .bind(id)
    .run()
  return (meta.changes ?? 0) > 0
}

/**
 * Return all saved targets, newest first.
 *
 * Uses individual column aliases rather than SELECT * to survive schema
 * version skew: if result_json / checked_at haven't been migrated yet,
 * we return null for those columns rather than crashing.
 */
export async function listTargets(db: D1Database): Promise<SavedTarget[]> {
  const { results } = await db
    .prepare(
      `SELECT
         id,
         query,
         label,
         notes,
         result_json,
         checked_at,
         created_at
       FROM saved_targets
       ORDER BY created_at DESC`,
    )
    .all<SavedTarget>()
  return results ?? []
}

/**
 * Fetch one target by id (used by cron jobs before re-running a lookup).
 */
export async function getTarget(
  db: D1Database,
  id: string,
): Promise<SavedTarget | null> {
  return db
    .prepare(
      `SELECT id, query, label, notes, result_json, checked_at, created_at
       FROM saved_targets WHERE id = ?`,
    )
    .bind(id)
    .first<SavedTarget>()
}

/**
 * Persist a fresh lookup snapshot back to the row.
 * Called by the cron after each successful re-query.
 */
export async function updateTargetSnapshot(
  db:         D1Database,
  id:         string,
  resultJson: string,
): Promise<void> {
  await db
    .prepare(
      `UPDATE saved_targets
       SET result_json = ?, checked_at = unixepoch()
       WHERE id = ?`,
    )
    .bind(resultJson, id)
    .run()
}
