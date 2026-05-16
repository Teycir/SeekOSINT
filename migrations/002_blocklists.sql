-- Migration: move Feodo and SSLBL blocklists from KV blobs to D1 tables.
--
-- Run against your D1 database:
--   wrangler d1 execute seek-osint --remote --file=migrations/002_blocklists.sql
--
-- Lookups go from O(n) in-memory array scan → O(log n) indexed SELECT.
-- Refresh is handled by the cron worker (worker/cron.ts) every hour.

-- ─── Feodo C2 IP blocklist ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS feodo_blocklist (
  ip_address   TEXT PRIMARY KEY,
  port         INTEGER,
  status       TEXT,
  hostname     TEXT,
  as_number    INTEGER,
  as_name      TEXT,
  country      TEXT,
  first_seen   TEXT,
  last_seen    TEXT,
  malware      TEXT
);

-- ─── SSLBL certificate blocklist ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sslbl_blocklist (
  sha1              TEXT PRIMARY KEY,
  listing_date      TEXT,
  listing_time      TEXT,
  suspicious_reason TEXT,
  dst_ip            TEXT,
  dst_port          INTEGER,
  subject           TEXT
);

-- Index on dst_ip so IP-based lookups are fast
CREATE INDEX IF NOT EXISTS idx_sslbl_dst_ip ON sslbl_blocklist (dst_ip);

-- ─── Refresh metadata ─────────────────────────────────────────────────────────
-- Tracks when each blocklist was last successfully refreshed.
-- The cron checks this before deciding whether to re-download.

CREATE TABLE IF NOT EXISTS blocklist_meta (
  name         TEXT PRIMARY KEY,   -- 'feodo' | 'sslbl'
  refreshed_at INTEGER NOT NULL    -- unix seconds
);
