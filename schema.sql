CREATE TABLE IF NOT EXISTS searches (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  query       TEXT NOT NULL,
  query_type  TEXT NOT NULL CHECK (query_type IN ('ip','domain','asn')),
  result_json TEXT NOT NULL,
  duration_ms INTEGER,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_searches_query
  ON searches (query, created_at DESC);

CREATE TABLE IF NOT EXISTS saved_targets (
  id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  query      TEXT NOT NULL UNIQUE,
  label      TEXT,
  notes      TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
