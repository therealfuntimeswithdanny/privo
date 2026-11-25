-- User API keys for the Privo API. Only the SHA-256 of each key is stored;
-- the full key ("pv_…") is shown once at creation and can never be recovered.
CREATE TABLE IF NOT EXISTS api_keys (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  scopes       TEXT NOT NULL DEFAULT 'links:write', -- comma-separated, e.g. 'links:write,links:custom'
  prefix       TEXT NOT NULL,              -- "pv_xxxxxxxx…" display prefix
  key_hash     TEXT NOT NULL UNIQUE,       -- hex SHA-256 of the full key
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  revoked_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
