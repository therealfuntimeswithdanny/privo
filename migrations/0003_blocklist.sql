-- Admin-curated destination blocklist. Entries are hostnames; a host or any
-- of its subdomains matching an entry is refused at create/edit/serve time.

CREATE TABLE IF NOT EXISTS blocklist (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  host       TEXT NOT NULL UNIQUE,          -- e.g. "evil.com"
  note       TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_blocklist_host ON blocklist(host);
