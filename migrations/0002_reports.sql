-- Abuse reports submitted via /report.

CREATE TABLE IF NOT EXISTS reports (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  url         TEXT NOT NULL,               -- the reported link/destination
  reason      TEXT NOT NULL DEFAULT 'other'
              CHECK (reason IN ('phishing','malware','spam','illegal','other')),
  details     TEXT,
  contact     TEXT,                        -- optional reporter email/handle
  reporter_ua TEXT,                        -- user agent only, no IPs
  status      TEXT NOT NULL DEFAULT 'open'
              CHECK (status IN ('open','resolved','dismissed')),
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status, created_at DESC);
