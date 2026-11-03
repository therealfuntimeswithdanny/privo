-- Step 1 of 2. Moves the ORIGINAL links table (shortcode PRIMARY KEY, no owner) to the
-- new shape. Needed because cloud-schema.sql uses CREATE TABLE IF NOT EXISTS, which skips
-- `links` when an old one already exists. Run this, THEN cloud-schema.sql again:
--   npx wrangler d1 execute <DB_NAME> --remote --file=./cloud-links-migration.sql
--   npx wrangler d1 execute <DB_NAME> --remote --file=./cloud-schema.sql
-- Existing links keep their shortcode, destination, SEO, image and Web Risk status,
-- and become anonymous (no created_by), so they don't count toward anyone's usage.

-- Clear anything a half-run of cloud-schema.sql may have left on the old table.
DROP TRIGGER IF EXISTS links_bi_limit;
DROP TRIGGER IF EXISTS links_ai;
DROP TRIGGER IF EXISTS links_au_touch;
DROP TRIGGER IF EXISTS links_au_usage;
DROP TRIGGER IF EXISTS links_au_audit;
DROP TRIGGER IF EXISTS links_ad;
DROP INDEX IF EXISTS idx_links_created_by;
DROP INDEX IF EXISTS idx_links_team;
DROP INDEX IF EXISTS idx_links_recheck;

ALTER TABLE links RENAME TO links_old;

CREATE TABLE links (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  domain          TEXT NOT NULL DEFAULT 'privo.fyi',
  shortcode       TEXT NOT NULL,
  url             TEXT NOT NULL,
  created_by      TEXT REFERENCES users(id) ON DELETE SET NULL,
  team_id         INTEGER REFERENCES teams(id) ON DELETE SET NULL,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_by      TEXT,
  title           TEXT,
  description     TEXT,
  image           TEXT,
  site_name       TEXT,
  seo_custom      INTEGER NOT NULL DEFAULT 0,
  meta_fetched_at TEXT,
  image_cached    INTEGER NOT NULL DEFAULT 0,
  safety_status     TEXT NOT NULL DEFAULT 'unchecked',
  safety_threats    TEXT,
  safety_checked_at TEXT,
  UNIQUE (domain, shortcode)
);

INSERT INTO links (
  shortcode, url, created_at, updated_at, title, description, image, site_name,
  meta_fetched_at, image_cached, safety_status, safety_threats, safety_checked_at
)
SELECT
  shortcode, url,
  COALESCE(created_at, datetime('now')), COALESCE(created_at, datetime('now')),
  title, description, image, site_name,
  meta_fetched_at, COALESCE(image_cached, 0), COALESCE(safety_status, 'unchecked'),
  safety_threats, safety_checked_at
FROM links_old;

DROP TABLE links_old;