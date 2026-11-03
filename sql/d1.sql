-- Privo Cloud: links, teams, custom domains, usage limits, audit logs.
-- Run AFTER accounts-schema.sql, against the same ACCOUNTS D1 database:
--   npx wrangler d1 execute <ACCOUNTS_DB_NAME> --remote --file=./cloud-schema.sql
--
-- One database on purpose: D1 can't join or run triggers across databases, so
-- keeping links, usage and logs together lets triggers keep the counters exact
-- and enforce the limits even if a Worker bug forgets to.
--
-- Limits per account: teams 10, custom domains 10, R2 3 GB, D1 1 GB, links unlimited.
-- Timestamps here use datetime('now') ("YYYY-MM-DD HH:MM:SS", UTC) to match the old links table.

-- ==========================================
-- Usage + limits (one row per account)
-- ==========================================
CREATE TABLE IF NOT EXISTS usage (
  user_id      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,

  teams        INTEGER NOT NULL DEFAULT 0,   -- teams this account owns
  domains      INTEGER NOT NULL DEFAULT 0,   -- custom domains
  links        INTEGER NOT NULL DEFAULT 0,   -- unlimited
  r2_bytes     INTEGER NOT NULL DEFAULT 0,   -- uploaded files
  d1_bytes     INTEGER NOT NULL DEFAULT 0,   -- estimated: links + audit logs
  d1_writes    INTEGER NOT NULL DEFAULT 0,   -- row writes made through the account

  max_teams    INTEGER NOT NULL DEFAULT 10,
  max_domains  INTEGER NOT NULL DEFAULT 10,
  max_r2_bytes INTEGER NOT NULL DEFAULT 3221225472,  -- 3 GB
  max_d1_bytes INTEGER NOT NULL DEFAULT 1073741824   -- 1 GB
);

-- Every new user gets a usage row.
CREATE TRIGGER IF NOT EXISTS users_ai_usage AFTER INSERT ON users
BEGIN
  INSERT OR IGNORE INTO usage (user_id) VALUES (NEW.id);
END;

-- Users that existed before this file ran.
INSERT OR IGNORE INTO usage (user_id) SELECT id FROM users;

-- ==========================================
-- Teams (max 10 owned per account)
-- ==========================================
CREATE TABLE IF NOT EXISTS teams (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_teams_owner ON teams(owner_id);

CREATE TABLE IF NOT EXISTS team_members (
  team_id    INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role       TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (team_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);

-- ==========================================
-- Custom domains (max 10 per account)
-- ==========================================
CREATE TABLE IF NOT EXISTS domains (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  team_id    INTEGER REFERENCES teams(id) ON DELETE SET NULL,
  hostname   TEXT NOT NULL UNIQUE,            -- lowercase, e.g. go.example.com
  verified   INTEGER NOT NULL DEFAULT 0,      -- 1 once DNS is confirmed
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_domains_owner ON domains(owner_id);

-- ==========================================
-- Links
-- ==========================================
-- Same column names as the original links table, so rows exported from it import
-- as-is (see the migration note at the bottom). A link is the pair
-- (domain, shortcode): privo.fyi/mylink or mydomain.com/promo.
CREATE TABLE IF NOT EXISTS links (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,

  domain          TEXT NOT NULL DEFAULT 'privo.fyi',  -- 'privo.fyi' or a verified custom domain
  shortcode       TEXT NOT NULL,
  url             TEXT NOT NULL,                      -- where it redirects to

  created_by      TEXT REFERENCES users(id) ON DELETE SET NULL,  -- NULL = made without an account
  team_id         INTEGER REFERENCES teams(id) ON DELETE SET NULL,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now')),       -- last modified (set by trigger)
  updated_by      TEXT,                                          -- set by the Worker on edits

  -- SEO shown on the short link page
  title           TEXT,
  description     TEXT,
  image           TEXT,
  site_name       TEXT,
  seo_custom      INTEGER NOT NULL DEFAULT 0,         -- 1 = edited by the owner, never overwrite by re-fetching
  meta_fetched_at TEXT,
  image_cached    INTEGER NOT NULL DEFAULT 0,         -- 0 none, 1 copy in R2, 2 failed

  -- Google Web Risk
  safety_status     TEXT NOT NULL DEFAULT 'unchecked',
  safety_threats    TEXT,
  safety_checked_at TEXT,

  UNIQUE (domain, shortcode)
);
CREATE INDEX IF NOT EXISTS idx_links_created_by ON links(created_by);
CREATE INDEX IF NOT EXISTS idx_links_team ON links(team_id);
CREATE INDEX IF NOT EXISTS idx_links_recheck ON links(safety_checked_at);

-- ==========================================
-- R2 files (max 3 GB per account)
-- ==========================================
CREATE TABLE IF NOT EXISTS r2_files (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  r2_key       TEXT NOT NULL UNIQUE,          -- object key in the bucket
  file_url     TEXT NOT NULL,                 -- link to the file
  content_type TEXT,
  size_bytes   INTEGER NOT NULL CHECK (size_bytes >= 0),
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_r2_files_user ON r2_files(user_id);

-- ==========================================
-- Audit logs (count toward D1 usage)
-- ==========================================
-- One table, four kinds of row. Only the columns for a row's category are filled:
--   signin  signin_method, ip, country, os, browser
--   link    short_link, direct_url, (user_id = who did it)   action: create | update | delete
--   r2      r2_key, file_url, bytes                          action: upload | delete
--   d1      db_table, db_rows                                action: insert | update | delete
CREATE TABLE IF NOT EXISTS audit_logs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       TEXT REFERENCES users(id) ON DELETE CASCADE,
  category      TEXT NOT NULL CHECK (category IN ('signin', 'link', 'r2', 'd1')),
  action        TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),

  signin_method TEXT,   -- google, github, bluesky, ...
  ip            TEXT,
  country       TEXT,   -- request.cf.country
  os            TEXT,
  browser       TEXT,

  short_link    TEXT,   -- https://privo.fyi/abc123
  direct_url    TEXT,

  r2_key        TEXT,
  file_url      TEXT,
  bytes         INTEGER,

  db_table      TEXT,
  db_rows       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_logs(category, created_at DESC);

-- ==========================================
-- Triggers: teams
-- ==========================================
CREATE TRIGGER IF NOT EXISTS teams_bi_limit BEFORE INSERT ON teams
BEGIN
  SELECT CASE
    WHEN (SELECT teams FROM usage WHERE user_id = NEW.owner_id)
         >= (SELECT max_teams FROM usage WHERE user_id = NEW.owner_id)
    THEN RAISE(ABORT, 'LIMIT_TEAMS')
  END;
END;

CREATE TRIGGER IF NOT EXISTS teams_ai AFTER INSERT ON teams
BEGIN
  UPDATE usage SET teams = teams + 1, d1_writes = d1_writes + 1 WHERE user_id = NEW.owner_id;
  INSERT INTO audit_logs (user_id, category, action, db_table, db_rows) VALUES (NEW.owner_id, 'd1', 'insert', 'teams', 1);
END;

CREATE TRIGGER IF NOT EXISTS teams_ad AFTER DELETE ON teams
BEGIN
  UPDATE usage SET teams = MAX(teams - 1, 0), d1_writes = d1_writes + 1 WHERE user_id = OLD.owner_id;
  INSERT INTO audit_logs (user_id, category, action, db_table, db_rows)
  SELECT OLD.owner_id, 'd1', 'delete', 'teams', 1 WHERE EXISTS (SELECT 1 FROM users WHERE id = OLD.owner_id);
END;

-- ==========================================
-- Triggers: custom domains
-- ==========================================
CREATE TRIGGER IF NOT EXISTS domains_bi_limit BEFORE INSERT ON domains
BEGIN
  SELECT CASE
    WHEN (SELECT domains FROM usage WHERE user_id = NEW.owner_id)
         >= (SELECT max_domains FROM usage WHERE user_id = NEW.owner_id)
    THEN RAISE(ABORT, 'LIMIT_DOMAINS')
  END;
END;

CREATE TRIGGER IF NOT EXISTS domains_ai AFTER INSERT ON domains
BEGIN
  UPDATE usage SET domains = domains + 1, d1_writes = d1_writes + 1 WHERE user_id = NEW.owner_id;
  INSERT INTO audit_logs (user_id, category, action, db_table, db_rows) VALUES (NEW.owner_id, 'd1', 'insert', 'domains', 1);
END;

CREATE TRIGGER IF NOT EXISTS domains_ad AFTER DELETE ON domains
BEGIN
  UPDATE usage SET domains = MAX(domains - 1, 0), d1_writes = d1_writes + 1 WHERE user_id = OLD.owner_id;
  INSERT INTO audit_logs (user_id, category, action, db_table, db_rows)
  SELECT OLD.owner_id, 'd1', 'delete', 'domains', 1 WHERE EXISTS (SELECT 1 FROM users WHERE id = OLD.owner_id);
END;

-- ==========================================
-- Triggers: links (unlimited count, but they use D1 space)
-- ==========================================
-- Row size is an estimate: 120 bytes of overhead + the text columns.
CREATE TRIGGER IF NOT EXISTS links_bi_limit BEFORE INSERT ON links
WHEN NEW.created_by IS NOT NULL
BEGIN
  SELECT CASE
    WHEN (SELECT d1_bytes FROM usage WHERE user_id = NEW.created_by)
         >= (SELECT max_d1_bytes FROM usage WHERE user_id = NEW.created_by)
    THEN RAISE(ABORT, 'LIMIT_D1')
  END;
END;

CREATE TRIGGER IF NOT EXISTS links_ai AFTER INSERT ON links
WHEN NEW.created_by IS NOT NULL
BEGIN
  UPDATE usage SET
    links = links + 1,
    d1_writes = d1_writes + 1,
    d1_bytes = d1_bytes + 120 + length(NEW.domain) + length(NEW.shortcode) + length(NEW.url)
      + length(COALESCE(NEW.title, '')) + length(COALESCE(NEW.description, ''))
      + length(COALESCE(NEW.image, '')) + length(COALESCE(NEW.site_name, ''))
  WHERE user_id = NEW.created_by;

  INSERT INTO audit_logs (user_id, category, action, short_link, direct_url)
  VALUES (NEW.created_by, 'link', 'create', 'https://' || NEW.domain || '/' || NEW.shortcode, NEW.url);
END;

-- Keeps "last modified" honest whatever the Worker does.
CREATE TRIGGER IF NOT EXISTS links_au_touch
AFTER UPDATE OF url, title, description, image, site_name, seo_custom, domain, shortcode, team_id ON links
WHEN NEW.updated_at IS OLD.updated_at
BEGIN
  UPDATE links SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS links_au_usage
AFTER UPDATE OF url, title, description, image, site_name, domain, shortcode ON links
WHEN NEW.created_by IS NOT NULL
BEGIN
  UPDATE usage SET
    d1_writes = d1_writes + 1,
    d1_bytes = MAX(d1_bytes
      + (length(NEW.domain) + length(NEW.shortcode) + length(NEW.url)
         + length(COALESCE(NEW.title, '')) + length(COALESCE(NEW.description, ''))
         + length(COALESCE(NEW.image, '')) + length(COALESCE(NEW.site_name, '')))
      - (length(OLD.domain) + length(OLD.shortcode) + length(OLD.url)
         + length(COALESCE(OLD.title, '')) + length(COALESCE(OLD.description, ''))
         + length(COALESCE(OLD.image, '')) + length(COALESCE(OLD.site_name, ''))), 0)
  WHERE user_id = NEW.created_by;

  INSERT INTO audit_logs (user_id, category, action, short_link, direct_url)
  VALUES (COALESCE(NEW.updated_by, NEW.created_by), 'link', 'update',
          'https://' || NEW.domain || '/' || NEW.shortcode, NEW.url);
END;

CREATE TRIGGER IF NOT EXISTS links_ad AFTER DELETE ON links
WHEN OLD.created_by IS NOT NULL
BEGIN
  UPDATE usage SET
    links = MAX(links - 1, 0),
    d1_writes = d1_writes + 1,
    d1_bytes = MAX(d1_bytes - (120 + length(OLD.domain) + length(OLD.shortcode) + length(OLD.url)
      + length(COALESCE(OLD.title, '')) + length(COALESCE(OLD.description, ''))
      + length(COALESCE(OLD.image, '')) + length(COALESCE(OLD.site_name, ''))), 0)
  WHERE user_id = OLD.created_by;

  INSERT INTO audit_logs (user_id, category, action, short_link, direct_url)
  VALUES (COALESCE(OLD.updated_by, OLD.created_by), 'link', 'delete',
          'https://' || OLD.domain || '/' || OLD.shortcode, OLD.url);
END;

-- ==========================================
-- Triggers: R2 files (max 3 GB)
-- ==========================================
CREATE TRIGGER IF NOT EXISTS r2_bi_limit BEFORE INSERT ON r2_files
BEGIN
  SELECT CASE
    WHEN (SELECT r2_bytes FROM usage WHERE user_id = NEW.user_id) + NEW.size_bytes
         > (SELECT max_r2_bytes FROM usage WHERE user_id = NEW.user_id)
    THEN RAISE(ABORT, 'LIMIT_R2')
  END;
END;

CREATE TRIGGER IF NOT EXISTS r2_ai AFTER INSERT ON r2_files
BEGIN
  UPDATE usage SET r2_bytes = r2_bytes + NEW.size_bytes, d1_writes = d1_writes + 1 WHERE user_id = NEW.user_id;
  INSERT INTO audit_logs (user_id, category, action, r2_key, file_url, bytes)
  VALUES (NEW.user_id, 'r2', 'upload', NEW.r2_key, NEW.file_url, NEW.size_bytes);
END;

CREATE TRIGGER IF NOT EXISTS r2_ad AFTER DELETE ON r2_files
BEGIN
  UPDATE usage SET r2_bytes = MAX(r2_bytes - OLD.size_bytes, 0), d1_writes = d1_writes + 1 WHERE user_id = OLD.user_id;
  INSERT INTO audit_logs (user_id, category, action, r2_key, file_url, bytes)
  SELECT OLD.user_id, 'r2', 'delete', OLD.r2_key, OLD.file_url, OLD.size_bytes
  WHERE EXISTS (SELECT 1 FROM users WHERE id = OLD.user_id);
END;

-- ==========================================
-- Triggers: audit logs count toward D1 usage
-- ==========================================
-- Deleting a user cascades to their rows without leaving new log rows behind.
-- Logging is never blocked by the D1 limit (otherwise a full account couldn't
-- even record that it was full). Purge old rows to free space; see the note below.
CREATE TRIGGER IF NOT EXISTS audit_ai AFTER INSERT ON audit_logs
WHEN NEW.user_id IS NOT NULL
BEGIN
  UPDATE usage SET d1_bytes = d1_bytes + 100 + length(NEW.category) + length(NEW.action)
    + length(COALESCE(NEW.signin_method, '')) + length(COALESCE(NEW.ip, ''))
    + length(COALESCE(NEW.country, '')) + length(COALESCE(NEW.os, '')) + length(COALESCE(NEW.browser, ''))
    + length(COALESCE(NEW.short_link, '')) + length(COALESCE(NEW.direct_url, ''))
    + length(COALESCE(NEW.r2_key, '')) + length(COALESCE(NEW.file_url, '')) + length(COALESCE(NEW.db_table, ''))
  WHERE user_id = NEW.user_id;
END;

CREATE TRIGGER IF NOT EXISTS audit_ad AFTER DELETE ON audit_logs
WHEN OLD.user_id IS NOT NULL
BEGIN
  UPDATE usage SET d1_bytes = MAX(d1_bytes - (100 + length(OLD.category) + length(OLD.action)
    + length(COALESCE(OLD.signin_method, '')) + length(COALESCE(OLD.ip, ''))
    + length(COALESCE(OLD.country, '')) + length(COALESCE(OLD.os, '')) + length(COALESCE(OLD.browser, ''))
    + length(COALESCE(OLD.short_link, '')) + length(COALESCE(OLD.direct_url, ''))
    + length(COALESCE(OLD.r2_key, '')) + length(COALESCE(OLD.file_url, '')) + length(COALESCE(OLD.db_table, ''))), 0)
  WHERE user_id = OLD.user_id;
END;

-- ==========================================
-- Notes
-- ==========================================
-- Sign-in log (written by the Worker, not a trigger, because it needs the request):
--   INSERT INTO audit_logs (user_id, category, action, signin_method, ip, country, os, browser)
--   VALUES (?, 'signin', 'login', 'google', <CF-Connecting-IP>, <request.cf.country>, <parsed UA>, <parsed UA>);
--
-- Purge (run from the 12-hour cron) so logs can't eat the 1 GB; the delete trigger credits the space back:
--   DELETE FROM audit_logs WHERE created_at < datetime('now', '-90 days');
--
-- Move the existing links (different database, so export/import):
--   npx wrangler d1 export <OLD_LINKS_DB> --remote --table=links --no-schema --output=links.sql
--   npx wrangler d1 execute <ACCOUNTS_DB_NAME> --remote --file=./links.sql
-- Old rows have no created_by, so they stay anonymous and don't touch anyone's usage.