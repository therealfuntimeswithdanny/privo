-- Privo.fyi schema — mirrors the live `privo` D1 database.
-- Everything is IF NOT EXISTS so this is a no-op on the existing database
-- and a full setup on a fresh one.

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT,
    picture TEXT,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS identities (
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (provider, provider_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_identities_user_id ON identities(user_id);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

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

CREATE TABLE IF NOT EXISTS links (
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
  safety_status   TEXT NOT NULL DEFAULT 'unchecked',
  safety_threats  TEXT,
  safety_checked_at TEXT,
  UNIQUE (domain, shortcode)
);

CREATE INDEX IF NOT EXISTS idx_links_created_by ON links(created_by);
CREATE INDEX IF NOT EXISTS idx_links_recheck ON links(safety_checked_at);
CREATE INDEX IF NOT EXISTS idx_links_team ON links(team_id);

CREATE TABLE IF NOT EXISTS domains (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  team_id    INTEGER REFERENCES teams(id) ON DELETE SET NULL,
  hostname   TEXT NOT NULL UNIQUE,
  verified   INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  cf_id      TEXT,
  status     TEXT NOT NULL DEFAULT 'pending',
  error      TEXT
);

CREATE INDEX IF NOT EXISTS idx_domains_owner ON domains(owner_id);
CREATE INDEX IF NOT EXISTS idx_domains_pending ON domains(verified, cf_id);

CREATE TABLE IF NOT EXISTS r2_files (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  r2_key       TEXT NOT NULL UNIQUE,
  file_url     TEXT NOT NULL,
  content_type TEXT,
  size_bytes   INTEGER NOT NULL CHECK (size_bytes >= 0),
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_r2_files_user ON r2_files(user_id);

CREATE TABLE IF NOT EXISTS audit_logs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       TEXT REFERENCES users(id) ON DELETE CASCADE,
  category      TEXT NOT NULL CHECK (category IN ('signin', 'link', 'r2', 'd1')),
  action        TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  signin_method TEXT,
  ip            TEXT,
  country       TEXT,
  os            TEXT,
  browser       TEXT,
  short_link    TEXT,
  direct_url    TEXT,
  r2_key        TEXT,
  file_url      TEXT,
  bytes         INTEGER,
  db_table      TEXT,
  db_rows       INTEGER
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_logs(category, created_at DESC);

CREATE TABLE IF NOT EXISTS usage (
  user_id      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  teams        INTEGER NOT NULL DEFAULT 0,
  domains      INTEGER NOT NULL DEFAULT 0,
  links        INTEGER NOT NULL DEFAULT 0,
  r2_bytes     INTEGER NOT NULL DEFAULT 0,
  d1_bytes     INTEGER NOT NULL DEFAULT 0,
  d1_writes    INTEGER NOT NULL DEFAULT 0,
  max_teams    INTEGER NOT NULL DEFAULT 10,
  max_domains  INTEGER NOT NULL DEFAULT 10,
  max_r2_bytes INTEGER NOT NULL DEFAULT 3221225472,
  max_d1_bytes INTEGER NOT NULL DEFAULT 1073741824
);

-- Usage + audit triggers (kept verbatim from the live schema).

CREATE TRIGGER IF NOT EXISTS users_ai_usage AFTER INSERT ON users
BEGIN
  INSERT OR IGNORE INTO usage (user_id) VALUES (NEW.id);
END;

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
