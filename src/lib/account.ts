// Sessions, sign-in logging, and the account-facing log/dashboard queries.

import type { Env } from "../env";
import { getCookie } from "./http";
import { hashToken, randomToken } from "./crypto";

export const SESSION_COOKIE = "privo_session";
export const SESSION_DAYS = 30;

export interface SessionUser {
  id: string;
  name: string | null;
  picture: string | null;
}

/** Returns the user for a valid session cookie, otherwise null. */
export async function getSessionUser(request: Request, env: Env): Promise<SessionUser | null> {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token || !env.ACCOUNTS) return null;

  return env.ACCOUNTS
    .prepare(
      `SELECT users.id AS id, users.name AS name, users.picture AS picture
       FROM sessions JOIN users ON users.id = sessions.user_id
       WHERE sessions.token_hash = ? AND sessions.expires_at > ?`
    )
    .bind(await hashToken(token), new Date().toISOString())
    .first<SessionUser>();
}

export async function createSession(env: Env, userId: string): Promise<{ token: string; maxAge: number }> {
  const token = randomToken(32);
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_DAYS * 86400 * 1000);

  await env.ACCOUNTS.batch([
    // Tidy this person's expired sessions while we're here.
    env.ACCOUNTS.prepare("DELETE FROM sessions WHERE user_id = ? AND expires_at <= ?").bind(
      userId,
      now.toISOString()
    ),
    env.ACCOUNTS
      .prepare("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
      .bind(await hashToken(token), userId, now.toISOString(), expires.toISOString()),
  ]);

  return { token, maxAge: SESSION_DAYS * 86400 };
}

/** The only account allowed to admin (reports, blocklist). */
export const ADMIN_DID = "did:plc:l37td5yhxl2irrzrgvei4qay";

/** Session user if signed in AND the admin DID, else a 401/403 Response. */
export async function requireAdmin(request: Request, env: Env): Promise<SessionUser | Response> {
  const user = await getSessionUser(request, env);
  if (!user) return Response.json({ error: "Not signed in" }, { status: 401 });
  if (user.id !== ADMIN_DID) return Response.json({ error: "Not authorized" }, { status: 403 });
  return user;
}

export async function destroySession(request: Request, env: Env): Promise<void> {
  const token = getCookie(request, SESSION_COOKIE);
  if (token && env.ACCOUNTS) {
    await env.ACCOUNTS.prepare("DELETE FROM sessions WHERE token_hash = ?")
      .bind(await hashToken(token))
      .run();
  }
}

// Writes one audit row per sign in: method, country, OS and browser only.
// No IP address is read or stored. Never blocks the sign in.
export async function logSignIn(env: Env, request: Request, userId: string, method: string): Promise<void> {
  try {
    const { os, browser } = parseUserAgent(request.headers.get("User-Agent") || "");
    const country = (request.cf?.country as string | undefined) || null;

    await env.ACCOUNTS
      .prepare(
        "INSERT INTO audit_logs (user_id, category, action, signin_method, country, os, browser) VALUES (?, 'signin', 'login', ?, ?, ?, ?)"
      )
      .bind(userId, method, country, os, browser)
      .run();
  } catch (error) {
    console.error("Sign-in log failed:", (error as Error)?.message);
  }
}

export function parseUserAgent(ua: string): { os: string; browser: string } {
  let os = "Unknown";
  if (/Windows/i.test(ua)) os = "Windows";
  else if (/iPhone|iPad|iPod/i.test(ua)) os = "iOS";
  else if (/Android/i.test(ua)) os = "Android";
  else if (/CrOS/i.test(ua)) os = "ChromeOS";
  else if (/Mac OS X|Macintosh/i.test(ua)) os = "macOS";
  else if (/Linux/i.test(ua)) os = "Linux";

  // Order matters: Edge and Opera also say "Chrome", Chrome also says "Safari".
  let browser = "Unknown";
  if (/Edg\//i.test(ua)) browser = "Edge";
  else if (/OPR\/|Opera/i.test(ua)) browser = "Opera";
  else if (/Firefox|FxiOS/i.test(ua)) browser = "Firefox";
  else if (/Chrome|CriOS/i.test(ua)) browser = "Chrome";
  else if (/Safari/i.test(ua)) browser = "Safari";

  return { os, browser };
}

/** Deletes are the only thing marked Medium; everything else is routine. */
function riskLevel(action: string): string {
  return action === "delete" ? "Medium" : "Low";
}

const LOG_PAGE_SIZE = 50;
const LOG_CATEGORIES = ["signin", "link", "r2", "d1"];

interface LogRow {
  id: number;
  category: string;
  action: string;
  created_at: string;
  signin_method: string | null;
  country: string | null;
  os: string | null;
  browser: string | null;
  short_link: string | null;
  direct_url: string | null;
  r2_key: string | null;
  file_url: string | null;
  bytes: number | null;
  db_table: string | null;
}

/** One page of the account's audit log. `next` is the id to pass as ?before=. */
export async function loadLogs(env: Env, user: SessionUser, params: URLSearchParams) {
  const category = params.get("category");
  const before = Number.parseInt(params.get("before") || "", 10);

  let sql =
    "SELECT id, category, action, created_at, signin_method, country, os, browser, short_link, direct_url, r2_key, file_url, bytes, db_table FROM audit_logs WHERE user_id = ?";
  const binds: (string | number)[] = [user.id];

  if (category && LOG_CATEGORIES.includes(category)) {
    sql += " AND category = ?";
    binds.push(category);
  }
  if (Number.isFinite(before)) {
    sql += " AND id < ?";
    binds.push(before);
  }

  sql += " ORDER BY id DESC LIMIT ?";
  binds.push(LOG_PAGE_SIZE + 1);

  const { results } = await env.ACCOUNTS.prepare(sql).bind(...binds).all<LogRow>();
  const more = results.length > LOG_PAGE_SIZE;
  const page = more ? results.slice(0, LOG_PAGE_SIZE) : results;

  return {
    logs: page.map((r) => ({
      id: r.id,
      category: r.category,
      action: r.action,
      risk: riskLevel(r.action),
      at: r.created_at,
      method: r.signin_method,
      country: r.country,
      os: r.os,
      browser: r.browser,
      shortLink: r.short_link,
      directUrl: r.direct_url,
      r2Key: r.r2_key,
      fileUrl: r.file_url,
      bytes: r.bytes,
      table: r.db_table,
    })),
    next: more ? page[page.length - 1]!.id : null,
  };
}

/** Everything the dashboard shows, in one round trip. */
export async function loadDashboard(env: Env, user: SessionUser) {
  const db = env.ACCOUNTS;

  const [usageRes, linksRes, logsRes, domainsRes] = await db.batch([
    db.prepare("SELECT * FROM usage WHERE user_id = ?").bind(user.id),
    db
      .prepare(
        `SELECT l.domain, l.shortcode, l.url, l.updated_at, u.name AS by_name, COALESCE(l.updated_by, l.created_by) AS by_id
         FROM links l LEFT JOIN users u ON u.id = COALESCE(l.updated_by, l.created_by)
         WHERE l.created_by = ? ORDER BY l.updated_at DESC, l.id DESC LIMIT 200`
      )
      .bind(user.id),
    db
      .prepare(
        `SELECT category, action, created_at, signin_method, short_link, r2_key, db_table
         FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT 100`
      )
      .bind(user.id),
    db
      .prepare(
        `SELECT d.hostname, d.verified, d.created_at, u.name AS by_name, d.owner_id AS by_id
         FROM domains d LEFT JOIN users u ON u.id = d.owner_id
         WHERE d.owner_id = ? ORDER BY d.created_at DESC LIMIT 50`
      )
      .bind(user.id),
  ]);

  const u = ((usageRes?.results || [])[0] || {}) as Record<string, number>;

  interface LinkDashRow { domain: string; shortcode: string; url: string; updated_at: string; by_name: string | null; by_id: string | null }
  interface LogDashRow { category: string; action: string; created_at: string; signin_method: string | null; short_link: string | null; r2_key: string | null; db_table: string | null }
  interface DomainDashRow { hostname: string; verified: number; created_at: string; by_name: string | null; by_id: string | null }

  return {
    user: { email: user.id, name: user.name, picture: user.picture },
    usage: {
      links: u.links || 0,
      domains: u.domains || 0,
      maxDomains: u.max_domains || 10,
      teams: u.teams || 0,
      maxTeams: u.max_teams || 10,
      r2Bytes: u.r2_bytes || 0,
      maxR2Bytes: u.max_r2_bytes || 3221225472,
      d1Bytes: u.d1_bytes || 0,
      maxD1Bytes: u.max_d1_bytes || 1073741824,
    },
    links: ((linksRes?.results || []) as LinkDashRow[]).map((r) => ({
      shortLink: `${r.domain}/${r.shortcode}`,
      url: r.url,
      modifiedAt: r.updated_at,
      modifiedBy: r.by_name || r.by_id,
    })),
    logs: ((logsRes?.results || []) as LogDashRow[]).map((r) => ({
      category: r.category,
      action: r.action,
      risk: riskLevel(r.action),
      at: r.created_at,
      method: r.signin_method,
      shortLink: r.short_link,
      r2Key: r.r2_key,
      table: r.db_table,
    })),
    domains: ((domainsRes?.results || []) as DomainDashRow[]).map((r) => ({
      hostname: r.hostname,
      verified: Boolean(r.verified),
      modifiedAt: r.created_at,
      modifiedBy: r.by_name || r.by_id,
    })),
  };
}
