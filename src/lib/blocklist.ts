// Hostname blocklist: an entry "evil.com" blocks evil.com and any subdomain.

import type { Env } from "../env";

/** Returns the matching blocklist host, or null if the URL's host is allowed. */
export async function blockedHost(env: Env, urlString: string): Promise<string | null> {
  let host: string;
  try {
    host = new URL(urlString).hostname.toLowerCase();
  } catch {
    return null;
  }
  if (!host) return null;

  // Candidates: the full host, then each parent suffix (a.b.evil.com →
  // b.evil.com, evil.com). TLD-only suffixes are skipped.
  const labels = host.split(".");
  const candidates = [host];
  for (let i = 1; i < labels.length - 1; i++) {
    candidates.push(labels.slice(i).join("."));
  }

  const placeholders = candidates.map(() => "?").join(",");
  const row = await env.ACCOUNTS
    .prepare(`SELECT host FROM blocklist WHERE host IN (${placeholders}) LIMIT 1`)
    .bind(...candidates)
    .first<{ host: string }>();

  return row?.host ?? null;
}
