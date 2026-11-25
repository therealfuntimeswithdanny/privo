// Google Web Risk lookup via hashes:search — only 4-byte hash prefixes of the
// destination's canonical expressions leave the Worker. Google returns full
// hashes that share those prefixes and we compare them locally. The full URL
// is never sent.

import type { Env } from "../env";
import { normB64, sha256, toBase64 } from "./crypto";

const WEB_RISK_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"];
const WEB_RISK_TIMEOUT_MS = 3000;

export type SafetyStatus = "clean" | "flagged" | "unchecked";

export interface SafetyResult {
  status: SafetyStatus;
  threats: string[] | null;
  checkedAt: string | null;
}

const UNCHECKED: SafetyResult = { status: "unchecked", threats: null, checkedAt: null };

interface WebRiskThreat {
  hash?: string;
  threatTypes?: string[];
}

/** Never throws; a failed lookup never blocks link creation. */
export async function checkSafety(env: Env, targetUrl: string): Promise<SafetyResult> {
  if (!env.WEB_RISK_API_KEY) return UNCHECKED;

  let digests: Uint8Array[];
  try {
    const expressions = canonicalExpressions(targetUrl);
    if (!expressions.length) return UNCHECKED;
    digests = await Promise.all(expressions.map((x) => sha256(x)));
  } catch {
    return UNCHECKED;
  }

  const fullHashes = new Set(digests.map((d) => normB64(toBase64(d))));
  const prefixes = [...new Set(digests.map((d) => toBase64(d.subarray(0, 4))))];

  const params = new URLSearchParams();
  for (const p of prefixes) params.append("hashPrefix", p);
  for (const t of WEB_RISK_THREAT_TYPES) params.append("threatTypes", t);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WEB_RISK_TIMEOUT_MS);

  try {
    const res = await fetch(`https://webrisk.googleapis.com/v1/hashes:search?${params}`, {
      method: "GET",
      headers: {
        "x-goog-api-key": env.WEB_RISK_API_KEY,
        Accept: "application/json",
      },
      signal: controller.signal,
    });

    if (!res.ok) {
      console.error("Web Risk API error:", res.status, await res.text());
      return UNCHECKED;
    }

    const data = (await res.json()) as { threats?: WebRiskThreat[] };
    const threatList = data.threats || [];

    // Matches without a hash field can't be confirmed — treat as unchecked.
    if (threatList.length && !threatList.some((t) => t.hash)) {
      console.error("Web Risk response had no hash fields; response shape may have changed");
      return UNCHECKED;
    }

    const hits = threatList.filter((t) => fullHashes.has(normB64(t.hash || "")));
    const checkedAt = new Date().toISOString();

    if (!hits.length) return { status: "clean", threats: [], checkedAt };

    const threats = [...new Set(hits.flatMap((t) => t.threatTypes || []))];
    return { status: "flagged", threats, checkedAt };
  } catch (err) {
    console.error("Web Risk lookup error:", err);
    return UNCHECKED;
  } finally {
    clearTimeout(timer);
  }
}

// Safe Browsing canonical expressions: host suffixes × path prefixes.
// Throws on input it can't parse, which the caller treats as unchecked.
export function canonicalExpressions(targetUrl: string): string[] {
  let raw = String(targetUrl).replace(/[\t\r\n]/g, "");

  const hashAt = raw.indexOf("#");
  if (hashAt !== -1) raw = raw.slice(0, hashAt);

  // Unescape until stable, so %25 and %2525 resolve the same way.
  for (let i = 0; i < 10; i++) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(raw);
    } catch {
      break;
    }
    if (decoded === raw) break;
    raw = decoded;
  }

  const u = new URL(raw);
  if (u.protocol !== "http:" && u.protocol !== "https:") return [];

  const host = u.hostname.toLowerCase().replace(/\.\./g, ".").replace(/^\.|\.$/g, "");
  const path = u.pathname.replace(/\/{2,}/g, "/") || "/";
  const search = u.search;

  const escapeChars = (s: string) =>
    s.replace(/[\x00-\x20\x7f#%]|[^\x00-\x7f]/gu, (c) => encodeURIComponent(c));

  // Hosts: the exact host, then up to four suffixes of its last five labels.
  const isIp = /^[\d.]+$/.test(host) || host.includes(":");
  const hosts = [host];
  if (!isIp) {
    const labels = host.split(".");
    for (let i = Math.max(labels.length - 5, 0); i <= labels.length - 2; i++) {
      const suffix = labels.slice(i).join(".");
      if (!hosts.includes(suffix)) hosts.push(suffix);
    }
  }

  // Paths: exact path with query, path without query, then directory prefixes.
  const paths = [path + search];
  if (search) paths.push(path);
  paths.push("/");
  const segments = path.split("/").filter(Boolean);
  for (let i = 0; i < segments.length; i++) {
    const isLast = i === segments.length - 1;
    if (isLast && !path.endsWith("/")) break;
    paths.push("/" + segments.slice(0, i + 1).join("/") + "/");
  }
  const uniquePaths = [...new Set(paths)].slice(0, 6);

  const expressions: string[] = [];
  for (const h of hosts) {
    for (const p of uniquePaths) {
      expressions.push(escapeChars(h) + escapeChars(p));
    }
  }
  return expressions;
}

// Cached wrapper used by /api/check. Verdicts are kept for an hour under a
// hashed key, so the address itself is never stored.
export async function checkSafetyCached(
  env: Env,
  ctx: ExecutionContext,
  targetUrl: string
): Promise<SafetyResult> {
  const digest = await sha256(targetUrl);
  const hex = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
  const key = new Request(`https://privo.fyi/__safety/${hex}`);
  const cache = caches.default;

  const hit = await cache.match(key);
  if (hit) {
    try {
      return (await hit.json()) as SafetyResult;
    } catch {
      // fall through and re-check
    }
  }

  const result = await checkSafety(env, targetUrl);

  // Failed lookups aren't cached, so the next request tries again.
  if (result.status !== "unchecked") {
    ctx.waitUntil(
      cache.put(
        key,
        new Response(JSON.stringify(result), {
          headers: { "Content-Type": "application/json", "Cache-Control": "max-age=3600" },
        })
      )
    );
  }

  return result;
}

/** Cron: re-checks links oldest-verdict first, in small parallel groups. */
export async function recheckLinks(env: Env): Promise<void> {
  if (!env.WEB_RISK_API_KEY) {
    console.log("Re-check skipped: WEB_RISK_API_KEY is not set");
    return;
  }

  const limit = Math.max(1, Math.min(Number(env.RECHECK_BATCH) || 40, 900));

  const { results } = await env.ACCOUNTS
    .prepare(
      "SELECT id, domain, shortcode, url, safety_status FROM links ORDER BY safety_checked_at IS NOT NULL, safety_checked_at ASC LIMIT ?"
    )
    .bind(limit)
    .all<{ id: number; domain: string; shortcode: string; url: string; safety_status: string }>();

  let checked = 0;
  let newlyFlagged = 0;
  let cleared = 0;

  const { imageKey } = await import("./images");

  for (let i = 0; i < results.length; i += 5) {
    await Promise.all(
      results.slice(i, i + 5).map(async (row) => {
        const result = await checkSafety(env, row.url);
        if (result.status === "unchecked") return;

        checked++;

        await env.ACCOUNTS
          .prepare("UPDATE links SET safety_status = ?, safety_threats = ?, safety_checked_at = ? WHERE id = ?")
          .bind(
            result.status,
            result.threats && result.threats.length ? JSON.stringify(result.threats) : null,
            result.checkedAt,
            row.id
          )
          .run();

        if (result.status === "flagged" && row.safety_status !== "flagged") {
          newlyFlagged++;
          console.warn(`Link flagged: ${row.shortcode} (${(result.threats || []).join(", ")})`);

          // Stop serving the destination's preview image from our domain.
          if (env.IMAGES) {
            await env.IMAGES.delete(imageKey(row.shortcode, row.domain)).catch(() => {});
            await env.ACCOUNTS.prepare("UPDATE links SET image_cached = 2 WHERE id = ?").bind(row.id).run();
          }
        }

        if (result.status === "clean" && row.safety_status === "flagged") cleared++;
      })
    );
  }

  console.log(`Re-check done: ${checked}/${results.length} checked, ${newlyFlagged} newly flagged, ${cleared} cleared`);
}
