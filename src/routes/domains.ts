// Custom domains via Cloudflare for SaaS custom hostnames.
// Customers CNAME their domain to CNAME_TARGET; Cloudflare issues the
// certificate and reports status, which sets domains.verified = 1.
// Requires: CF_API_TOKEN (secret), CF_ZONE_ID (var).

import type { Env } from "../env";
import { error, json, sameOrigin } from "../lib/http";
import { getSessionUser, type SessionUser } from "../lib/account";

const CF_API = "https://api.cloudflare.com/client/v4";
const CNAME_TARGET = "dns.privo.fyi";
const DOMAIN_RECHECK_BATCH = 20;

// Lowercase letters, digits, hyphens; at least two labels; no IPs; not privo.fyi itself.
const HOSTNAME_RE = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\.)+[a-z]{2,63}$/;
export { HOSTNAME_RE };

function normalizeHostname(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const h = input.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0]!.replace(/\.$/, "");
  if (!HOSTNAME_RE.test(h)) return null;
  if (h === "privo.fyi" || h.endsWith(".privo.fyi")) return null;
  return h;
}

interface CfResult {
  id?: string;
  status?: string;
  verification_errors?: string[];
}

interface CfResponse {
  ok: boolean;
  status: number;
  result: CfResult | null;
  errors: { message?: string }[];
}

/** One call to the Cloudflare API for this zone. Never throws. */
async function cf(env: Env, method: string, path: string, body?: unknown): Promise<CfResponse> {
  try {
    const res = await fetch(`${CF_API}/zones/${env.CF_ZONE_ID}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${env.CF_API_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    let data: { success?: boolean; result?: CfResult; errors?: { message?: string }[] } = {};
    try {
      data = (await res.json()) as typeof data;
    } catch {
      // empty body
    }
    const errors = Array.isArray(data.errors) ? data.errors : [];
    return { ok: res.ok && data.success !== false, status: res.status, result: data.result || null, errors };
  } catch (e) {
    console.error("Cloudflare API error:", (e as Error)?.message);
    return { ok: false, status: 0, result: null, errors: [] };
  }
}

function domainState(result: CfResult | null) {
  const status = result?.status || "pending";
  const verificationError = Array.isArray(result?.verification_errors) ? result!.verification_errors[0] : null;
  return {
    status,
    verified: status === "active",
    error: status === "active" ? null : verificationError || null,
  };
}

interface DomainRow {
  id: number;
  hostname: string;
  verified: number;
  status: string | null;
  error: string | null;
  cf_id?: string | null;
  created_at?: string;
}

function domainJson(row: DomainRow, extra: Record<string, unknown> = {}) {
  return {
    id: row.id,
    hostname: row.hostname,
    verified: Boolean(row.verified),
    status: row.status || "pending",
    error: row.error || null,
    cnameTarget: CNAME_TARGET,
    ...extra,
  };
}

export async function handleDomains(request: Request, env: Env, url: URL): Promise<Response> {
  const isWrite = request.method !== "GET";

  if (isWrite && !sameOrigin(request, url)) {
    return error("Forbidden", 403);
  }

  const user = await getSessionUser(request, env);
  if (!user) return error("Not signed in", 401);

  if (!env.CF_API_TOKEN || !env.CF_ZONE_ID) {
    return error("Custom domains aren't set up yet.", 503);
  }

  const path = url.pathname;
  const byId = path.match(/^\/api\/cloud\/domains\/(\d+)$/);
  const verify = path.match(/^\/api\/cloud\/domains\/(\d+)\/verify$/);

  try {
    if (path === "/api/cloud/domains" && request.method === "GET") {
      return listDomains(env, user);
    }
    if (path === "/api/cloud/domains" && request.method === "POST") {
      return addDomain(request, env, user);
    }
    if (verify && request.method === "POST") {
      return verifyDomain(env, user, Number(verify[1]));
    }
    if (byId && request.method === "DELETE") {
      return removeDomain(env, user, Number(byId[1]));
    }
    return error("Not found", 404);
  } catch (e) {
    console.error("Domains error:", (e as Error)?.message);
    return error("Something went wrong. Try again.", 500);
  }
}

async function listDomains(env: Env, user: SessionUser): Promise<Response> {
  const [rowsRes, usageRes] = await env.ACCOUNTS.batch([
    env.ACCOUNTS
      .prepare("SELECT id, hostname, verified, status, error, created_at FROM domains WHERE owner_id = ? ORDER BY created_at DESC, id DESC")
      .bind(user.id),
    env.ACCOUNTS.prepare("SELECT domains, max_domains FROM usage WHERE user_id = ?").bind(user.id),
  ]);

  const u = ((usageRes?.results || [])[0] || {}) as { domains?: number; max_domains?: number };
  return json({
    domains: ((rowsRes?.results || []) as DomainRow[]).map((r) => ({ ...domainJson(r), modifiedAt: r.created_at })),
    usage: { domains: u.domains || 0, maxDomains: u.max_domains || 10 },
    cnameTarget: CNAME_TARGET,
  });
}

async function addDomain(request: Request, env: Env, user: SessionUser): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    body = {};
  }

  const hostname = normalizeHostname(body.hostname);
  if (!hostname) {
    return error("Enter a domain like links.example.com. privo.fyi can’t be used.");
  }

  const taken = await env.ACCOUNTS.prepare("SELECT id FROM domains WHERE hostname = ?").bind(hostname).first();
  if (taken) return error("That domain is already in use.", 409);

  const created = await cf(env, "POST", "/custom_hostnames", {
    hostname,
    ssl: { method: "http", type: "dv", settings: { min_tls_version: "1.2" } },
  });

  if (!created.ok || !created.result) {
    console.error("Custom hostname create failed:", created.status, JSON.stringify(created.errors));
    const duplicate = created.errors.some((e) => /already|duplicate|exists/i.test(e.message || ""));
    return error(duplicate ? "That domain is already in use." : "Couldn’t add that domain right now. Try again.", duplicate ? 409 : 502);
  }

  const cfId = created.result.id!;
  const state = domainState(created.result);

  try {
    const row = await env.ACCOUNTS
      .prepare("INSERT INTO domains (owner_id, hostname, verified, cf_id, status, error) VALUES (?, ?, ?, ?, ?, ?) RETURNING id, hostname, verified, status, error")
      .bind(user.id, hostname, state.verified ? 1 : 0, cfId, state.status, state.error)
      .first<DomainRow>();

    return json(domainJson(row!), { status: 201 });
  } catch (e) {
    // Couldn't save it (usually the domain limit): undo the Cloudflare side.
    await cf(env, "DELETE", `/custom_hostnames/${cfId}`);
    if (String((e as Error)?.message).includes("LIMIT_DOMAINS")) {
      return error("You’ve reached your limit of 10 custom domains.", 403);
    }
    throw e;
  }
}

async function verifyDomain(env: Env, user: SessionUser, id: number): Promise<Response> {
  const row = await env.ACCOUNTS
    .prepare("SELECT id, hostname, cf_id FROM domains WHERE id = ? AND owner_id = ?")
    .bind(id, user.id)
    .first<DomainRow>();
  if (!row) return error("Not found", 404);

  const res = await cf(env, "GET", `/custom_hostnames/${row.cf_id}`);
  if (!res.ok || !res.result) {
    return error("Couldn’t check that domain right now. Try again.", 502);
  }

  const state = domainState(res.result);
  await env.ACCOUNTS
    .prepare("UPDATE domains SET verified = ?, status = ?, error = ? WHERE id = ?")
    .bind(state.verified ? 1 : 0, state.status, state.error, id)
    .run();

  return json(domainJson({ id, hostname: row.hostname, verified: state.verified ? 1 : 0, status: state.status, error: state.error }));
}

async function removeDomain(env: Env, user: SessionUser, id: number): Promise<Response> {
  const row = await env.ACCOUNTS
    .prepare("SELECT id, hostname, cf_id FROM domains WHERE id = ? AND owner_id = ?")
    .bind(id, user.id)
    .first<DomainRow>();
  if (!row) return error("Not found", 404);

  if (row.cf_id) {
    const res = await cf(env, "DELETE", `/custom_hostnames/${row.cf_id}`);
    if (!res.ok && res.status !== 404) {
      return error("Couldn’t remove that domain right now. Try again.", 502);
    }
  }

  // Links on the domain go with it. The triggers adjust usage and the audit log.
  await env.ACCOUNTS.batch([
    env.ACCOUNTS.prepare("DELETE FROM links WHERE domain = ?").bind(row.hostname),
    env.ACCOUNTS.prepare("DELETE FROM domains WHERE id = ?").bind(id),
  ]);

  return json({ ok: true });
}

/** Cron: checks domains still waiting on DNS, oldest first. */
export async function recheckDomains(env: Env): Promise<void> {
  if (!env.CF_API_TOKEN || !env.CF_ZONE_ID) return;

  const { results } = await env.ACCOUNTS
    .prepare("SELECT id, cf_id FROM domains WHERE verified = 0 AND cf_id IS NOT NULL ORDER BY id LIMIT ?")
    .bind(DOMAIN_RECHECK_BATCH)
    .all<{ id: number; cf_id: string }>();

  for (const row of results) {
    const res = await cf(env, "GET", `/custom_hostnames/${row.cf_id}`);
    if (!res.ok || !res.result) continue;

    const state = domainState(res.result);
    await env.ACCOUNTS
      .prepare("UPDATE domains SET verified = ?, status = ?, error = ? WHERE id = ?")
      .bind(state.verified ? 1 : 0, state.status, state.error, row.id)
      .run();
  }
}
