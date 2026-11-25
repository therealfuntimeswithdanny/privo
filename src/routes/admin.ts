// Admin blocklist CRUD — gated to ADMIN_DID.

import type { Env } from "../env";
import { error, json, sameOrigin } from "../lib/http";
import { requireAdmin } from "../lib/account";
import { HOSTNAME_RE } from "./domains";

// GET /api/admin/blocklist
export async function listBlocklist(request: Request, env: Env): Promise<Response> {
  const user = await requireAdmin(request, env);
  if (user instanceof Response) return user;

  const { results } = await env.ACCOUNTS
    .prepare("SELECT id, host, note, created_by, created_at FROM blocklist ORDER BY host")
    .all<{ id: number; host: string; note: string | null; created_by: string | null; created_at: string }>();

  return json({
    hosts: results.map((r) => ({
      id: r.id,
      host: r.host,
      note: r.note,
      createdBy: r.created_by,
      createdAt: r.created_at,
    })),
  });
}

// POST /api/admin/blocklist {host, note?}
export async function addToBlocklist(request: Request, env: Env, url: URL): Promise<Response> {
  const user = await requireAdmin(request, env);
  if (user instanceof Response) return user;
  if (!sameOrigin(request, url)) return error("Forbidden", 403);

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return error("Request body must be valid JSON.");
  }

  // Accept a bare hostname or a full URL — we store the hostname.
  let host = typeof body.host === "string" ? body.host.trim().toLowerCase() : "";
  try {
    const parsed = new URL(/^https?:\/\//i.test(host) ? host : `https://${host}`);
    host = parsed.hostname;
  } catch {
    return error("Enter a valid domain or URL.");
  }
  host = host.replace(/^www\./, "");
  if (!HOSTNAME_RE.test(host) && !/^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/.test(host)) {
    return error("Enter a valid domain or URL.");
  }
  if (host === "privo.fyi" || host.endsWith(".privo.fyi")) {
    return error("You can’t block privo.fyi.");
  }

  const note = typeof body.note === "string" ? body.note.trim().slice(0, 500) || null : null;

  try {
    const row = await env.ACCOUNTS
      .prepare("INSERT INTO blocklist (host, note, created_by) VALUES (?, ?, ?) RETURNING id, host, note, created_at")
      .bind(host, note, user.id)
      .first<{ id: number; host: string; note: string | null; created_at: string }>();
    return json({ host: { ...row, createdBy: user.id, createdAt: row!.created_at } }, { status: 201 });
  } catch (e) {
    if (String((e as Error)?.message).includes("UNIQUE")) {
      return error("That host is already blocked.", 409);
    }
    throw e;
  }
}

// DELETE /api/admin/blocklist/:id
export async function removeFromBlocklist(request: Request, env: Env, url: URL): Promise<Response> {
  const user = await requireAdmin(request, env);
  if (user instanceof Response) return user;
  if (!sameOrigin(request, url)) return error("Forbidden", 403);

  const match = url.pathname.match(/^\/api\/admin\/blocklist\/(\d+)$/);
  if (!match) return error("Not found", 404);

  const res = await env.ACCOUNTS.prepare("DELETE FROM blocklist WHERE id = ?").bind(Number(match[1])).run();
  if (!res.meta.changes) return error("Not found", 404);
  return json({ ok: true });
}
