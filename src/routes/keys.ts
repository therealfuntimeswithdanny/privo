// API key management: /api/cloud/keys — session-authenticated only, so a key
// can never mint or revoke other keys.

import type { Env } from "../env";
import { error, json, sameOrigin } from "../lib/http";
import { getSessionUser } from "../lib/account";
import { hashToken, randomToken } from "../lib/crypto";

export const KEY_PREFIX = "pv_";
const MAX_ACTIVE_KEYS = 20;
const NAME_MAX = 60;

interface KeyRow {
  id: number;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
}

function keyJson(row: KeyRow) {
  return {
    id: row.id,
    name: row.name,
    prefix: row.prefix,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
  };
}

// GET /api/cloud/keys
export async function listKeys(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return error("Not signed in", 401);

  const { results } = await env.ACCOUNTS
    .prepare(
      "SELECT id, name, prefix, created_at, last_used_at FROM api_keys WHERE user_id = ? AND revoked_at IS NULL ORDER BY id DESC"
    )
    .bind(user.id)
    .all<KeyRow>();

  return json({ keys: (results || []).map(keyJson) });
}

// POST /api/cloud/keys — body {name}. The full key is returned exactly once.
export async function createKey(request: Request, env: Env, url: URL): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return error("Not signed in", 401);
  if (!sameOrigin(request, url)) return error("Keys can only be created from Privo Cloud.", 403);

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return error("Request body must be valid JSON.");
  }

  const name = typeof body.name === "string" ? body.name.trim().slice(0, NAME_MAX) : "";
  if (!name) return error("Give the key a name so you remember what it's for.");

  const count = await env.ACCOUNTS
    .prepare("SELECT COUNT(*) AS n FROM api_keys WHERE user_id = ? AND revoked_at IS NULL")
    .bind(user.id)
    .first<{ n: number }>();
  if ((count?.n || 0) >= MAX_ACTIVE_KEYS) {
    return error(`You can have at most ${MAX_ACTIVE_KEYS} active keys. Revoke one first.`, 403);
  }

  const key = KEY_PREFIX + randomToken(32);
  const prefix = key.slice(0, 11); // "pv_" + 8 chars — enough to identify it later

  let row: KeyRow | null;
  try {
    row = await env.ACCOUNTS
      .prepare("INSERT INTO api_keys (user_id, name, prefix, key_hash) VALUES (?, ?, ?, ?) RETURNING id, name, prefix, created_at, last_used_at")
      .bind(user.id, name, prefix, await hashToken(key))
      .first<KeyRow>();
  } catch (e) {
    if (String((e as Error)?.message).includes("LIMIT_D1")) {
      return error("Your account has reached its 300 MB database limit.", 403);
    }
    console.error("Key create error:", (e as Error)?.message);
    return error("Could not create the key.", 500);
  }
  if (!row) return error("Could not create the key.", 500);

  await env.ACCOUNTS
    .prepare("INSERT INTO audit_logs (user_id, category, action, db_table, db_rows) VALUES (?, 'd1', 'insert', 'api_keys', 1)")
    .bind(user.id)
    .run();

  return json({ key: { ...keyJson(row), secret: key } }, { status: 201 });
}

// DELETE /api/cloud/keys/:id — revokes (soft-deletes) one of the user's keys.
export async function revokeKey(request: Request, env: Env, url: URL, id: string): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return error("Not signed in", 401);
  if (!sameOrigin(request, url)) return error("Keys can only be revoked from Privo Cloud.", 403);

  const keyId = Number.parseInt(id, 10);
  if (!Number.isFinite(keyId)) return error("Invalid key id.");

  const result = await env.ACCOUNTS
    .prepare("UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ? AND user_id = ? AND revoked_at IS NULL")
    .bind(keyId, user.id)
    .run();

  if (!result.meta?.changes) return error("Key not found", 404);

  await env.ACCOUNTS
    .prepare("INSERT INTO audit_logs (user_id, category, action, db_table, db_rows) VALUES (?, 'd1', 'delete', 'api_keys', 1)")
    .bind(user.id)
    .run();

  return json({ revoked: true });
}
