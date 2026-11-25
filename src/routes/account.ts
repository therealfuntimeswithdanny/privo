// Account-facing API: /api/me, dashboard, audit logs.

import type { Env } from "../env";
import { error, json } from "../lib/http";
import { authenticate, getSessionUser, loadDashboard, loadLogs } from "../lib/account";
import { sameOrigin } from "../lib/http";

export async function me(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  if (!auth) return error("Not signed in", 401);
  const user = auth.user;
  return json({ user: { email: user.id, name: user.name, picture: user.picture } });
}

export async function dashboard(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return error("Not signed in", 401);

  try {
    return json(await loadDashboard(env, user));
  } catch (e) {
    console.error("Dashboard error:", (e as Error)?.message);
    return error("Could not load the dashboard", 500);
  }
}

export async function logs(request: Request, env: Env, url: URL): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return error("Not signed in", 401);

  try {
    return json(await loadLogs(env, user, url.searchParams));
  } catch (e) {
    console.error("Logs error:", (e as Error)?.message);
    return error("Could not load the logs", 500);
  }
}

// POST /api/cloud/logs/clear — delete every audit row for the account. The
// audit_ad trigger subtracts each row's bytes from usage.d1_bytes, so the
// storage meter drops too.
export async function clearLogs(request: Request, env: Env, url: URL): Promise<Response> {
  if (!sameOrigin(request, url)) return error("Forbidden", 403);
  const user = await getSessionUser(request, env);
  if (!user) return error("Not signed in", 401);

  try {
    const res = await env.ACCOUNTS
      .prepare("DELETE FROM audit_logs WHERE user_id = ?")
      .bind(user.id)
      .run();

    // Leave one honest breadcrumb that the log was cleared.
    await env.ACCOUNTS
      .prepare(
        "INSERT INTO audit_logs (user_id, category, action, db_table) VALUES (?, 'd1', 'delete', 'audit_logs')"
      )
      .bind(user.id)
      .run();

    return json({ cleared: res.meta?.changes ?? 0 });
  } catch (e) {
    console.error("Clear logs error:", (e as Error)?.message);
    return error("Could not clear the logs", 500);
  }
}
