// Account-facing API: /api/me, dashboard, audit logs.

import type { Env } from "../env";
import { error, json } from "../lib/http";
import { authenticate, getSessionUser, loadDashboard, loadLogs } from "../lib/account";

export async function me(request: Request, env: Env): Promise<Response> {
  const user = await authenticate(request, env);
  if (!user) return error("Not signed in", 401);
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
