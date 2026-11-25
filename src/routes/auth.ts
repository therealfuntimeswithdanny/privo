// Sign in: Google OAuth 2.0 (code + PKCE) and AT Protocol OAuth (PAR + PKCE + DPoP).
//
// Storage (env.ACCOUNTS):
//   users       id = verified email (google) or DID (atproto), name, picture
//   identities  one row per sign-in method: (provider, provider_user_id) -> user
//   sessions    SHA-256 of the session token -> user, with an expiry
//
// Provider tokens are used once (to confirm identity) and are never stored.

import type { Env } from "../env";
import {
  absoluteHttpUrl,
  buildCookie,
  clean,
  getCookie,
  redirect,
} from "../lib/http";
import { base64url, randomToken, safeEqual, sha256 } from "../lib/crypto";
import {
  createSession,
  destroySession,
  logSignIn,
  SESSION_COOKIE,
} from "../lib/account";
import {
  finishAtprotoAuth,
  startAtprotoAuth,
} from "../atproto/oauth";

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";

const GOOGLE_SCOPES = [
  "openid",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
].join(" ");

const OAUTH_COOKIE = "privo_oauth"; // state + PKCE verifier while the user is away
const OAUTH_TTL_SECONDS = 600;

export async function handleAuth(request: Request, env: Env, url: URL): Promise<Response> {
  const path = url.pathname;
  const isGet = request.method === "GET";

  if (path === "/cloud/auth/google" && isGet) return googleStart(env, url);
  if (path === "/cloud/auth/google/callback" && isGet) return googleCallback(request, env, url);

  if (path === "/cloud/auth/bluesky" && isGet) return blueskyStart(request, env, url);
  if (path === "/cloud/auth/atproto/callback" && isGet) return atprotoCallback(request, env, url);

  if (path === "/cloud/auth/logout" && request.method === "POST") return logout(request, env, url);

  // Sign-in methods that aren't built yet get a friendly message.
  if (isGet && /^\/cloud\/auth\/(create|coffee-and-code|github|apikey)$/.test(path)) {
    return authRedirect(url, "unavailable");
  }

  return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
}

/** Any sign-in problem sends the user back to login with a short error code. */
function authRedirect(url: URL, code: string, cookies: string[] = []): Response {
  return redirect(`${url.origin}/cloud/login?error=${encodeURIComponent(code)}`, cookies);
}

function oauthCookieClear(url: URL): string {
  return buildCookie(OAUTH_COOKIE, "", { maxAge: 0, path: "/cloud/auth", secure: url.protocol === "https:" });
}

// ---------- Google ----------

function googleCredentials(env: Env) {
  // Secrets/vars can pick up stray whitespace when pasted in the dashboard.
  return {
    clientId: String(env.GOOGLE_CLIENT_ID || "").trim(),
    clientSecret: String(env.GOOGLE_CLIENT_SECRET || "").trim(),
  };
}

function googleConfigured(env: Env): boolean {
  const { clientId, clientSecret } = googleCredentials(env);
  return Boolean(clientId && clientSecret && env.ACCOUNTS);
}

function googleRedirectUri(url: URL): string {
  return `${url.origin}/cloud/auth/google/callback`;
}

async function googleStart(env: Env, url: URL): Promise<Response> {
  if (!googleConfigured(env)) return authRedirect(url, "unavailable");

  const { clientId } = googleCredentials(env);
  const state = randomToken(24);
  const verifier = randomToken(48);
  const challenge = base64url(await sha256(verifier));

  const authUrl = new URL(GOOGLE_AUTH_URL);
  authUrl.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: googleRedirectUri(url),
    response_type: "code",
    scope: GOOGLE_SCOPES,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  }).toString();

  return redirect(authUrl.toString(), [
    buildCookie(OAUTH_COOKIE, `${state}.${verifier}`, {
      maxAge: OAUTH_TTL_SECONDS,
      path: "/cloud/auth",
      secure: url.protocol === "https:",
    }),
  ]);
}

async function googleCallback(request: Request, env: Env, url: URL): Promise<Response> {
  const secure = url.protocol === "https:";
  const clearOauth = oauthCookieClear(url);

  if (!googleConfigured(env)) return authRedirect(url, "unavailable", [clearOauth]);

  const params = url.searchParams;

  if (params.get("error")) {
    return authRedirect(url, params.get("error") === "access_denied" ? "denied" : "failed", [clearOauth]);
  }

  const { clientId, clientSecret } = googleCredentials(env);
  const code = params.get("code");
  const state = params.get("state");
  const saved = (getCookie(request, OAUTH_COOKIE) || "").split(".");

  if (!code || !state || saved.length !== 2 || !safeEqual(saved[0]!, state)) {
    return authRedirect(url, "expired", [clearOauth]);
  }

  try {
    const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: googleRedirectUri(url),
        grant_type: "authorization_code",
        code_verifier: saved[1]!,
      }),
    });

    if (!tokenRes.ok) {
      console.error("Google token exchange failed:", tokenRes.status);
      return authRedirect(url, "failed", [clearOauth]);
    }

    const tokens = (await tokenRes.json()) as { access_token?: string };
    if (!tokens.access_token) return authRedirect(url, "failed", [clearOauth]);

    const infoRes = await fetch(GOOGLE_USERINFO_URL, {
      headers: { Authorization: `Bearer ${tokens.access_token}`, Accept: "application/json" },
    });

    if (!infoRes.ok) {
      console.error("Google userinfo failed:", infoRes.status);
      return authRedirect(url, "failed", [clearOauth]);
    }

    const info = (await infoRes.json()) as {
      sub?: string;
      email?: string;
      email_verified?: boolean | string;
      name?: string;
      given_name?: string;
      picture?: string;
    };
    if (!info.sub || !info.email) return authRedirect(url, "failed", [clearOauth]);

    // Only a verified address may be used as an account ID.
    if (info.email_verified !== true && info.email_verified !== "true") {
      return authRedirect(url, "unverified", [clearOauth]);
    }

    const user = await upsertIdentity(env, {
      provider: "google",
      providerUserId: info.sub,
      accountId: String(info.email).trim().toLowerCase(),
      name: clean(info.name || info.given_name || "", 100),
      picture: googlePicture(info.picture),
    });
    const session = await createSession(env, user.id);
    await logSignIn(env, request, user.id, "google");

    return redirect(`${url.origin}/cloud/app/dashboard`, [
      clearOauth,
      buildCookie(SESSION_COOKIE, session.token, { maxAge: session.maxAge, path: "/", secure }),
    ]);
  } catch (e) {
    console.error("Google sign in error:", (e as Error)?.message);
    return authRedirect(url, "failed", [clearOauth]);
  }
}

function googlePicture(raw: string | undefined): string | null {
  const photo = absoluteHttpUrl(raw, "https://lh3.googleusercontent.com");
  return photo && photo.startsWith("https://") ? photo : null;
}

// ---------- Bluesky / AT Protocol ----------

async function blueskyStart(request: Request, env: Env, url: URL): Promise<Response> {
  const handle = (url.searchParams.get("handle") || "").trim().toLowerCase().replace(/^@/, "");
  if (!handle || !/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(handle) || handle.length > 253) {
    return authRedirect(url, "invalid_handle");
  }

  const start = await startAtprotoAuth(handle);
  if (typeof start === "string") {
    return authRedirect(url, start);
  }

  return redirect(start.authorizeUrl, [
    buildCookie(OAUTH_COOKIE, start.cookiePayload, {
      maxAge: OAUTH_TTL_SECONDS,
      path: "/cloud/auth",
      secure: url.protocol === "https:",
    }),
  ]);
}

async function atprotoCallback(request: Request, env: Env, url: URL): Promise<Response> {
  const secure = url.protocol === "https:";
  const clearOauth = oauthCookieClear(url);

  const identity = await finishAtprotoAuth(request, url, getCookie(request, OAUTH_COOKIE));
  if (typeof identity === "string") {
    return authRedirect(url, identity === "denied" ? "denied" : identity, [clearOauth]);
  }

  try {
    const user = await upsertIdentity(env, {
      provider: "atproto",
      providerUserId: identity.did,
      accountId: identity.did,
      name: clean(identity.name || identity.handle, 100),
      picture: identity.picture,
    });
    const session = await createSession(env, user.id);
    await logSignIn(env, request, user.id, "bluesky");

    return redirect(`${url.origin}/cloud/app/dashboard`, [
      clearOauth,
      buildCookie(SESSION_COOKIE, session.token, { maxAge: session.maxAge, path: "/", secure }),
    ]);
  } catch (e) {
    console.error("atproto sign in error:", (e as Error)?.message);
    return authRedirect(url, "failed", [clearOauth]);
  }
}

// ---------- shared ----------

interface IdentityInput {
  provider: string;
  providerUserId: string;
  /** user id for newly-created users: email (google) or DID (atproto) */
  accountId: string;
  name: string | null;
  picture: string | null;
}

// Find or create the user for a sign-in:
//   1. Known provider identity: refresh name/photo, sign in as that user.
//   2. Known account id, new identity: link it as another sign-in method.
//   3. Otherwise: create the user.
async function upsertIdentity(env: Env, input: IdentityInput): Promise<{ id: string; created: boolean }> {
  const db = env.ACCOUNTS;
  const now = new Date().toISOString();

  const identity = await db
    .prepare("SELECT user_id FROM identities WHERE provider = ? AND provider_user_id = ?")
    .bind(input.provider, input.providerUserId)
    .first<{ user_id: string }>();

  if (identity) {
    await db
      .prepare("UPDATE users SET name = ?, picture = ?, last_login_at = ? WHERE id = ?")
      .bind(input.name, input.picture, now, identity.user_id)
      .run();
    return { id: identity.user_id, created: false };
  }

  const existing = await db.prepare("SELECT id FROM users WHERE id = ?").bind(input.accountId).first();

  if (existing) {
    await db.batch([
      db
        .prepare("INSERT INTO identities (provider, provider_user_id, user_id, created_at) VALUES (?, ?, ?, ?)")
        .bind(input.provider, input.providerUserId, input.accountId, now),
      db
        .prepare("UPDATE users SET name = COALESCE(name, ?), picture = COALESCE(picture, ?), last_login_at = ? WHERE id = ?")
        .bind(input.name, input.picture, now, input.accountId),
    ]);
    return { id: input.accountId, created: false };
  }

  await db.batch([
    db
      .prepare("INSERT INTO users (id, name, picture, created_at, last_login_at) VALUES (?, ?, ?, ?, ?)")
      .bind(input.accountId, input.name, input.picture, now, now),
    db
      .prepare("INSERT INTO identities (provider, provider_user_id, user_id, created_at) VALUES (?, ?, ?, ?)")
      .bind(input.provider, input.providerUserId, input.accountId, now),
  ]);

  return { id: input.accountId, created: true };
}

async function logout(request: Request, env: Env, url: URL): Promise<Response> {
  // Only our own pages may sign a user out.
  const origin = request.headers.get("Origin");
  if (origin && origin !== url.origin) {
    return new Response("Forbidden", { status: 403, headers: { "Cache-Control": "no-store" } });
  }

  await destroySession(request, env);

  return redirect(
    `${url.origin}/cloud/login`,
    [buildCookie(SESSION_COOKIE, "", { maxAge: 0, path: "/", secure: url.protocol === "https:" })],
    303
  );
}
