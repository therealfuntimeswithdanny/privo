// AT Protocol OAuth 2.0 sign-in (Bluesky, Eurosky, Blacksky, self-hosted PDS).
//
// Flow (atproto spec): handle → DID → PDS → authorization server → PAR
// (client_id is our public client-metadata document, PKCE + DPoP proof) →
// user consent → callback → token exchange (PKCE + DPoP) → DID confirmed by
// the token response's `sub`. Tokens are never stored.

import type { Env } from "../env";
import { base64url, base64urlDecode, base64urlEncode, randomToken, sha256 } from "../lib/crypto";
import { dpopProof, generateDpopKey, type DpopKeyPair } from "./dpop";

// Client metadata document. Hosted on privo.coffeencode.cc because
// Cloudflare edge security on privo.fyi challenges the PDS auth server's
// non-browser fetch — different zone, no bot rules. The doc must live at
// exactly this URL and its client_id must match.
export const ATCLIENT_ID = "https://privo.coffeencode.cc/oauth-client-metadata.json";
// Sign-in only: the base atproto scope, no additional permissions.
export const ATPROTO_SCOPE = "atproto";
export const ATPROTO_REDIRECT = "https://privo.fyi/cloud/auth/atproto/callback";

export interface OAuthStart {
  /** b64url-encoded state the callback verifies */
  state: string;
  /** Cookie payload (b64url JSON) carrying everything the callback needs */
  cookiePayload: string;
  /** Where to send the user for consent */
  authorizeUrl: string;
}

export type AtprotoError =
  | "invalid_handle"
  | "no_pds"
  | "no_auth_server"
  | "par_failed"
  | "state_mismatch"
  | "token_failed"
  | "denied";

interface AuthServerMeta {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  pushed_authorization_request_endpoint?: string;
  dpop_signing_alg_values_supported?: string[];
}

// ---------- handle → DID → PDS → authorization server ----------

async function resolveHandle(handle: string): Promise<string | null> {
  // Preferred: XRPC via the public API (works for any handle whose DNS TXT
  // or did doc is resolvable).
  try {
    const res = await fetch(
      `https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(handle)}`
    );
    if (res.ok) {
      const data = (await res.json()) as { did?: string };
      if (data.did && data.did.startsWith("did:")) return data.did;
    }
  } catch {
    // fall through to .well-known
  }

  // Fallback: https://{handle}/.well-known/atproto-did
  try {
    const res = await fetch(`https://${handle}/.well-known/atproto-did`);
    if (res.ok) {
      const did = (await res.text()).trim();
      if (did.startsWith("did:")) return did;
    }
  } catch {
    // give up
  }
  return null;
}

interface DidDocService {
  id?: string;
  type?: string;
  serviceEndpoint?: string;
}

interface DidDoc {
  service?: DidDocService[];
}

async function pdsFromDid(did: string): Promise<string | null> {
  try {
    let doc: DidDoc | null = null;

    if (did.startsWith("did:plc:")) {
      const res = await fetch(`https://plc.directory/${did}`);
      if (res.ok) doc = (await res.json()) as DidDoc;
    } else if (did.startsWith("did:web:")) {
      const host = did.slice("did:web:".length).replace(/%3A/g, ":");
      const res = await fetch(`https://${host}/.well-known/did.json`);
      if (res.ok) doc = (await res.json()) as DidDoc;
    }

    const service = doc?.service?.find(
      (s) => s.id === "#atproto_pds" || s.id?.endsWith("#atproto_pds") || s.type === "AtprotoPersonalDataServer"
    );
    return service?.serviceEndpoint || null;
  } catch {
    return null;
  }
}

async function authServerFromPds(pds: string): Promise<AuthServerMeta | null> {
  try {
    const prRes = await fetch(`${pds}/.well-known/oauth-protected-resource`);
    if (!prRes.ok) return null;
    const pr = (await prRes.json()) as { authorization_servers?: string[] };
    const iss = pr.authorization_servers?.[0];
    if (!iss) return null;

    const asRes = await fetch(`${iss}/.well-known/oauth-authorization-server`);
    if (!asRes.ok) return null;
    const meta = (await asRes.json()) as AuthServerMeta;
    if (!meta.authorization_endpoint || !meta.token_endpoint) return null;
    return meta;
  } catch {
    return null;
  }
}

// ---------- DPoP-bound POSTs (PAR and token share the nonce-retry dance) ----------

async function dpopPost(
  key: DpopKeyPair,
  endpoint: string,
  params: URLSearchParams,
  iss?: string
): Promise<Response> {
  let nonce: string | undefined;

  for (let attempt = 0; attempt < 2; attempt++) {
    const proof = await dpopProof(key, "POST", endpoint, { iss, nonce });
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        DPoP: proof,
      },
      body: params,
    });

    if (res.ok) return res;
    if (attempt > 0) return res;

    // Retry once with the nonce the server demands.
    const headerNonce = res.headers.get("DPoP-Nonce");
    let bodyNonce: string | null = null;
    try {
      const body = (await res.clone().json()) as { error?: string; dpop_nonce?: string };
      if (body.error === "use_dpop_nonce" && typeof body.dpop_nonce === "string") {
        bodyNonce = body.dpop_nonce;
      }
    } catch {
      // no json body
    }
    nonce = headerNonce || bodyNonce || undefined;
    if (!nonce) return res;
  }

  throw new Error("unreachable");
}

// ---------- the flow ----------

export async function startAtprotoAuth(handle: string): Promise<OAuthStart | AtprotoError> {
  const did = await resolveHandle(handle);
  if (!did) return "invalid_handle";

  const pds = await pdsFromDid(did);
  if (!pds) return "no_pds";

  return startWithPds(pds, { did, handle });
}

// Account creation: the PDS's own authorization server hosts the sign-up
// UI — we just PAR into it with our client metadata, no handle needed.
export async function startAtprotoCreate(pdsOrigin: string): Promise<OAuthStart | AtprotoError> {
  return startWithPds(pdsOrigin, {});
}

async function startWithPds(
  pds: string,
  identity: { did?: string; handle?: string }
): Promise<OAuthStart | AtprotoError> {
  const authServer = await authServerFromPds(pds);
  if (!authServer) return "no_auth_server";

  const parEndpoint = authServer.pushed_authorization_request_endpoint;
  if (!parEndpoint) return "no_auth_server";

  const state = randomToken(24);
  const verifier = randomToken(48);
  const challenge = base64url(await sha256(verifier));
  const dpop = await generateDpopKey();

  const params = new URLSearchParams({
    client_id: ATCLIENT_ID,
    redirect_uri: ATPROTO_REDIRECT,
    response_type: "code",
    scope: ATPROTO_SCOPE,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  if (identity.handle) params.set("login_hint", identity.handle);

  const parRes = await dpopPost(dpop, parEndpoint, params, ATCLIENT_ID);
  if (!parRes.ok) {
    console.error("atproto PAR failed:", parRes.status, await parRes.text().catch(() => ""));
    return "par_failed";
  }

  const par = (await parRes.json()) as { request_uri?: string };
  if (!par.request_uri) return "par_failed";

  const cookiePayload = base64urlEncode(
    JSON.stringify({
      state,
      verifier,
      dpop: dpop.privateJwk,
      iss: authServer.issuer,
      did: identity.did ?? null,
      handle: identity.handle ?? null,
    })
  );

  const authorize = new URL(authServer.authorization_endpoint);
  authorize.searchParams.set("client_id", ATCLIENT_ID);
  authorize.searchParams.set("request_uri", par.request_uri);

  return { state, cookiePayload, authorizeUrl: authorize.toString() };
}

export interface AtprotoIdentity {
  did: string;
  handle: string;
  name: string | null;
  picture: string | null;
}

export async function finishAtprotoAuth(
  request: Request,
  url: URL,
  cookieValue: string | null
): Promise<AtprotoIdentity | AtprotoError> {
  const params = url.searchParams;

  if (params.get("error")) return "denied";

  const code = params.get("code");
  const state = params.get("state");
  if (!code || !state || !cookieValue) return "state_mismatch";

  const saved = base64urlDecode<{
    state: string;
    verifier: string;
    dpop: JsonWebKey;
    iss: string;
    did: string | null;
    handle: string | null;
  }>(cookieValue);
  if (!saved || saved.state !== state) return "state_mismatch";

  const authServer = await authServerFromIssuer(saved.iss);
  if (!authServer) return "no_auth_server";

  const key: DpopKeyPair = {
    privateJwk: saved.dpop,
    publicJwk: { kty: "EC", crv: "P-256", x: saved.dpop.x!, y: saved.dpop.y! },
  };

  const tokenParams = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: ATPROTO_REDIRECT,
    client_id: ATCLIENT_ID,
    code_verifier: saved.verifier,
  });

  const tokenRes = await dpopPost(key, authServer.token_endpoint, tokenParams, ATCLIENT_ID);
  if (!tokenRes.ok) {
    console.error("atproto token exchange failed:", tokenRes.status, await tokenRes.text().catch(() => ""));
    return "token_failed";
  }

  const tokens = (await tokenRes.json()) as { access_token?: string; sub?: string };
  // `sub` is the DID the user authorized as — when we started with a
  // known handle it must match; on the create flow it's brand new.
  if (!tokens.sub || (saved.did && tokens.sub !== saved.did)) return "token_failed";
  const did = tokens.sub;

  // Display name + avatar from the public API — no token needed.
  let handle = saved.handle;
  let name: string | null = saved.handle;
  let picture: string | null = null;
  try {
    const profileRes = await fetch(
      `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(did)}`
    );
    if (profileRes.ok) {
      const profile = (await profileRes.json()) as {
        displayName?: string;
        handle?: string;
        avatar?: string;
      };
      name = profile.displayName || profile.handle || saved.handle;
      handle = profile.handle || saved.handle;
      // Serve avatars via our own CDN — same paths, different host.
      if (profile.avatar && profile.avatar.startsWith("https://")) {
        picture = profile.avatar.replace("https://cdn.bsky.app", "https://cdn.coffeencode.cc");
      }
    }
  } catch {
    // keep what we have
  }

  return { did, handle: handle || did, name, picture };
}

async function authServerFromIssuer(iss: string): Promise<AuthServerMeta | null> {
  try {
    const res = await fetch(`${iss}/.well-known/oauth-authorization-server`);
    if (!res.ok) return null;
    const meta = (await res.json()) as AuthServerMeta;
    if (!meta.authorization_endpoint || !meta.token_endpoint) return null;
    return meta;
  } catch {
    return null;
  }
}
