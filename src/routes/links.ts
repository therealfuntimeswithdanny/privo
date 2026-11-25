// Link API: create, edit, read, and destination safety checks.

import type { Env } from "../env";
import { error, generateShortCode, isValidUrl, json, sameOrigin } from "../lib/http";
import { checkSafety, checkSafetyCached } from "../lib/webrisk";
import { fetchPageMeta, saveMeta } from "../lib/meta";
import { cacheImageState, publicImage, uploadedImageKeyFromUrl } from "../lib/images";
import { authenticate, type SessionUser } from "../lib/account";
import { blockedHost } from "../lib/blocklist";

const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SHORTCODE_RE = /^[a-zA-Z0-9]{4,45}$/;

// Names of pages and route prefixes on privo.fyi — they can never be
// shortcodes there (the page map is checked before the shortcode matcher,
// so a link with one of these names would be unreachable).
const RESERVED_SHORTCODES = new Set([
  "about", "terms", "privacy", "stop", "report", "login", "admin", "cloud",
  "assets", "api", "legal", "auth", "me", "docs",
]);

function reservedCode(domain: string, code: string): boolean {
  return domain === "privo.fyi" && RESERVED_SHORTCODES.has(code.toLowerCase());
}

interface SeoInput {
  title: string | null;
  description: string | null;
  siteName: string | null;
  image: string | null;
}

/** Validate the `seo` object. Returns null on success, or the error Response. */
function parseSeo(raw: unknown, required: boolean): { seo: SeoInput | null; err: Response | null } {
  const seo: SeoInput = { title: null, description: null, siteName: null, image: null };

  if (raw === undefined && !required) return { seo, err: null };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { seo, err: error("SEO metadata must be an object") };
  }

  const fields: [keyof SeoInput, number][] = [
    ["title", 200],
    ["description", 1000],
    ["siteName", 100],
    ["image", 2048],
  ];
  for (const [field, maxLength] of fields) {
    const value = (raw as Record<string, unknown>)[field];
    if (value !== undefined && value !== null && typeof value !== "string") {
      return { seo, err: error(`SEO ${field} must be text`) };
    }
    const normalized = typeof value === "string" ? value.trim() : "";
    if (normalized.length > maxLength) {
      return { seo, err: error(`SEO ${field} is too long`) };
    }
    seo[field] = normalized || null;
  }
  if (seo.image && !isValidUrl(seo.image)) {
    return { seo, err: error("SEO image must be an HTTP or HTTPS URL") };
  }

  return { seo, err: null };
}

/** Resolve and authorize the domain a link is created under. */
async function resolveLinkDomain(
  raw: unknown,
  user: SessionUser | null
): Promise<{ domain: string | null; err: Response | null }> {
  const requested = raw === undefined ? "privo.fyi" : raw;
  if (typeof requested !== "string") return { domain: null, err: error("Invalid link domain.") };

  const domain = requested.trim().toLowerCase();
  if (domain !== "privo.fyi" && !DOMAIN_RE.test(domain)) {
    return { domain: null, err: error("Invalid link domain.") };
  }
  if (domain === "privo.fyi") return { domain, err: null };

  if (!user) return { domain: null, err: error("Sign in to use a custom domain.", 401) };
  return { domain, err: null };
}

async function ownedDomain(env: Env, hostname: string, userId: string): Promise<boolean> {
  const row = await env.ACCOUNTS
    .prepare("SELECT hostname FROM domains WHERE hostname = ? AND owner_id = ? AND verified = 1")
    .bind(hostname, userId)
    .first();
  return Boolean(row);
}

// POST /api/link
export async function createLink(request: Request, env: Env): Promise<Response> {
  try {
    const body = (await request.json()) as Record<string, unknown>;
    const targetUrl = body.url;
    const customShortcode = body.shortcode as string | undefined;

    if (!isValidUrl(targetUrl)) {
      return error("Invalid URL provided");
    }

    const auth = await authenticate(request, env);
    const owner = auth?.user ?? null;

    const { domain: linkDomain, err: domainErr } = await resolveLinkDomain(body.domain, owner);
    if (domainErr) return domainErr;

    // API keys carry scopes: links:write covers privo.fyi, links:custom covers
    // the account's verified domains. Sessions are unrestricted.
    if (auth?.scopes && !auth.scopes.includes(linkDomain === "privo.fyi" ? "links:write" : "links:custom")) {
      return error("This API key doesn't have permission to create links on that domain.", 403);
    }
    if (linkDomain !== "privo.fyi" && !(await ownedDomain(env, linkDomain!, owner!.id))) {
      return error("Choose a verified custom domain on your account.", 403);
    }

    const { seo: customMeta, err: seoErr } = await parseSeo(body.seo, false);
    if (seoErr) return seoErr;
    const hasCustomSeo = Object.values(customMeta!).some(Boolean);

    // Safety checks first: blocklist and Web Risk are refused before
    // anything is stored or fetched from the destination.
    const blocked = await blockedHost(env, targetUrl);
    if (blocked) {
      return error("That destination is blocked and can't be shortened.", 422);
    }
    const safety = await checkSafety(env, targetUrl);
    if (safety.status === "flagged") {
      return json(
        {
          error: "This URL was flagged by Google Web Risk and can't be shortened.",
          threats: safety.threats,
        },
        { status: 422 }
      );
    }

    let shortcode = customShortcode;

    if (shortcode) {
      if (!SHORTCODE_RE.test(shortcode)) {
        return error("Shortcode must be 4-45 alphanumeric characters");
      }
      if (reservedCode(linkDomain!, shortcode)) {
        return error("That name is reserved for a Privo page", 409);
      }
      const existing = await env.ACCOUNTS
        .prepare("SELECT shortcode FROM links WHERE domain = ? AND shortcode = ?")
        .bind(linkDomain, shortcode)
        .first();
      if (existing) return error("Shortcode already taken", 409);
    } else {
      let attempts = 0;
      while (attempts < 10) {
        shortcode = generateShortCode();
        const existing = await env.ACCOUNTS
          .prepare("SELECT shortcode FROM links WHERE domain = ? AND shortcode = ?")
          .bind(linkDomain, shortcode)
          .first();
        if (!existing && !reservedCode(linkDomain!, shortcode)) break;
        attempts++;
      }
      if (attempts >= 10) return error("Failed to generate unique shortcode", 500);
    }

    // Database triggers keep usage and the audit log.
    try {
      await env.ACCOUNTS
        .prepare(
          "INSERT INTO links (domain, shortcode, url, created_by, safety_status, safety_threats, safety_checked_at, title, description, image, site_name, seo_custom) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(
          linkDomain,
          shortcode,
          targetUrl,
          owner ? owner.id : null,
          safety.status,
          safety.threats ? JSON.stringify(safety.threats) : null,
          safety.checkedAt,
          customMeta!.title,
          customMeta!.description,
          customMeta!.image,
          customMeta!.siteName,
          hasCustomSeo ? 1 : 0
        )
        .run();
    } catch (insertError) {
      if (String((insertError as Error)?.message).includes("LIMIT_D1")) {
        return error("Your account has reached its 300 MB database limit.", 403);
      }
      throw insertError;
    }

    // Grab the destination's SEO/preview metadata (and a copy of its
    // preview image) so the short link page can present itself as the
    // destination. Never blocks link creation.
    let preview: { title: string | null; description: string | null; image: string | null; siteName: string | null } | null =
      hasCustomSeo
        ? {
            title: customMeta!.title,
            description: customMeta!.description,
            image: customMeta!.image,
            siteName: customMeta!.siteName,
          }
        : null;

    try {
      const fetchedMeta = await fetchPageMeta(targetUrl);
      const meta = {
        title: customMeta!.title || fetchedMeta.title,
        description: customMeta!.description || fetchedMeta.description,
        image: customMeta!.image || fetchedMeta.image,
        siteName: customMeta!.siteName || fetchedMeta.siteName,
      };
      const imageState = await cacheImageState(env, shortcode!, meta.image, linkDomain!);
      await saveMeta(env, linkDomain!, shortcode!, meta, imageState);

      preview = {
        title: meta.title,
        description: meta.description,
        image: publicImage(shortcode!, meta.image, imageState, linkDomain!),
        siteName: meta.siteName,
      };
    } catch (metaError) {
      console.error("Metadata fetch error:", metaError);
    }

    return json(
      {
        shortcode,
        shortUrl: `https://${linkDomain}/${shortcode}`,
        originalUrl: targetUrl,
        safety: safety.status,
        preview,
      },
      { status: 201 }
    );
  } catch (err) {
    console.error("Create link error:", err);
    return error("Failed to create short link", 500);
  }
}

// GET /api/link/:shortcode?domain=… — public for privo.fyi links. Reading a
// link on a custom domain requires auth and ownership of that domain.
export async function getLink(request: Request, env: Env, url: URL, shortcode: string): Promise<Response> {
  if (!shortcode) return error("Shortcode required");

  const domain = (url.searchParams.get("domain") || "privo.fyi").toLowerCase();
  if (!DOMAIN_RE.test(domain)) return error("Invalid link domain.");

  if (domain !== "privo.fyi") {
    const auth = await authenticate(request, env);
    if (!auth) return error("Sign in or send an API key.", 401);
    if (auth.scopes && !auth.scopes.includes("links:read") && !auth.scopes.includes("links:custom")) {
      return error("This API key doesn't have permission to read links.", 403);
    }
    if (!(await ownedDomain(env, domain, auth.user.id))) {
      return error("Choose a verified custom domain on your account.", 403);
    }
  }

  const result = await env.ACCOUNTS
    .prepare(
      "SELECT url, created_at, title, description, image, site_name, image_cached FROM links WHERE domain = ? AND shortcode = ?"
    )
    .bind(domain, shortcode)
    .first<{
      url: string;
      created_at: string;
      title: string | null;
      description: string | null;
      image: string | null;
      site_name: string | null;
      image_cached: number;
    }>();

  if (!result) return error("Not found", 404);

  return json({
    shortcode,
    url: result.url,
    createdAt: result.created_at,
    shortUrl: `https://${domain}/${shortcode}`,
    preview: {
      title: result.title,
      description: result.description,
      image: publicImage(shortcode, result.image, result.image_cached, domain),
      siteName: result.site_name,
    },
  });
}

// GET|PUT /api/cloud/link/:shortcode — the owner's editor.
export async function editLink(request: Request, env: Env, url: URL, shortcode: string): Promise<Response> {
  const auth = await authenticate(request, env);
  if (!auth) return error("Sign in or send an API key.", 401);
  const user = auth.user;

  // The Origin check guards browser sessions; an API key is its own credential.
  if (request.method === "PUT" && auth.scopes === null && !sameOrigin(request, url)) {
    return error("Edits must come from Privo Cloud.", 403);
  }

  const domain = (url.searchParams.get("domain") || "privo.fyi").toLowerCase();
  if (!DOMAIN_RE.test(domain)) return error("Invalid link domain.");

  if (auth.scopes && !auth.scopes.includes(domain === "privo.fyi" ? "links:write" : "links:custom")) {
    return error("This API key doesn't have permission for that domain.", 403);
  }

  interface LinkEditRow {
    id: number;
    url: string;
    title: string | null;
    description: string | null;
    image: string | null;
    site_name: string | null;
    image_cached: number;
    seo_custom: number;
  }

  let link: LinkEditRow | null;
  try {
    link = await env.ACCOUNTS
      .prepare(
        "SELECT id, url, title, description, image, site_name, image_cached, seo_custom FROM links WHERE domain = ? AND shortcode = ? AND created_by = ?"
      )
      .bind(domain, shortcode, user.id)
      .first<LinkEditRow>();
  } catch (e) {
    console.error("Link edit lookup error:", e);
    return error("Could not load this link.", 500);
  }
  if (!link) return error("Link not found", 404);

  if (request.method === "GET") {
    return json({
      shortcode,
      shortLink: `${domain}/${shortcode}`,
      url: link.url,
      title: link.title,
      description: link.description,
      image: link.image,
      siteName: link.site_name,
    });
  }

  // PUT
  try {
    let body: Record<string, unknown>;
    try {
      body = (await request.json()) as Record<string, unknown>;
    } catch {
      return error("Request body must be valid JSON.");
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return error("Request body must be an object.");
    }

    const targetUrl = typeof body.url === "string" ? body.url.trim() : "";
    if (!targetUrl || targetUrl.length > 2048 || !isValidUrl(targetUrl)) {
      return error("Enter a valid HTTP or HTTPS destination URL.");
    }

    const { seo, err: seoErr } = await parseSeo(body.seo, true);
    if (seoErr) return seoErr;

    const uploadedImageKeyValue = seo!.image && uploadedImageKeyFromUrl(seo!.image);
    if (uploadedImageKeyValue) {
      const ownedImage = await env.ACCOUNTS
        .prepare("SELECT 1 AS owned FROM r2_files WHERE user_id = ? AND r2_key = ?")
        .bind(user.id, uploadedImageKeyValue)
        .first();
      if (!ownedImage) {
        return error("That uploaded image does not belong to your account.", 403);
      }
    }

    const blocked = await blockedHost(env, targetUrl);
    if (blocked) {
      return error("That destination is blocked and can't be used.", 422);
    }

    const safety = await checkSafety(env, targetUrl);
    if (safety.status === "flagged") {
      return json(
        { error: "This destination was flagged by Google Web Risk and can't be used.", threats: safety.threats },
        { status: 422 }
      );
    }

    const fetched = await fetchPageMeta(targetUrl);
    const meta = {
      title: seo!.title || fetched.title,
      description: seo!.description || fetched.description,
      siteName: seo!.siteName || fetched.siteName,
      image: seo!.image || fetched.image,
    };
    const imageState = await cacheImageState(env, shortcode, meta.image, domain);

    try {
      const results = await env.ACCOUNTS.batch([
        env.ACCOUNTS
          .prepare(
            "UPDATE links SET url = ?, title = ?, description = ?, image = ?, site_name = ?, seo_custom = ?, image_cached = ?, safety_status = ?, safety_threats = ?, safety_checked_at = ?, updated_by = ? WHERE id = ? AND created_by = ?"
          )
          .bind(
            targetUrl,
            meta.title,
            meta.description,
            meta.image,
            meta.siteName,
            Object.values(seo!).some(Boolean) ? 1 : 0,
            imageState,
            safety.status,
            safety.threats ? JSON.stringify(safety.threats) : null,
            safety.checkedAt,
            user.id,
            link.id,
            user.id
          ),
        env.ACCOUNTS
          .prepare("UPDATE links SET meta_fetched_at = datetime('now') WHERE id = ? AND created_by = ?")
          .bind(link.id, user.id),
      ]);
      if (!results[0]?.meta?.changes) return error("Link not found", 404);
    } catch (e) {
      if (String((e as Error)?.message).includes("LIMIT_D1")) {
        return error("Your account has reached its 300 MB database limit.", 403);
      }
      throw e;
    }

    return json({
      shortcode,
      shortLink: `${domain}/${shortcode}`,
      url: targetUrl,
      title: meta.title,
      description: meta.description,
      image: publicImage(shortcode, meta.image, imageState, domain),
      siteName: meta.siteName,
    });
  } catch (e) {
    console.error("Link edit error:", e);
    return error("Could not update this link.", 500);
  }
}

// GET /api/check?url=... — called by the stop page for every redirect.
export async function checkDestination(env: Env, ctx: ExecutionContext, url: URL): Promise<Response> {
  const target = url.searchParams.get("url");

  if (!target || target.length > 2048 || !isValidUrl(target)) {
    return json({ error: "Invalid URL provided" }, { status: 400 });
  }

  // The admin blocklist wins over (and precedes) the cached Web Risk verdict.
  if (await blockedHost(env, target)) {
    return json({ status: "flagged", threats: ["BLOCKLIST"] });
  }

  const result = await checkSafetyCached(env, ctx, target);
  return json({ status: result.status, threats: result.threats || [] });
}
