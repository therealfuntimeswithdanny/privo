// Serving short links on privo.fyi and on verified custom domains.
//
// A shortcode URL serves a small HTML page whose <head> mirrors the
// destination (title, description, Open Graph, Twitter card, canonical) —
// crawlers and link unfurlers read that — while people are sent on to
// privo.fyi/p/stop, the safety interstitial.

import type { Env } from "../env";
import { backfill } from "../lib/meta";
import { renderBlockedPage, renderLinkPage, type LinkRow } from "../lib/links";
import { serveCachedImage, serveUploadedImage } from "../lib/images";
import { blockedHost } from "../lib/blocklist";
import { HOSTNAME_RE } from "./domains";

const LINK_SELECT =
  "SELECT domain, url, title, description, image, site_name, seo_custom, meta_fetched_at, image_cached, safety_status, safety_threats FROM links WHERE domain = ? AND shortcode = ?";

function linkPageResponse(shortcode: string, row: LinkRow, headOnly: boolean): Response {
  return new Response(headOnly ? null : renderLinkPage(shortcode, row), {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Referrer-Policy": "no-referrer",
      "Cache-Control": "public, max-age=300",
    },
  });
}

/** privo.fyi (and dns.privo.fyi) shortcode + image routes. Returns null when nothing matched. */
export async function serveMainHost(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  url: URL
): Promise<Response | null> {
  const pathname = url.pathname;
  const isRead = request.method === "GET" || request.method === "HEAD";
  if (!isRead) return null;

  // Dated user-uploaded preview image: /og/YYYY-MM-DD/<uuid>.<ext>
  const datedImageMatch = pathname.match(/^\/og\/\d{4}-\d{2}-\d{2}\/[a-f0-9-]{36}\.(?:png|jpg|gif|webp|avif)$/i);
  if (datedImageMatch) {
    return serveUploadedImage(env, pathname.slice(1), request.method === "HEAD");
  }

  // Legacy user-uploaded preview image URL.
  const legacyUploaded = pathname.match(/^\/i\/u\/([a-f0-9-]{36})$/i);
  if (legacyUploaded) {
    return serveUploadedImage(env, `user-preview/${legacyUploaded[1]}`, request.method === "HEAD");
  }

  // Cached destination preview image: /i/<code>
  const imageMatch = pathname.match(/^\/i\/([a-zA-Z0-9]{4,})$/);
  if (imageMatch) {
    return serveCachedImage(env, imageMatch[1]!, request.method === "HEAD");
  }

  // The short link page itself.
  if (/^\/[a-zA-Z0-9]{4,}$/.test(pathname)) {
    const shortcode = pathname.slice(1);
    const row = await env.ACCOUNTS.prepare(LINK_SELECT).bind("privo.fyi", shortcode).first<LinkRow>();
    if (!row) return null; // let assets serve the 404

    if (row.safety_status === "flagged") {
      return renderBlockedPage(shortcode, row, request.method === "HEAD");
    }

    // Admin blocklist is checked live — a link blocked after creation stops
    // serving immediately.
    if (await blockedHost(env, row.url)) {
      return renderBlockedPage(
        shortcode,
        { ...row, safety_threats: '["BLOCKLIST"]' },
        request.method === "HEAD"
      );
    }

    // Links made before metadata/image caching existed get filled in once,
    // in the background. This visit gets the fallback tags.
    if (!row.meta_fetched_at || (row.image && !row.image_cached)) {
      ctx.waitUntil(backfill(env, "privo.fyi", shortcode, row as Required<LinkRow>));
    }

    return linkPageResponse(shortcode, row, request.method === "HEAD");
  }

  return null;
}

/** Any hostname that isn't ours: verified custom domains serve their own links. */
export async function serveCustomHost(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  url: URL
): Promise<Response> {
  const hostname = url.hostname;
  const pathname = url.pathname;
  const notFound = () => new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });

  // A customer's bare domain points at the info page.
  if (pathname === "/") {
    return Response.redirect(
      `https://privo.fyi/p/customdomain?domain=${encodeURIComponent(hostname)}`,
      302
    );
  }

  if (!HOSTNAME_RE.test(hostname)) return notFound();

  const verifiedDomain = await env.ACCOUNTS
    .prepare("SELECT hostname FROM domains WHERE hostname = ? AND verified = 1")
    .bind(hostname)
    .first();
  if (!verifiedDomain) return notFound();

  const isRead = request.method === "GET" || request.method === "HEAD";
  if (!isRead) return notFound();

  const imageMatch = pathname.match(/^\/i\/([a-zA-Z0-9]{4,45})$/);
  if (imageMatch) {
    return serveCachedImage(env, imageMatch[1]!, request.method === "HEAD", hostname);
  }

  if (/^\/[a-zA-Z0-9]{4,45}$/.test(pathname)) {
    const shortcode = pathname.slice(1);
    const row = await env.ACCOUNTS.prepare(LINK_SELECT).bind(hostname, shortcode).first<LinkRow>();
    if (!row) return notFound();

    if (row.safety_status === "flagged") {
      return renderBlockedPage(shortcode, row, request.method === "HEAD");
    }

    if (await blockedHost(env, row.url)) {
      return renderBlockedPage(
        shortcode,
        { ...row, safety_threats: '["BLOCKLIST"]' },
        request.method === "HEAD"
      );
    }

    if (!row.meta_fetched_at || (row.image && !row.image_cached)) {
      ctx.waitUntil(backfill(env, hostname, shortcode, row as Required<LinkRow>));
    }

    return linkPageResponse(shortcode, row, request.method === "HEAD");
  }

  return notFound();
}
