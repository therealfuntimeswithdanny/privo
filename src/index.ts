// Privo.fyi — one Worker on one domain.
//
// Pipeline: JSON API → OAuth → uploaded/cached images → short links →
// static assets → custom domains → 404.

import type { Env } from "./env";
import { error, json } from "./lib/http";
import { recheckLinks } from "./lib/webrisk";
import * as linksApi from "./routes/links";
import { uploadImage } from "./routes/upload";
import * as account from "./routes/account";
import { handleDomains, recheckDomains } from "./routes/domains";
import { handleAuth } from "./routes/auth";
import { listReports, submitReport, updateReport } from "./routes/reports";
import { addToBlocklist, listBlocklist, removeFromBlocklist } from "./routes/admin";
import { serveCustomHost, serveMainHost } from "./routes/shortlink";

const OWN_HOSTS = new Set(["privo.fyi", "dns.privo.fyi"]);

// Content pages at pretty root paths. Checked before the shortcode matcher so
// these paths can never be treated as links — and shortcodes can't shadow them.
// Values are the assets binding's canonical extensionless paths (asking assets
// for a .html URL just 307s back to the extensionless form).
export const PAGE_MAP: Record<string, string> = {
  "/about": "/p/about",
  "/terms": "/p/terms",
  "/privacy": "/p/privacy",
  "/stop": "/p/stop",
  "/report": "/report",
  "/login": "/cloud/login",
  "/admin": "/cloud/admin/reports",
  "/cloud": "/cloud/",
};

// Old locations 301 to the pretty paths (bookmarks, indexed pages).
const PAGE_REDIRECTS: Record<string, string> = {
  "/legal/terms": "/terms",
  "/legal/terms.html": "/terms",
  "/legal/privacy": "/privacy",
  "/legal/privacy.html": "/privacy",
  "/p/about.html": "/about",
  "/p/terms.html": "/terms",
  "/p/privacy.html": "/privacy",
  "/cloud/index.html": "/cloud",
};

export default {
  // Cron (every 12 hours): re-check links against Web Risk and pending
  // domains against Cloudflare.
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(recheckLinks(env));
    ctx.waitUntil(recheckDomains(env));
  },

  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const hostname = url.hostname;
    const pathname = url.pathname;

    // ==========================================
    // 0. CUSTOM DOMAINS (anything that isn't ours)
    // ==========================================
    if (!OWN_HOSTS.has(hostname)) {
      return serveCustomHost(request, env, ctx, url);
    }

    // ==========================================
    // 1. API ROUTES (/api/*) — same origin, no CORS
    // ==========================================
    if (pathname.startsWith("/api/")) {
      if (pathname === "/api/link" && request.method === "POST") {
        return linksApi.createLink(request, env);
      }

      const editLinkMatch = pathname.match(/^\/api\/cloud\/link\/([a-zA-Z0-9]{4,45})$/);
      if (editLinkMatch && (request.method === "GET" || request.method === "PUT")) {
        return linksApi.editLink(request, env, url, editLinkMatch[1]!);
      }

      if (pathname.startsWith("/api/link/") && request.method === "GET") {
        return linksApi.getLink(env, pathname.split("/")[3] || "");
      }

      if (pathname === "/api/cloud/upload-image" && request.method === "POST") {
        return uploadImage(request, env, url);
      }

      if (pathname === "/api/me" && request.method === "GET") {
        return account.me(request, env);
      }

      if (pathname === "/api/cloud/dashboard" && request.method === "GET") {
        return account.dashboard(request, env);
      }

      if (pathname.startsWith("/api/cloud/domains")) {
        return handleDomains(request, env, url);
      }

      if (pathname === "/api/cloud/logs" && request.method === "GET") {
        return account.logs(request, env, url);
      }

      if (pathname === "/api/check" && request.method === "GET") {
        return linksApi.checkDestination(env, ctx, url);
      }

      if (pathname === "/api/report" && request.method === "POST") {
        return submitReport(request, env, url);
      }

      if (pathname === "/api/admin/reports" && request.method === "GET") {
        return listReports(request, env, url);
      }

      if (pathname.startsWith("/api/admin/reports/") && request.method === "POST") {
        return updateReport(request, env, url);
      }

      if (pathname === "/api/admin/blocklist" && request.method === "GET") {
        return listBlocklist(request, env);
      }
      if (pathname === "/api/admin/blocklist" && request.method === "POST") {
        return addToBlocklist(request, env, url);
      }
      if (pathname.startsWith("/api/admin/blocklist/") && request.method === "DELETE") {
        return removeFromBlocklist(request, env, url);
      }

      return json({ error: "API endpoint not found" }, { status: 404 });
    }

    // ==========================================
    // 2. SIGN IN (/cloud/auth/*)
    // ==========================================
    if (pathname.startsWith("/cloud/auth/")) {
      return handleAuth(request, env, url);
    }

    // ==========================================
    // 3a. PAGES at pretty root paths (before shortcodes, so /about is never a link)
    // ==========================================
    if (request.method === "GET" || request.method === "HEAD") {
      const redirectTo = PAGE_REDIRECTS[pathname];
      if (redirectTo) {
        const target = new URL(redirectTo, url);
        target.search = url.search;
        return Response.redirect(target.toString(), 301);
      }
      const assetPath = PAGE_MAP[pathname];
      if (assetPath) {
        const pageUrl = new URL(assetPath, url);
        pageUrl.search = url.search;
        return env.ASSETS.fetch(new Request(pageUrl.toString(), request));
      }
    }

    // ==========================================
    // 3. SHORT LINKS + IMAGES (before assets, since codes have no extension)
    // ==========================================
    const shortlink = await serveMainHost(request, env, ctx, url);
    if (shortlink) return shortlink;

    // ==========================================
    // 4. STATIC SITE (assets binding; 404.html on misses)
    // ==========================================
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
