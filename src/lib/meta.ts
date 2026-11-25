// Destination metadata: fetch a page's <head> and pull out title,
// description, image and site name (Open Graph → Twitter → plain HTML).

import type { Env } from "../env";
import { absoluteHttpUrl, clean } from "./http";
import { cacheImageState, uploadedImageKeyFromUrl } from "./images";

const META_TIMEOUT_MS = 3500;
const META_MAX_BYTES = 262144; // 256 KB is plenty to cover <head>

export interface PageMeta {
  title: string | null;
  description: string | null;
  image: string | null;
  siteName: string | null;
}

const EMPTY_META: PageMeta = { title: null, description: null, image: null, siteName: null };

/** Never throws; returns nulls for anything it can't find. */
export async function fetchPageMeta(targetUrl: string): Promise<PageMeta> {
  let target: URL;
  try {
    target = new URL(targetUrl);
  } catch {
    return EMPTY_META;
  }

  // Don't scrape ourselves.
  if (target.hostname === "privo.fyi" || target.hostname.endsWith(".privo.fyi")) {
    return EMPTY_META;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), META_TIMEOUT_MS);

  try {
    const res = await fetch(target.href, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; PrivoBot/1.0; +https://privo.fyi)",
        Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
        "Accept-Language": "en",
      },
    });

    const contentType = res.headers.get("content-type") || "";
    if (!res.ok || !/text\/html|application\/xhtml/i.test(contentType) || !res.body) {
      return EMPTY_META;
    }

    const html = await readHead(res, contentType);

    const tags: Record<string, string> = {};
    let titleText = "";
    let titleDone = false;

    await new HTMLRewriter()
      .on("title", {
        text(chunk) {
          if (titleDone) return;
          titleText += chunk.text;
          if (chunk.lastInTextNode) titleDone = true;
        },
      })
      .on("meta", {
        element(el) {
          const key = (el.getAttribute("property") || el.getAttribute("name") || "").toLowerCase();
          const content = el.getAttribute("content");
          if (key && content && !(key in tags)) tags[key] = content;
        },
      })
      .transform(new Response(html, { headers: { "content-type": "text/html" } }))
      .arrayBuffer();

    const base = res.url || target.href;

    return {
      title: clean(tags["og:title"] || tags["twitter:title"] || titleText, 200),
      description: clean(
        tags["og:description"] || tags["twitter:description"] || tags["description"],
        300
      ),
      image: absoluteHttpUrl(
        tags["og:image"] || tags["og:image:url"] || tags["twitter:image"] || tags["twitter:image:src"],
        base
      ),
      siteName: clean(tags["og:site_name"], 100),
    };
  } catch {
    return EMPTY_META;
  } finally {
    clearTimeout(timer);
  }
}

/** Read only as much of the response as needed to cover <head>. */
async function readHead(res: Response, contentType: string): Promise<string> {
  const charset = (contentType.match(/charset=([^;\s]+)/i) || [])[1];
  let decoder: TextDecoder;
  try {
    decoder = new TextDecoder(charset || "utf-8");
  } catch {
    decoder = new TextDecoder("utf-8");
  }

  const reader = res.body!.getReader();
  let html = "";
  let bytes = 0;

  try {
    while (bytes < META_MAX_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.length;
      html += decoder.decode(value, { stream: true });
      if (html.toLowerCase().includes("</head>")) break;
    }
  } finally {
    reader.cancel().catch(() => {});
  }

  return html;
}

/** image_cached: 0 = not attempted, 1 = copy stored in R2, 2 = attempted and failed. */
export async function saveMeta(
  env: Env,
  domain: string,
  shortcode: string,
  meta: PageMeta,
  imageState: number
): Promise<void> {
  await env.ACCOUNTS
    .prepare(
      `UPDATE links SET
        title = CASE WHEN seo_custom = 1 THEN COALESCE(title, ?) ELSE ? END,
        description = CASE WHEN seo_custom = 1 THEN COALESCE(description, ?) ELSE ? END,
        image = CASE WHEN seo_custom = 1 OR image LIKE 'https://privo.fyi/i/u/%' OR image LIKE 'https://privo.fyi/og/%' THEN COALESCE(image, ?) ELSE ? END,
        site_name = CASE WHEN seo_custom = 1 THEN COALESCE(site_name, ?) ELSE ? END,
        image_cached = ?, meta_fetched_at = datetime('now')
       WHERE domain = ? AND shortcode = ?`
    )
    .bind(
      meta.title, meta.title,
      meta.description, meta.description,
      meta.image, meta.image,
      meta.siteName, meta.siteName,
      imageState, domain, shortcode
    )
    .run();
}

interface BackfillRow {
  url: string;
  title: string | null;
  description: string | null;
  image: string | null;
  site_name: string | null;
  seo_custom: number;
  meta_fetched_at: string | null;
}

// Fill in whatever a link is missing. Saved even when the result is empty or
// failed so a dead destination isn't re-fetched on every visit.
export async function backfill(env: Env, domain: string, shortcode: string, row: BackfillRow): Promise<void> {
  try {
    if (!row.meta_fetched_at) {
      const fetchedMeta = await fetchPageMeta(row.url);
      const meta =
        row.seo_custom || uploadedImageKeyFromUrl(row.image)
          ? {
              title: row.title || fetchedMeta.title,
              description: row.description || fetchedMeta.description,
              image: row.image || fetchedMeta.image,
              siteName: row.site_name || fetchedMeta.siteName,
            }
          : fetchedMeta;
      const imageState = await cacheImageState(env, shortcode, meta.image, domain);
      await saveMeta(env, domain, shortcode, meta, imageState);
      return;
    }

    // Metadata exists but the image was never copied.
    const imageState = await cacheImageState(env, shortcode, row.image, domain);
    await env.ACCOUNTS
      .prepare("UPDATE links SET image_cached = ? WHERE domain = ? AND shortcode = ?")
      .bind(imageState, domain, shortcode)
      .run();
  } catch (error) {
    console.error("Backfill error:", error);
  }
}
