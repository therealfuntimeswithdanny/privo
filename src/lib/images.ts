// Preview images: destinations' OG images copied into R2 and served from our
// domain (/i/<code>), plus user-uploaded images (/og/YYYY-MM-DD/<uuid>).

import type { Env } from "../env";

const IMAGE_TIMEOUT_MS = 3000;
export const IMAGE_MAX_BYTES = 5 * 1024 * 1024; // 5 MB

export function imageKey(shortcode: string, domain = "privo.fyi"): string {
  return domain === "privo.fyi" ? `og/${shortcode}` : `og/${domain}/${shortcode}`;
}

export function imageExtension(contentType: string): string | undefined {
  return {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/avif": ".avif",
  }[contentType];
}

/** If a URL points at one of our own uploaded images, return its R2 key. */
export function uploadedImageKeyFromUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.hostname !== "privo.fyi" ||
      url.port ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    ) {
      return null;
    }

    const dated = url.pathname.match(/^\/og\/(\d{4}-\d{2}-\d{2})\/([a-f0-9-]{36}\.(?:png|jpg|gif|webp|avif))$/i);
    if (dated) return `og/${dated[1]}/${dated[2]!.toLowerCase()}`;

    const legacy = url.pathname.match(/^\/i\/u\/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/i);
    return legacy ? `user-preview/${legacy[1]!.toLowerCase()}` : null;
  } catch {
    return null;
  }
}

/** Our own URL when a copy exists, otherwise the destination's original. */
export function publicImage(
  shortcode: string,
  source: string | null | undefined,
  imageState: number | null | undefined,
  domain = "privo.fyi"
): string | null {
  if (!source) return null;
  if (uploadedImageKeyFromUrl(source)) return source;
  return Number(imageState) === 1 ? `https://${domain}/i/${shortcode}` : source;
}

/** Returns the image_cached value to store: 0 (no image), 1 (cached), 2 (failed). */
export async function cacheImageState(
  env: Env,
  shortcode: string,
  imageUrl: string | null,
  domain = "privo.fyi"
): Promise<number> {
  if (!imageUrl) return 0;
  const uploadedKey = uploadedImageKeyFromUrl(imageUrl);
  if (uploadedKey) {
    if (!env.IMAGES) return 2;
    return (await env.IMAGES.head(uploadedKey)) ? 1 : 2;
  }
  return (await cacheImage(env, shortcode, imageUrl, domain)) ? 1 : 2;
}

// Copy a destination's preview image into R2. Only real raster images are
// kept (type sniffed from the bytes, not trusted from headers) and SVG is
// refused, since it can carry script and would be served from privo.fyi.
async function cacheImage(env: Env, shortcode: string, imageUrl: string, domain: string): Promise<boolean> {
  if (!env.IMAGES) return false;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), IMAGE_TIMEOUT_MS);

  try {
    const res = await fetch(imageUrl, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; PrivoBot/1.0; +https://privo.fyi)",
        Accept: "image/avif,image/webp,image/png,image/jpeg,image/gif,*/*;q=0.1",
      },
    });

    if (!res.ok || !res.body) return false;

    const declared = Number(res.headers.get("content-length"));
    if (declared && declared > IMAGE_MAX_BYTES) return false;

    const bytes = await readLimitedBytes(res, IMAGE_MAX_BYTES);
    if (!bytes) return false;

    const contentType = sniffImageType(bytes);
    if (!contentType) return false;

    await env.IMAGES.put(imageKey(shortcode, domain), bytes, {
      httpMetadata: { contentType },
      customMetadata: { source: imageUrl.slice(0, 1000) },
    });

    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/** Read a body fully, or return null if it exceeds maxBytes. */
export async function readLimitedBytes(res: Response, maxBytes: number): Promise<Uint8Array | null> {
  const reader = res.body!.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        reader.cancel().catch(() => {});
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export async function readLimitedRequestBody(request: Request, maxBytes: number): Promise<Uint8Array | null> {
  if (!request.body) return null;

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

/** Identify PNG / JPEG / GIF / WebP / AVIF from magic bytes. */
export function sniffImageType(b: Uint8Array | null): string | null {
  if (!b || b.length < 12) return null;

  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return "image/gif";

  const tag = (start: number) => String.fromCharCode(b[start]!, b[start + 1]!, b[start + 2]!, b[start + 3]!);
  if (tag(0) === "RIFF" && tag(8) === "WEBP") return "image/webp";
  if (tag(4) === "ftyp" && (tag(8) === "avif" || tag(8) === "avis")) return "image/avif";

  return null;
}

export async function serveCachedImage(env: Env, shortcode: string, headOnly: boolean, domain = "privo.fyi"): Promise<Response> {
  const notFound = () => new Response("Not found", { status: 404 });

  if (!env.IMAGES) return notFound();

  const object = await env.IMAGES.get(imageKey(shortcode, domain));
  if (!object) return notFound();

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Cache-Control", "public, max-age=86400");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Content-Security-Policy", "default-src 'none'");
  headers.set("Cross-Origin-Resource-Policy", "cross-origin");
  headers.set("Access-Control-Allow-Origin", "*");

  return new Response(headOnly ? null : object.body, { status: 200, headers });
}

export async function serveUploadedImage(env: Env, key: string, headOnly: boolean): Promise<Response> {
  const notFound = () =>
    new Response("Not found", { status: 404, headers: { "X-Content-Type-Options": "nosniff" } });

  if (!env.IMAGES) return notFound();

  const object = await env.IMAGES.get(key);
  if (!object) return notFound();

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Cache-Control", "public, max-age=31536000, immutable");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Content-Security-Policy", "default-src 'none'");
  headers.set("Cross-Origin-Resource-Policy", "cross-origin");
  headers.set("Access-Control-Allow-Origin", "*");

  return new Response(headOnly ? null : object.body, { status: 200, headers });
}
