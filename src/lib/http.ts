// Response + cookie helpers. Everything on privo.fyi is same-origin, so no
// CORS headers exist anywhere: mutating endpoints instead check that Origin,
// when present, is our own origin.

export const NO_STORE = { "Cache-Control": "no-store" } as const;

export function json(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("Cache-Control", "no-store");
  return Response.json(data, { ...init, headers });
}

export function error(message: string, status = 400): Response {
  return json({ error: message }, { status });
}

/** Reject mutating requests whose Origin isn't this Worker's own origin. */
export function sameOrigin(request: Request, url: URL): boolean {
  const origin = request.headers.get("Origin");
  return !origin || origin === url.origin;
}

export function redirect(location: string, cookies: string[] = [], status = 302): Response {
  const headers = new Headers({
    Location: location,
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
  });
  for (const cookie of cookies) headers.append("Set-Cookie", cookie);
  return new Response(null, { status, headers });
}

export interface CookieOptions {
  maxAge: number;
  path?: string;
  secure?: boolean;
}

export function buildCookie(name: string, value: string, opts: CookieOptions): string {
  const { maxAge, path = "/", secure = true } = opts;
  return `${name}=${value}; Path=${path}; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

export function getCookie(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ",
};

// HTMLRewriter hands back raw text, so <title> entities need decoding.
export function decodeEntities(value: string): string {
  return value.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, entity: string) => {
    if (entity[0] === "#") {
      const code = entity[1]?.toLowerCase() === "x"
        ? parseInt(entity.slice(2), 16)
        : parseInt(entity.slice(1), 10);
      try {
        return String.fromCodePoint(code);
      } catch {
        return match;
      }
    }
    const key = entity.toLowerCase();
    return Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, key)
      ? NAMED_ENTITIES[key]!
      : match;
  });
}

/** Decode, strip control characters, collapse whitespace, cap the length. */
export function clean(value: unknown, max: number): string | null {
  if (!value) return null;
  const text = decodeEntities(String(value))
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!text) return null;
  return text.length > max ? text.slice(0, max - 1).trimEnd() + "…" : text;
}

/** Resolve a possibly-relative URL and keep it only if it's http(s). */
export function absoluteHttpUrl(value: unknown, base: string): string | null {
  if (!value) return null;
  try {
    const resolved = new URL(String(value).trim(), base);
    if (resolved.protocol !== "http:" && resolved.protocol !== "https:") return null;
    return resolved.href.length <= 2000 ? resolved.href : null;
  } catch {
    return null;
  }
}

export function isValidUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

const SHORTCODE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

export function generateShortCode(length = 6): string {
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);
  let result = "";
  for (const n of array) result += SHORTCODE_CHARS[n % SHORTCODE_CHARS.length];
  return result;
}
