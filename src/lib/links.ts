// The page served at a shortcode: mirrors the destination's SEO/OG tags for
// crawlers and unfurlers, then sends humans to the /p/stop safety interstitial.

import { escapeHtml } from "./http";
import { publicImage } from "./images";

export interface LinkRow {
  domain: string;
  url: string;
  title: string | null;
  description: string | null;
  image: string | null;
  site_name: string | null;
  image_cached: number | null;
  safety_status?: string;
  safety_threats?: string | null;
  meta_fetched_at?: string | null;
  seo_custom?: number;
}

/** Interstitial URL for a stored destination — handles ?, &, #, unicode. */
function buildStopUrl(destination: string): string {
  const stop = new URL("https://privo.fyi/p/stop");
  stop.searchParams.set("url", destination);
  stop.searchParams.set("viaPrivo", "true");
  return stop.toString();
}

export function renderLinkPage(shortcode: string, row: LinkRow): string {
  const destination = new URL(row.url);
  const host = destination.hostname.replace(/^www\./, "");
  const domain = row.domain || "privo.fyi";
  const shortUrl = `https://${domain}/${shortcode}`;
  const stopUrl = buildStopUrl(row.url);

  const title = row.title || host;
  const description = row.description || `Shortened link to ${host}`;
  const siteName = row.site_name || host;
  const image = publicImage(shortcode, row.image, row.image_cached, domain);

  const e = escapeHtml;

  // Safe to embed in a <script>: stopUrl is fully percent-encoded, and "<" is escaped anyway.
  const stopJs = JSON.stringify(stopUrl).replace(/</g, "\\u003c");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta name="robots" content="index, follow, max-image-preview:large">
  <meta name="theme-color" content="#1c1310">
  <title>${e(title)}</title>
  <meta name="description" content="${e(description)}">
  <link rel="canonical" href="${e(destination.href)}">

  <meta property="og:type" content="website">
  <meta property="og:site_name" content="${e(siteName)}">
  <meta property="og:title" content="${e(title)}">
  <meta property="og:description" content="${e(description)}">
  <meta property="og:url" content="${e(shortUrl)}">${image ? `
  <meta property="og:image" content="${e(image)}">` : ""}

  <meta name="twitter:card" content="${image ? "summary_large_image" : "summary"}">
  <meta name="twitter:title" content="${e(title)}">
  <meta name="twitter:description" content="${e(description)}">${image ? `
  <meta name="twitter:image" content="${e(image)}">` : ""}

  <meta http-equiv="refresh" content="0;url=${e(stopUrl)}">
  <style>
    html { background: #1c1310; }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      background: #1c1310; color: #d4975c;
      font: 18px/1.4 "Inria Serif", Georgia, serif;
    }
    a { color: #e8c28a; }
  </style>
</head>
<body>
  <p>Taking you to the safety check… <a href="${e(stopUrl)}">Continue</a></p>
  <script>location.replace(${stopJs});</script>
</body>
</html>`;
}

const THREAT_LABELS: Record<string, string> = {
  MALWARE: "malware",
  SOCIAL_ENGINEERING: "phishing or other social engineering",
  UNWANTED_SOFTWARE: "unwanted software",
};

/** Shown instead of a redirect. Deliberately does not link to the destination. */
export function renderBlockedPage(shortcode: string, row: LinkRow, headOnly: boolean): Response {
  let threats: string[] = [];
  try {
    threats = JSON.parse(row.safety_threats || "[]");
  } catch {
    threats = [];
  }

  const reasons = [...new Set(threats.map((t) => THREAT_LABELS[t] || "a security risk"))];
  const reasonText = reasons.length ? reasons.join(" and ") : "a security risk";

  let host = "this site";
  try {
    host = new URL(row.url).hostname.replace(/^www\./, "");
  } catch {
    // keep the fallback
  }

  const e = escapeHtml;

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <meta name="referrer" content="no-referrer">
  <meta name="theme-color" content="#1c1310">
  <title>Link blocked · Privo</title>
  <style>
    html { background: #1c1310; }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px;
      background: #1c1310; color: #e8c28a;
      font: 18px/1.5 "Inria Serif", Georgia, serif;
    }
    main {
      max-width: 480px; padding: 32px; border-radius: 20px;
      background: #d4975c; color: #000; text-align: center;
    }
    h1 { margin: 0 0 16px; font-size: 32px; font-weight: 400; }
    p { margin: 0 0 14px; }
    a { color: #000; }
  </style>
</head>
<body>
  <main>
    <h1>Link blocked</h1>
    <p>Google Web Risk has flagged <strong>${e(host)}</strong> for ${e(reasonText)}, so Privo won't send you there.</p>
    <p><a href="mailto:abuse@privo.fyi?subject=${encodeURIComponent("Link blocked: " + shortcode)}">Report a mistake</a></p>
  </main>
</body>
</html>`;

  return new Response(headOnly ? null : html, {
    status: 403,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Referrer-Policy": "no-referrer",
      "X-Robots-Tag": "noindex, nofollow",
      "Cache-Control": "public, max-age=300",
    },
  });
}
