// The branded stop page served at {custom-domain}/p/stop. Same behaviour as
// privo.fyi/p/stop — Web Risk check, 20s countdown, Proceed button — but
// rendered with the domain owner's brand name, logo, accent colour and
// message instead of Privo's.

import { escapeHtml } from "./http";

export interface StopBranding {
  brand: string | null;
  logo: string | null;
  color: string | null;
  message: string | null;
}

const COLOR_RE = /^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i;

/** Server-side cleanup, mirrored by the PUT endpoint's validation. */
export function cleanStopColor(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const v = value.trim().toLowerCase();
  return COLOR_RE.test(v) ? v : null;
}

export function cleanStopText(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  const v = value.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  return v && v.length <= max ? v : null;
}

export function cleanStopLogo(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const v = value.trim();
  if (v.length > 300) return null;
  try {
    const u = new URL(v);
    return u.protocol === "https:" ? u.href : null;
  } catch {
    return null;
  }
}

export function renderCustomStop(hostname: string, branding: StopBranding): Response {
  const brand = branding.brand || hostname;
  const logo = branding.logo;
  const color = branding.color;
  const message = branding.message;

  const e = escapeHtml;
  // For embedding in <script>: JSON.stringify + escape "<" kills any breakout.
  const brandJs = JSON.stringify(brand).replace(/</g, "\\u003c");
  const title = `Whoa, wait a second! · ${brand}`;

  const icon = logo
    ? `<img class="brand-logo" src="${e(logo)}" alt="" referrerpolicy="no-referrer">`
    : `<div class="stop-icon" aria-hidden="true"><i class="fa-solid fa-hand"></i></div>`;

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="robots" content="noindex, nofollow">
  <meta name="referrer" content="no-referrer">
  <meta name="theme-color" content="#140d08">
  <meta name="color-scheme" content="dark">
  <title>${e(title)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://kit.fontawesome.com/8f1701cd51.js" crossorigin="anonymous" defer><\/script>
  <style>
    :root {
      --bg: #140d08;
      --panel: #1e150d;
      --panel-2: #261a10;
      --border: #3a2918;
      --border-strong: #574026;
      --peach: ${color || "#d4975c"};
      --peach-hi: ${color || "#e8c28a"};
      --text: #f0e6da;
      --muted: #a8978a;
      --faint: #7a6a5e;
      --black: #160e08;
      --card-radius: 16px;
    }
    *, *::before, *::after { box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      margin: 0; min-height: 100vh; min-height: 100dvh;
      display: flex; align-items: flex-start; justify-content: center;
      padding: 50px 16px;
      background:
        radial-gradient(1000px 520px at 78% -10%, rgb(212 151 92 / 14%), transparent 62%),
        radial-gradient(900px 700px at -8% 110%, rgb(150 95 55 / 13%), transparent 62%),
        linear-gradient(168deg, #1d1309 0%, var(--bg) 55%, #0e0906 100%);
      color: var(--text);
      font-family: "Inter", system-ui, sans-serif;
      text-rendering: optimizeLegibility;
      -webkit-font-smoothing: antialiased;
    }
    ::selection { background: var(--peach); color: var(--bg); }
    a { color: inherit; }
    a, button { -webkit-tap-highlight-color: transparent; }
    :focus-visible { outline: 2px solid var(--peach); outline-offset: 3px; }
    .card {
      position: relative; width: 100%; max-width: 440px; min-height: 732px;
      padding: 34px 36px 22px;
      display: flex; flex-direction: column; align-items: center; text-align: center;
      border: 1px solid var(--border); border-radius: var(--card-radius);
      background: linear-gradient(180deg, var(--panel-2), var(--panel));
      box-shadow: 0 1px 0 rgb(255 255 255 / 4%) inset, 0 24px 60px rgb(0 0 0 / 40%);
    }
    .stop-icon {
      flex: none; display: flex; align-items: center; justify-content: center;
      width: 72px; height: 72px; border-radius: 18px;
      background: rgb(212 151 92 / 12%); color: var(--peach);
      font-size: 34px; line-height: 1;
    }
    .brand-logo {
      flex: none; width: 72px; height: 72px; border-radius: 18px;
      object-fit: contain; background: rgb(255 255 255 / 4%);
    }
    h1 {
      margin: 24px 0 0;
      font-family: "Space Grotesk", system-ui, sans-serif;
      font-size: 28px; font-weight: 600; line-height: 1.15; letter-spacing: -.02em;
    }
    .lede {
      margin: 22px 0 0; font-size: 16px; line-height: 1.45;
      color: var(--muted); overflow-wrap: anywhere;
    }
    .lede strong { font-weight: 600; color: var(--peach); }
    .source-note {
      margin: 12px 0 0; font-size: 14px; line-height: 1.45;
      color: var(--muted); overflow-wrap: anywhere;
    }
    .source-note strong { font-weight: 600; color: var(--text); }
    .custom-message {
      margin: 14px 0 0; padding: 10px 14px;
      border: 1px solid var(--border); border-radius: 10px;
      background: rgb(255 255 255 / 3%);
      font-size: 13px; line-height: 1.5; color: var(--muted);
      overflow-wrap: anywhere;
    }
    .countdown { margin: 36px 0 4px; font-size: 14px; line-height: 1.4; color: var(--faint); }
    .countdown strong { font-weight: 600; color: var(--text); }
    .proceed {
      display: flex; align-items: center; justify-content: center;
      width: 100%; min-height: 56px; padding: 10px 16px;
      border: 0; border-radius: 10px;
      background: linear-gradient(145deg, var(--peach), #c2854d);
      color: var(--black);
      font: 600 16px/1.2 "Inter", system-ui, sans-serif;
      text-decoration: none; overflow-wrap: anywhere;
      transition: transform .16s ease, background .16s ease;
    }
    .proceed:hover { transform: translateY(-1px); background: linear-gradient(145deg, var(--peach-hi), var(--peach)); }
    .proceed:active { transform: none; }
    .disclaimer { margin: 10px 0 0; font-size: 12px; line-height: 1.5; color: var(--faint); }
    .spacer { flex: 1 1 auto; min-height: 24px; }
    .powered {
      display: inline-flex; align-items: center; gap: 8px;
      height: 40px; padding: 0 14px;
      border: 1px solid var(--border-strong); border-radius: 999px;
      background: rgb(255 255 255 / 3%); color: var(--muted);
      font-size: 13px; text-decoration: none;
      transition: border-color .16s ease, background .16s ease, color .16s ease;
    }
    .powered:hover { border-color: var(--peach); background: rgb(212 151 92 / 10%); color: var(--peach); }
    .powered i { font-size: 15px; line-height: 1; }
    .powered em { font-style: italic; }
    .footer-links { margin: 16px 0 0; font-size: 12px; color: var(--faint); }
    .footer-links a { color: var(--muted); text-underline-offset: 2px; }
    .footer-links a:hover { color: var(--peach); }
    .card.is-error .proceed { display: none; }
    .error-detail { margin: 20px 0 0; font-size: 14px; line-height: 1.5; color: var(--muted); }
    .error-detail code {
      padding: 1px 6px; border: 1px solid var(--border-strong); border-radius: 6px;
      background: var(--bg); color: var(--peach);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 13px; white-space: nowrap;
    }
    .error-detail ul { margin: 10px 0 0; padding: 0; list-style: none; }
    .error-detail li + li { margin-top: 6px; }
    [hidden] { display: none !important; }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: .01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: .01ms !important;
      }
    }
    @media (max-width: 480px) {
      body { padding: 16px; }
      .card { min-height: calc(100dvh - 32px); padding-left: 24px; padding-right: 24px; }
      h1 { font-size: 24px; }
    }
  </style>
</head>

<body>
  <main class="card" id="card" aria-labelledby="title">

    ${icon}

    <h1 id="title">Whoa, wait a second!</h1>

    <p class="lede" id="lede">Checking this link…</p>
    <p class="source-note" id="source-note" hidden></p>${message ? `
    <p class="custom-message">${e(message)}</p>` : ""}
    <div class="error-detail" id="error-detail" hidden></div>

    <p class="countdown" id="countdown" hidden>
      You’ll be redirected in <strong id="seconds">20</strong> <span id="seconds-label">seconds</span>
    </p>

    <a class="proceed" id="proceed" href="#" rel="noreferrer noopener" hidden>Proceed</a>

    <p class="disclaimer" id="disclaimer" hidden>
      <span id="disclaimer-text">${e(brand)} can’t determine the authenticity of this site, if you believe this
      site is malicious please</span> <a id="report-inline" href="https://privo.fyi/report">report it</a>
    </p>

    <noscript>
      <p class="disclaimer">Please enable JavaScript to view this link’s destination.</p>
    </noscript>

    <div class="spacer"></div>

    <a class="powered" href="https://privo.fyi" aria-label="Powered by Privo.fyi">
      <i class="fa-solid fa-link" aria-hidden="true"></i>
      <span>Powered by Privo.<em>fyi</em></span>
    </a>

    <p class="footer-links">
      <a id="report-footer" href="https://privo.fyi/report">Report malicious link</a>
      -
      <a href="https://privo.fyi/privacy">Privacy Policy</a>
    </p>

  </main>

  <script>
    "use strict";

    (() => {
      const COUNTDOWN_SECONDS = 20;
      const BRAND = ${brandJs};

      const params = new URLSearchParams(window.location.search);

      const $ = (id) => document.getElementById(id);
      const card = $("card");
      const lede = $("lede");
      const sourceNote = $("source-note");
      const errorDetail = $("error-detail");
      const countdown = $("countdown");
      const secondsEl = $("seconds");
      const secondsLabel = $("seconds-label");
      const proceed = $("proceed");
      const disclaimer = $("disclaimer");

      /* Only plain http(s) URLs are ever accepted. */
      function parseHttpUrl(value) {
        if (!value) return null;
        try {
          const parsed = new URL(value);
          if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
          return parsed;
        } catch {
          return null;
        }
      }

      function renderLede(target) {
        lede.textContent = "";
        lede.append(BRAND + " is sending you to ");
        const strong = document.createElement("strong");
        strong.textContent = target.origin;
        lede.append(strong);
        lede.append(", please verify this is the site you intend to visit.");
      }

      function setReportLinks(target) {
        const href = "https://privo.fyi/report?url=" + encodeURIComponent(target);
        $("report-inline").href = href;
        $("report-footer").href = href;
      }

      /* Same-origin: the worker serves /api/check on this domain too.
         Fails open if the check errors or takes longer than 5 seconds. */
      async function checkDestination(href) {
        const controller = new AbortController();
        const abortTimer = window.setTimeout(() => controller.abort(), 5000);
        try {
          const res = await fetch("/api/check?url=" + encodeURIComponent(href), {
            signal: controller.signal,
            cache: "no-store",
            referrerPolicy: "no-referrer"
          });
          if (!res.ok) return { status: "unchecked", threats: [] };
          const data = await res.json();
          if (data && data.status === "flagged") {
            return { status: "flagged", threats: Array.isArray(data.threats) ? data.threats : [] };
          }
          return { status: data && data.status === "clean" ? "clean" : "unchecked", threats: [] };
        } catch {
          return { status: "unchecked", threats: [] };
        } finally {
          window.clearTimeout(abortTimer);
        }
      }

      const THREAT_LABELS = {
        MALWARE: "malware",
        SOCIAL_ENGINEERING: "phishing or other social engineering",
        UNWANTED_SOFTWARE: "unwanted software"
      };

      const target = parseHttpUrl(params.get("url"));

      function showBlocked(threats) {
        card.classList.add("is-error");
        document.title = "Link blocked · " + BRAND;
        $("title").textContent = "This link has been blocked";

        const reasons = [...new Set(threats.map((t) => THREAT_LABELS[t] || "a security risk"))];
        const reasonText = reasons.length ? reasons.join(" and ") : "a security risk";

        lede.textContent = "";
        lede.append("Google Web Risk has flagged ");
        const hostStrong = document.createElement("strong");
        hostStrong.textContent = target.host;
        lede.append(hostStrong, " for " + reasonText + ", so we won’t send you there.");

        sourceNote.hidden = true;
        countdown.hidden = true;
        proceed.hidden = true;
        disclaimer.hidden = true;

        errorDetail.hidden = false;
        errorDetail.textContent = "";
        const note = document.createElement("p");
        note.style.margin = "0";
        note.append("If you think this is a mistake, email ");
        const mail = document.createElement("a");
        mail.href = "mailto:abuse@privo.fyi";
        mail.textContent = "abuse@privo.fyi";
        note.append(mail, ".");
        errorDetail.append(note);
      }

      function showError() {
        card.classList.add("is-error");
        document.title = "Invalid link · " + BRAND;
        $("title").textContent = "Hmm, that link isn’t right.";
        lede.textContent = "We couldn’t work out where this link is supposed to go, so we haven’t sent you anywhere.";
        errorDetail.hidden = false;
        errorDetail.textContent = "This link is missing or has an invalid url parameter.";
      }

      if (!target) {
        showError();
        return;
      }

      lede.textContent = "Checking this link…";
      setReportLinks(target.href);

      checkDestination(target.href).then((result) => {
        if (result.status === "flagged") {
          showBlocked(result.threats);
          return;
        }
        showDestination(result.status);
      });

      function showDestination(status) {
        if (status === "clean") {
          $("disclaimer-text").textContent =
            "This link passed the Google Web Risk check. " +
            BRAND + " can’t guarantee a site is safe, if you believe this site is malicious please";
        }

        renderLede(target);

        sourceNote.hidden = false;
        sourceNote.textContent =
          "You are viewing this page because the link you clicked was shortened using ";
        const brandStrong = document.createElement("strong");
        brandStrong.textContent = BRAND;
        sourceNote.append(brandStrong, ".");

        proceed.href = target.href;
        proceed.textContent = "Proceed to " + target.host;
        proceed.hidden = false;

        disclaimer.hidden = false;
        countdown.hidden = false;

        setReportLinks(target.href);

        let remaining = COUNTDOWN_SECONDS;

        function paint() {
          secondsEl.textContent = String(remaining);
          secondsLabel.textContent = remaining === 1 ? "second" : "seconds";
        }

        paint();

        const timer = window.setInterval(() => {
          remaining -= 1;
          if (remaining <= 0) {
            window.clearInterval(timer);
            window.location.replace(target.href);
            return;
          }
          paint();
        }, 1000);

        proceed.addEventListener("click", () => window.clearInterval(timer));
      }
    })();
  <\/script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Referrer-Policy": "no-referrer",
      "Cache-Control": "no-store",
    },
  });
}
