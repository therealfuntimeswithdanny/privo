# Privo.fyi

A safety-first link shortener: every link is checked against Google Web Risk,
every visit goes through a warning interstitial, and short pages mirror the
destination's SEO/Open Graph tags so unfurls look right.

**One Cloudflare Worker on one domain** (`privo.fyi`), written in TypeScript.
The static site is served by the Worker's Assets binding — there is no Pages
site, no `api.`/`redirect.` hostnames, and no CORS anywhere.

## Layout

```
src/
  index.ts          request pipeline + cron entry
  env.ts            bindings/secrets interface
  lib/              http, crypto, webrisk, meta, images, links, account
  routes/           links, upload, account, domains, auth, shortlink
  atproto/          AT Protocol OAuth (PAR + PKCE + DPoP)
assets/             the static site
migrations/         D1 schema (idempotent; matches the live database)
```

## Deploy

```bash
npm install
npm run typecheck
npx wrangler d1 migrations apply privo --remote
npx wrangler deploy
```

### Secrets / vars

| Name | Where | Purpose |
| --- | --- | --- |
| `GOOGLE_CLIENT_ID` | secret | Google sign-in |
| `GOOGLE_CLIENT_SECRET` | secret | Google sign-in |
| `WEB_RISK_API_KEY` | secret | safety checks + 12 h cron re-check |
| `CF_API_TOKEN` | secret | custom hostnames (Zone: SSL & Certs) |
| `CF_ZONE_ID` | var | zone for custom hostnames |
| `RECHECK_BATCH` | var (opt) | links re-checked per cron run (default 40) |

### One-time production steps after migrating from the old worker

1. **Google OAuth**: add `https://privo.fyi/cloud/auth/google/callback` as an
   authorized redirect URI (the old `api.privo.fyi` callback is dead).
2. **Bluesky/ATProto**: `assets/oauth-client-metadata.json` already declares
   `https://privo.fyi/cloud/auth/atproto/callback` — the AS validates it once
   the new worker is live.
3. **DNS**: `api.privo.fyi`, `redirect.privo.fyi`, `proxy.privo.fyi` records
   can be removed. Keep `dns.privo.fyi` — it's the CNAME target for customer
   custom domains (Cloudflare for SaaS).
4. **Pages**: the old Pages project can be torn down; `assets/` now serves
   everything, including `404.html` (`not_found_handling = "404-page"`).

## Request pipeline

1. `/api/*` — JSON API (session-cookie auth, same-origin only)
2. `/cloud/auth/*` — Google + Bluesky sign-in, logout
3. `/og/…`, `/i/u/…`, `/i/<code>` — uploaded / cached preview images (R2)
4. `/<code>` — link page (OG tags for crawlers, then → `/p/stop`)
5. everything else — `assets/`
6. any other hostname — verified custom domains serve their own links;
   `/` redirects to the custom-domain info page, else 404

## Safety

- `POST /api/link` and the 12-hour cron call Google Web Risk
  `hashes:search` — only 4-byte hash prefixes leave the worker.
- Flagged links serve a "Link blocked" page (never redirect, never fetch
  metadata/images); flagged destinations can't be created or saved by edit.
- `/p/stop` calls `/api/check`, whose verdicts are cached 1 h under a
  hashed key so addresses aren't stored.
- No IP addresses are logged anywhere; audit rows keep method/country/OS/
  browser only.
