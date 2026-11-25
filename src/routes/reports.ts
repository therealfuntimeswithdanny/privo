// Abuse reports: a public form posts here, reports land in D1 and a
// notification email goes out via the send_email binding. The admin
// endpoints are gated to a single atproto DID.

import type { Env } from "../env";
import { EmailMessage } from "cloudflare:email";
import { error, isValidUrl, json, sameOrigin } from "../lib/http";
import { requireAdmin } from "../lib/account";

const NOTIFY_TO = "danny@danielmorrisey.com";
const NOTIFY_FROM = "reports@privo.fyi";

const REASONS = new Set(["phishing", "malware", "spam", "illegal", "other"]);
const REPORT_PAGE_SIZE = 50;

// POST /api/report — public. Accepts {url, reason?, details?, contact?, website?}
// `website` is a honeypot: real browsers leave it empty.
export async function submitReport(request: Request, env: Env, url: URL): Promise<Response> {
  if (!sameOrigin(request, url)) return error("Forbidden", 403);

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return error("Request body must be valid JSON.");
  }

  // Honeypot: pretend success so bots don't adapt.
  if (typeof body.website === "string" && body.website) {
    return json({ ok: true }, { status: 201 });
  }

  const target = typeof body.url === "string" ? body.url.trim() : "";
  if (!target || target.length > 2048 || !isValidUrl(target)) {
    return error("Enter a valid HTTP or HTTPS link to report.");
  }

  const reason = typeof body.reason === "string" && REASONS.has(body.reason) ? body.reason : "other";
  const details = typeof body.details === "string" ? body.details.trim().slice(0, 2000) || null : null;
  const contactRaw = typeof body.contact === "string" ? body.contact.trim().slice(0, 320) : "";
  const contact = contactRaw && /^[^\s@]+@[^\s@]+\.[^\s@]+$|^@?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(contactRaw)
    ? contactRaw
    : null;

  let id: number;
  try {
    const row = await env.ACCOUNTS
      .prepare("INSERT INTO reports (url, reason, details, contact, reporter_ua) VALUES (?, ?, ?, ?, ?) RETURNING id")
      .bind(target, reason, details, contact, (request.headers.get("User-Agent") || "").slice(0, 300))
      .first<{ id: number }>();
    id = row!.id;
  } catch (e) {
    console.error("Report insert error:", e);
    return error("Couldn’t save that report. Try again, or email abuse@privo.fyi.", 500);
  }

  // Email is best-effort: the report is already safe in D1.
  try {
    await sendReportEmail(env, { id, url: target, reason, details, contact });
  } catch (e) {
    console.error("Report email failed:", (e as Error)?.message);
  }

  return json({ ok: true, id }, { status: 201 });
}

async function sendReportEmail(
  env: Env,
  report: { id: number; url: string; reason: string; details: string | null; contact: string | null }
): Promise<void> {
  if (!env.EMAIL) return;

  let host = report.url;
  try {
    host = new URL(report.url).hostname;
  } catch {
    // keep raw
  }

  const text = [
    `Report #${report.id} on Privo`,
    ``,
    `Link:    ${report.url}`,
    `Reason:  ${report.reason}`,
    `Details: ${report.details || "—"}`,
    `Contact: ${report.contact || "—"}`,
    ``,
    `Review reports: https://privo.fyi/cloud/admin/reports`,
  ].join("\r\n");

  const raw = [
    `From: Privo Reports <${NOTIFY_FROM}>`,
    `To: ${NOTIFY_TO}`,
    `Subject: [Privo] Link reported — ${host}`,
    `Content-Type: text/plain; charset=utf-8`,
    `MIME-Version: 1.0`,
    ``,
    text,
  ].join("\r\n");

  await env.EMAIL.send(new EmailMessage(NOTIFY_FROM, NOTIFY_TO, raw));
}

// ---------- admin ----------

interface ReportRow {
  id: number;
  url: string;
  reason: string;
  details: string | null;
  contact: string | null;
  reporter_ua: string | null;
  status: string;
  created_at: string;
  resolved_at: string | null;
}

// GET /api/admin/reports?status=open|all&before=<id>
export async function listReports(request: Request, env: Env, url: URL): Promise<Response> {
  const user = await requireAdmin(request, env);
  if (user instanceof Response) return user;

  const status = url.searchParams.get("status") || "open";
  const before = Number.parseInt(url.searchParams.get("before") || "", 10);

  let sql = "SELECT * FROM reports WHERE 1=1";
  const binds: (string | number)[] = [];

  if (status === "open" || status === "resolved" || status === "dismissed") {
    sql += " AND status = ?";
    binds.push(status);
  }
  if (Number.isFinite(before)) {
    sql += " AND id < ?";
    binds.push(before);
  }
  sql += " ORDER BY id DESC LIMIT ?";
  binds.push(REPORT_PAGE_SIZE + 1);

  const { results } = await env.ACCOUNTS.prepare(sql).bind(...binds).all<ReportRow>();
  const more = results.length > REPORT_PAGE_SIZE;
  const page = more ? results.slice(0, REPORT_PAGE_SIZE) : results;

  return json({
    reports: page.map((r) => ({
      id: r.id,
      url: r.url,
      reason: r.reason,
      details: r.details,
      contact: r.contact,
      status: r.status,
      createdAt: r.created_at,
      resolvedAt: r.resolved_at,
    })),
    next: more ? page[page.length - 1]!.id : null,
  });
}

// POST /api/admin/reports/:id/(resolve|dismiss|reopen)
export async function updateReport(request: Request, env: Env, url: URL): Promise<Response> {
  const user = await requireAdmin(request, env);
  if (user instanceof Response) return user;
  if (!sameOrigin(request, url)) return error("Forbidden", 403);

  const match = url.pathname.match(/^\/api\/admin\/reports\/(\d+)\/(resolve|dismiss|reopen)$/);
  if (!match) return error("Not found", 404);

  const id = Number(match[1]);
  const status = match[2] === "resolve" ? "resolved" : match[2] === "dismiss" ? "dismissed" : "open";

  const res = await env.ACCOUNTS
    .prepare("UPDATE reports SET status = ?, resolved_at = CASE WHEN ? = 'open' THEN NULL ELSE datetime('now') END WHERE id = ?")
    .bind(status, status, id)
    .run();

  if (!res.meta.changes) return error("Not found", 404);
  return json({ ok: true, id, status });
}
