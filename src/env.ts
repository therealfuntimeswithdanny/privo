export interface Env {
  /** D1: users, identities, sessions, links, domains, audit_logs, r2_files, teams, usage */
  ACCOUNTS: D1Database;
  /** R2: cached OG images and user-uploaded preview images */
  IMAGES: R2Bucket;
  /** Static site served by this Worker */
  ASSETS: Fetcher;

  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  WEB_RISK_API_KEY?: string;
  CF_API_TOKEN?: string;
  CF_ZONE_ID?: string;
  /** Cron link re-check batch size (default 40) */
  RECHECK_BATCH?: string;
}
