export default {
  // Cron trigger (every 12 hours): re-check existing links against Web Risk.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(recheckLinks(env));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const hostname = url.hostname;
    const pathname = url.pathname;

    // CORS headers: the Pages frontend on privo.fyi calls this API with
    // credentials (the session cookie), so the origin must be exact and
    // credentials must be allowed.
    const corsHeaders = {
      "Access-Control-Allow-Origin": "https://privo.fyi",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Cache-Control": "no-store, no-cache, must-revalidate, private"
    };

    // Headers for /api/me, so the frontend can read the signed-in user.
    const meHeaders = {
      "Access-Control-Allow-Origin": "https://privo.fyi",
      "Access-Control-Allow-Credentials": "true",
      "Cache-Control": "no-store"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // ==========================================
    // 1. API ROUTES (/api/*)
    // Handle these FIRST before Pages pass-through
    // ==========================================
    if (pathname.startsWith("/api/")) {
      const editLinkMatch = pathname.match(/^\/api\/cloud\/link\/([a-zA-Z0-9]{4,45})$/);
      if (editLinkMatch && (request.method === "GET" || request.method === "PUT")) {
        const user = await getSessionUser(request, env);
        if (!user) {
          return Response.json({ error: "Not signed in" }, { status: 401, headers: meHeaders });
        }
        if (request.method === "PUT" && request.headers.get("Origin") !== "https://privo.fyi") {
          return Response.json({ error: "Edits must come from Privo Cloud." }, { status: 403, headers: corsHeaders });
        }

        const shortcode = editLinkMatch[1];
        const domain = (url.searchParams.get("domain") || "privo.fyi").toLowerCase();
        if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(domain)) {
          return Response.json({ error: "Invalid link domain." }, { status: 400, headers: corsHeaders });
        }
        let link;
        try {
          link = await env.ACCOUNTS
            .prepare(
              "SELECT id, url, title, description, image, site_name, image_cached, seo_custom FROM links WHERE domain = ? AND shortcode = ? AND created_by = ?"
            )
            .bind(domain, shortcode, user.id)
            .first();
        } catch (error) {
          console.error("Link edit lookup error:", error);
          return Response.json({ error: "Could not load this link." }, { status: 500, headers: meHeaders });
        }
        if (!link) {
          return Response.json({ error: "Link not found" }, { status: 404, headers: corsHeaders });
        }

        if (request.method === "GET") {
          return Response.json(
            {
              shortcode,
              shortLink: `${domain}/${shortcode}`,
              url: link.url,
              title: link.title,
              description: link.description,
              image: link.image,
              siteName: link.site_name
            },
            { status: 200, headers: meHeaders }
          );
        }

        try {
          let body;
          try {
            body = await request.json();
          } catch (_) {
            return Response.json({ error: "Request body must be valid JSON." }, { status: 400, headers: corsHeaders });
          }
          if (!body || typeof body !== "object" || Array.isArray(body)) {
            return Response.json({ error: "Request body must be an object." }, { status: 400, headers: corsHeaders });
          }
          const targetUrl = typeof body.url === "string" ? body.url.trim() : "";
          if (!targetUrl || targetUrl.length > 2048 || !isValidUrl(targetUrl)) {
            return Response.json({ error: "Enter a valid HTTP or HTTPS destination URL." }, { status: 400, headers: corsHeaders });
          }
          if (!body.seo || typeof body.seo !== "object" || Array.isArray(body.seo)) {
            return Response.json({ error: "SEO metadata must be an object." }, { status: 400, headers: corsHeaders });
          }

          const seo = { title: null, description: null, siteName: null, image: null };
          for (const [field, maxLength] of [["title", 200], ["description", 1000], ["siteName", 100], ["image", 2048]]) {
            const value = body.seo[field];
            if (value !== undefined && value !== null && typeof value !== "string") {
              return Response.json({ error: "SEO " + field + " must be text." }, { status: 400, headers: corsHeaders });
            }
            const normalized = typeof value === "string" ? value.trim() : "";
            if (normalized.length > maxLength) {
              return Response.json({ error: "SEO " + field + " is too long." }, { status: 400, headers: corsHeaders });
            }
            seo[field] = normalized || null;
          }
          if (seo.image && !isValidUrl(seo.image)) {
            return Response.json({ error: "SEO image must be an HTTP or HTTPS URL." }, { status: 400, headers: corsHeaders });
          }

          const uploadedImageKeyValue = seo.image && uploadedImageKeyFromUrl(seo.image);
          if (uploadedImageKeyValue) {
            const ownedImage = await env.ACCOUNTS
              .prepare("SELECT 1 AS owned FROM r2_files WHERE user_id = ? AND r2_key = ?")
              .bind(user.id, uploadedImageKeyValue)
              .first();
            if (!ownedImage) {
              return Response.json({ error: "That uploaded image does not belong to your account." }, { status: 403, headers: corsHeaders });
            }
          }

          const safety = await checkSafety(env, targetUrl);
          if (safety.status === "flagged") {
            return Response.json(
              { error: "This destination was flagged by Google Web Risk and can't be used.", threats: safety.threats },
              { status: 422, headers: corsHeaders }
            );
          }

          const fetched = await fetchPageMeta(targetUrl);
          const meta = {
            title: seo.title || fetched.title,
            description: seo.description || fetched.description,
            siteName: seo.siteName || fetched.siteName,
            image: seo.image || fetched.image
          };
          const imageState = await cacheImageState(env, shortcode, meta.image);

          try {
            const results = await env.ACCOUNTS.batch([
              env.ACCOUNTS
                .prepare(
                  "UPDATE links SET url = ?, title = ?, description = ?, image = ?, site_name = ?, seo_custom = ?, image_cached = ?, safety_status = ?, safety_threats = ?, safety_checked_at = ?, updated_by = ? WHERE id = ? AND created_by = ?"
                )
                .bind(
                  targetUrl,
                  meta.title,
                  meta.description,
                  meta.image,
                  meta.siteName,
                  Object.values(seo).some(Boolean) ? 1 : 0,
                  imageState,
                  safety.status,
                  safety.threats ? JSON.stringify(safety.threats) : null,
                  safety.checkedAt,
                  user.id,
                  link.id,
                  user.id
                ),
              env.ACCOUNTS
                .prepare("UPDATE links SET meta_fetched_at = datetime('now') WHERE id = ? AND created_by = ?")
                .bind(link.id, user.id)
            ]);
            if (!results[0]?.meta?.changes) {
              return Response.json({ error: "Link not found" }, { status: 404, headers: corsHeaders });
            }
          } catch (error) {
            if (String(error && error.message).includes("LIMIT_D1")) {
              return Response.json(
                { error: "Your account has reached its 1 GB database limit." },
                { status: 403, headers: corsHeaders }
              );
            }
            throw error;
          }

          return Response.json(
            {
              shortcode,
              shortLink: `${domain}/${shortcode}`,
              url: targetUrl,
              title: meta.title,
              description: meta.description,
              image: publicImage(shortcode, meta.image, imageState),
              siteName: meta.siteName
            },
            { status: 200, headers: corsHeaders }
          );
        } catch (error) {
          console.error("Link edit error:", error);
          return Response.json({ error: "Could not update this link." }, { status: 500, headers: corsHeaders });
        }
      }

      // Upload an account-owned preview image to R2.
      if (pathname === "/api/cloud/upload-image" && request.method === "POST") {
        if (request.headers.get("Origin") !== "https://privo.fyi") {
          return Response.json(
            { error: "Uploads must come from Privo Cloud." },
            { status: 403, headers: corsHeaders }
          );
        }

        const user = await getSessionUser(request, env);
        if (!user) {
          return Response.json({ error: "Not signed in" }, { status: 401, headers: meHeaders });
        }
        if (!env.IMAGES) {
          return Response.json(
            { error: "Image storage is unavailable right now." },
            { status: 503, headers: corsHeaders }
          );
        }

        const requestContentType = request.headers.get("Content-Type") || "";
        if (!/^multipart\/form-data\s*;/i.test(requestContentType)) {
          return Response.json(
            { error: "Choose an image file to upload." },
            { status: 400, headers: corsHeaders }
          );
        }

        const contentLength = Number(request.headers.get("Content-Length"));
        if (contentLength && contentLength > IMAGE_MAX_BYTES + 65536) {
          return Response.json(
            { error: "Preview images must be 5 MB or smaller." },
            { status: 413, headers: corsHeaders }
          );
        }

        let form;
        try {
          const body = await readLimitedRequestBody(request, IMAGE_MAX_BYTES + 65536);
          if (!body) {
            return Response.json(
              { error: "Preview images must be 5 MB or smaller." },
              { status: 413, headers: corsHeaders }
            );
          }
          const formRequest = new Request(request.url, {
            method: "POST",
            headers: { "Content-Type": requestContentType },
            body
          });
          form = await formRequest.formData();
        } catch (error) {
          console.error("Preview image form error:", error);
          return Response.json(
            { error: "Choose an image file to upload." },
            { status: 400, headers: corsHeaders }
          );
        }

        const file = form.get("image");
        if (!(file instanceof File) || !file.size) {
          return Response.json(
            { error: "Choose an image file to upload." },
            { status: 400, headers: corsHeaders }
          );
        }
        if (file.size > IMAGE_MAX_BYTES) {
          return Response.json(
            { error: "Preview images must be 5 MB or smaller." },
            { status: 413, headers: corsHeaders }
          );
        }

        let bytes;
        try {
          bytes = new Uint8Array(await file.arrayBuffer());
        } catch (error) {
          console.error("Preview image read error:", error);
          return Response.json(
            { error: "Could not read the selected image." },
            { status: 400, headers: corsHeaders }
          );
        }

        const contentType = sniffImageType(bytes);
        if (!contentType) {
          return Response.json(
            { error: "Use a PNG, JPEG, GIF, WebP, or AVIF image." },
            { status: 415, headers: corsHeaders }
          );
        }

        const date = new Date().toISOString().slice(0, 10);
        const imageName = crypto.randomUUID() + imageExtension(contentType);
        const key = `og/${date}/${imageName}`;
        const imageUrl = `https://privo.fyi/${key}`;

        try {
          await env.IMAGES.put(key, bytes, {
            httpMetadata: { contentType },
            customMetadata: { owner: user.id, kind: "custom-preview" }
          });
        } catch (error) {
          console.error("Preview image upload error:", error);
          return Response.json(
            { error: "Could not upload the image. Try again." },
            { status: 500, headers: corsHeaders }
          );
        }

        try {
          await env.ACCOUNTS
            .prepare("INSERT INTO r2_files (user_id, r2_key, file_url, content_type, size_bytes) VALUES (?, ?, ?, ?, ?)")
            .bind(user.id, key, imageUrl, contentType, bytes.byteLength)
            .run();
        } catch (error) {
          try {
            await env.IMAGES.delete(key);
          } catch (cleanupError) {
            console.error("Preview image cleanup error:", cleanupError);
            return Response.json(
              { error: "Upload could not be recorded and its temporary file could not be removed. Contact support." },
              { status: 500, headers: corsHeaders }
            );
          }

          const message = String(error && error.message);
          if (message.includes("LIMIT_R2")) {
            return Response.json(
              { error: "Your account has reached its R2 storage limit." },
              { status: 403, headers: corsHeaders }
            );
          }
          if (message.includes("LIMIT_D1")) {
            return Response.json(
              { error: "Your account has reached its 1 GB database limit." },
              { status: 403, headers: corsHeaders }
            );
          }
          console.error("Preview image record error:", error);
          return Response.json(
            { error: "The image uploaded, but its account record could not be saved." },
            { status: 500, headers: corsHeaders }
          );
        }

        return Response.json(
          { image: imageUrl, contentType, size: bytes.byteLength },
          { status: 201, headers: corsHeaders }
        );
      }

      // Create short link: POST /api/link
      if (pathname === "/api/link" && request.method === "POST") {
        try {
          const body = await request.json();
          const { url: targetUrl, shortcode: customShortcode } = body;

          if (!targetUrl || !isValidUrl(targetUrl)) {
            return Response.json(
              { error: "Invalid URL provided" },
              { status: 400, headers: corsHeaders }
            );
          }

          const seo = body.seo;
          const customMeta = { title: null, description: null, image: null, siteName: null };
          if (seo !== undefined && (!seo || typeof seo !== "object" || Array.isArray(seo))) {
            return Response.json(
              { error: "SEO metadata must be an object" },
              { status: 400, headers: corsHeaders }
            );
          }
          if (seo) {
            const seoFields = [
              ["title", 200],
              ["description", 1000],
              ["siteName", 100],
              ["image", 2048]
            ];
            for (const [field, maxLength] of seoFields) {
              const value = seo[field];
              if (value !== undefined && value !== null && typeof value !== "string") {
                return Response.json(
                  { error: "SEO " + field + " must be text" },
                  { status: 400, headers: corsHeaders }
                );
              }
              const normalized = typeof value === "string" ? value.trim() : "";
              if (normalized.length > maxLength) {
                return Response.json(
                  { error: "SEO " + field + " is too long" },
                  { status: 400, headers: corsHeaders }
                );
              }
              customMeta[field] = normalized || null;
            }
            if (customMeta.image && !isValidUrl(customMeta.image)) {
              return Response.json(
                { error: "SEO image must be an HTTP or HTTPS URL" },
                { status: 400, headers: corsHeaders }
              );
            }
          }
          const hasCustomSeo = Object.values(customMeta).some(Boolean);

          // Safety check first: a flagged URL is refused before anything is
          // stored or fetched from it.
          const safety = await checkSafety(env, targetUrl);
          if (safety.status === "flagged") {
            return Response.json(
              {
                error: "This URL was flagged by Google Web Risk and can't be shortened.",
                threats: safety.threats
              },
              { status: 422, headers: corsHeaders }
            );
          }

          let shortcode = customShortcode;

          // If custom shortcode provided, validate it
          if (shortcode) {
            if (!/^[a-zA-Z0-9]{4,45}$/.test(shortcode)) {
              return Response.json(
                { error: "Shortcode must be 4-45 alphanumeric characters" },
                { status: 400, headers: corsHeaders }
              );
            }

            // Check if already taken
            const existing = await env.ACCOUNTS
              .prepare("SELECT shortcode FROM links WHERE domain = 'privo.fyi' AND shortcode = ?")
              .bind(shortcode)
              .first();

            if (existing) {
              return Response.json(
                { error: "Shortcode already taken" },
                { status: 409, headers: corsHeaders }
              );
            }
          } else {
            // Generate unique shortcode
            let attempts = 0;
            while (attempts < 10) {
              shortcode = generateShortCode();
              const existing = await env.ACCOUNTS
                .prepare("SELECT shortcode FROM links WHERE domain = 'privo.fyi' AND shortcode = ?")
                .bind(shortcode)
                .first();
              if (!existing) break;
              attempts++;
            }

            if (attempts >= 10) {
              return Response.json(
                { error: "Failed to generate unique shortcode" },
                { status: 500, headers: corsHeaders }
              );
            }
          }

          // Signed in (cookie sent with credentials: "include") -> the link belongs
          // to that account and counts toward its usage. Otherwise it's anonymous.
          const owner = await getSessionUser(request, env);

          // Insert into database. Database triggers keep usage and the audit log.
          try {
            await env.ACCOUNTS
              .prepare("INSERT INTO links (domain, shortcode, url, created_by, safety_status, safety_threats, safety_checked_at, title, description, image, site_name, seo_custom) VALUES ('privo.fyi', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
              .bind(
                shortcode,
                targetUrl,
                owner ? owner.id : null,
                safety.status,
                safety.threats ? JSON.stringify(safety.threats) : null,
                safety.checkedAt,
                customMeta.title,
                customMeta.description,
                customMeta.image,
                customMeta.siteName,
                hasCustomSeo ? 1 : 0
              )
              .run();
          } catch (insertError) {
            if (String(insertError && insertError.message).includes("LIMIT_D1")) {
              return Response.json(
                { error: "Your account has reached its 1 GB database limit." },
                { status: 403, headers: corsHeaders }
              );
            }
            throw insertError;
          }

          // Grab the destination's SEO/preview metadata (and a copy of its
          // preview image) so privo.fyi/{shortcode} can present itself as the
          // destination. Never blocks link creation.
          let preview = hasCustomSeo
            ? {
                title: customMeta.title,
                description: customMeta.description,
                image: customMeta.image,
                siteName: customMeta.siteName
              }
            : null;
          try {
            const fetchedMeta = await fetchPageMeta(targetUrl);
            const meta = {
              title: customMeta.title || fetchedMeta.title,
              description: customMeta.description || fetchedMeta.description,
              image: customMeta.image || fetchedMeta.image,
              siteName: customMeta.siteName || fetchedMeta.siteName
            };
            const imageState = await cacheImageState(env, shortcode, meta.image);

            await saveMeta(env, shortcode, meta, imageState);

            preview = {
              title: meta.title,
              description: meta.description,
              image: publicImage(shortcode, meta.image, imageState),
              siteName: meta.siteName
            };
          } catch (metaError) {
            console.error("Metadata fetch error:", metaError);
          }

          return Response.json(
            {
              shortcode,
              shortUrl: `https://privo.fyi/${shortcode}`,
              originalUrl: targetUrl,
              safety: safety.status,
              preview
            },
            { status: 201, headers: corsHeaders }
          );

        } catch (error) {
          console.error("Create link error:", error);
          return Response.json(
            { error: "Failed to create short link" },
            { status: 500, headers: corsHeaders }
          );
        }
      }

      // Check shortcode: GET /api/link/:shortcode
      if (pathname.startsWith("/api/link/") && request.method === "GET") {
        const shortcode = pathname.split("/")[3];

        if (!shortcode) {
          return Response.json(
            { error: "Shortcode required" },
            { status: 400, headers: corsHeaders }
          );
        }

        const result = await env.ACCOUNTS
          .prepare(
            "SELECT url, created_at, title, description, image, site_name, image_cached FROM links WHERE domain = 'privo.fyi' AND shortcode = ?"
          )
          .bind(shortcode)
          .first();

        if (!result) {
          return Response.json(
            { error: "Not found" },
            { status: 404, headers: corsHeaders }
          );
        }

        return Response.json(
          {
            shortcode,
            url: result.url,
            createdAt: result.created_at,
            shortUrl: `https://privo.fyi/${shortcode}`,
            preview: {
              title: result.title,
              description: result.description,
              image: publicImage(shortcode, result.image, result.image_cached),
              siteName: result.site_name
            }
          },
          { status: 200, headers: corsHeaders }
        );
      }

      // Who am I: GET /api/me (reads the session cookie set by api.privo.fyi).
      // The frontend on privo.fyi fetches this with credentials: "include".
      if (pathname === "/api/me" && request.method === "GET") {
        const user = await getSessionUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not signed in" },
            { status: 401, headers: meHeaders }
          );
        }

        return Response.json(
          { user: { email: user.id, name: user.name, picture: user.picture } },
          { status: 200, headers: meHeaders }
        );
      }

      // Dashboard data: GET /api/cloud/dashboard (signed-in users only).
      // One request returns everything the dashboard shows.
      if (pathname === "/api/cloud/dashboard" && request.method === "GET") {
        const user = await getSessionUser(request, env);

        if (!user) {
          return Response.json({ error: "Not signed in" }, { status: 401, headers: meHeaders });
        }

        try {
          return Response.json(await loadDashboard(env, user), { status: 200, headers: meHeaders });
        } catch (error) {
          console.error("Dashboard error:", error && error.message);
          return Response.json({ error: "Could not load the dashboard" }, { status: 500, headers: meHeaders });
        }
      }

      // Audit log, newest first, 50 at a time: GET /api/cloud/logs?category=&before=<id>
      if (pathname === "/api/cloud/logs" && request.method === "GET") {
        const user = await getSessionUser(request, env);

        if (!user) {
          return Response.json({ error: "Not signed in" }, { status: 401, headers: meHeaders });
        }

        try {
          return Response.json(await loadLogs(env, user, url.searchParams), { status: 200, headers: meHeaders });
        } catch (error) {
          console.error("Logs error:", error && error.message);
          return Response.json({ error: "Could not load the logs" }, { status: 500, headers: meHeaders });
        }
      }

      // Check a destination: GET /api/check?url=...
      // Called by the stop page so every redirect is checked, including links
      // from other sites.
      if (pathname === "/api/check" && request.method === "GET") {
        const target = url.searchParams.get("url");

        if (!target || target.length > 2048 || !isValidUrl(target)) {
          return Response.json(
            { error: "Invalid URL provided" },
            { status: 400, headers: { "Cache-Control": "no-store" } }
          );
        }

        const result = await checkSafetyCached(env, ctx, target);

        return Response.json(
          { status: result.status, threats: result.threats || [] },
          { status: 200, headers: { "Cache-Control": "no-store" } }
        );
      }

      // API 404
      return Response.json(
        { error: "API endpoint not found" },
        { status: 404, headers: corsHeaders }
      );
    }

    // ==========================================
    // 1b. ACCOUNT SIGN IN (/cloud/auth/*)
    // ==========================================
    if (pathname.startsWith("/cloud/auth/")) {
      return handleAuth(request, env, url);
    }

    const datedImageMatch = pathname.match(/^\/og\/\d{4}-\d{2}-\d{2}\/[a-f0-9-]{36}\.(?:png|jpg|gif|webp|avif)$/i);
    if (hostname === "privo.fyi" && datedImageMatch && (request.method === "GET" || request.method === "HEAD")) {
      return serveUploadedImage(env, pathname.slice(1), request.method === "HEAD");
    }

    // ==========================================
    // 2. STATIC ASSETS & PAGES PASS-THROUGH
    // Root and files go to Pages
    // ==========================================
    if (pathname === "/" || (/\.[a-zA-Z0-9]+$/.test(pathname) && !(hostname === "privo.fyi" && datedImageMatch))) {
      return fetch(request);
    }

    // ==========================================
    // 3. REDIRECT SUBDOMAIN (redirect.privo.fyi)
    // Optional: dedicated redirect domain
    // ==========================================
    if (hostname === "redirect.privo.fyi") {
      if (/^\/[a-zA-Z0-9]{4,}$/.test(pathname)) {
        const shortcode = pathname.slice(1);
        const result = await env.ACCOUNTS
          .prepare("SELECT url FROM links WHERE domain = 'privo.fyi' AND shortcode = ?")
          .bind(shortcode)
          .first();

        if (result) {
          return new Response(null, {
            status: 307,
            headers: {
              "Location": result.url,
              "Referrer-Policy": "no-referrer"
            }
          });
        }
      }

      // Fallback: redirect to main domain
      return new Response(null, {
        status: 301,
        headers: {
          "Location": `https://privo.fyi${pathname}${url.search}`,
          ...corsHeaders
        }
      });
    }

    // ==========================================
    // 4. MAIN DOMAIN (privo.fyi)
    // ==========================================
    if (hostname === "privo.fyi") {
      const isRead = request.method === "GET" || request.method === "HEAD";

      // Dated user-uploaded preview image: privo.fyi/og/YYYY-MM-DD/<filename>
      // Legacy user-uploaded preview image URL.
      const legacyUploadedImageMatch = pathname.match(/^\/i\/u\/([a-f0-9-]{36})$/i);
      if (hostname === "privo.fyi" && legacyUploadedImageMatch && isRead) {
        return serveUploadedImage(env, `user-preview/${legacyUploadedImageMatch[1]}`, request.method === "HEAD");
      }

      // Cached preview image: privo.fyi/i/44hf4
      const imageMatch = pathname.match(/^\/i\/([a-zA-Z0-9]{4,})$/);
      if (imageMatch && isRead) {
        return serveCachedImage(env, imageMatch[1], request.method === "HEAD");
      }

      // privo.fyi/44hf4 serves a tiny HTML page whose <head> mirrors the
      // destination (title, description, Open Graph, Twitter card, canonical).
      // Crawlers and link unfurlers read that; people are sent on to
      // privo.fyi/p/stop?url=<destination>&viaPrivo=true.
      if (isRead && /^\/[a-zA-Z0-9]{4,}$/.test(pathname)) {
        const shortcode = pathname.slice(1);
        const result = await env.ACCOUNTS
          .prepare(
            "SELECT url, title, description, image, site_name, seo_custom, meta_fetched_at, image_cached, safety_status, safety_threats FROM links WHERE domain = 'privo.fyi' AND shortcode = ?"
          )
          .bind(shortcode)
          .first();

        if (result) {
          // Links made before metadata / image caching existed: fill them in
          // once, in the background. This visit gets the fallback tags.
          // Flagged links are never fetched, redirected or previewed.
          if (result.safety_status === "flagged") {
            return renderBlockedPage(shortcode, result, request.method === "HEAD");
          }

          const needsMeta = !result.meta_fetched_at;
          const needsImage = result.image && !result.image_cached;

          if (needsMeta || needsImage) {
            ctx.waitUntil(backfill(env, shortcode, result));
          }

          const html = renderLinkPage(shortcode, result);

          return new Response(request.method === "HEAD" ? null : html, {
            status: 200,
            headers: {
              "Content-Type": "text/html; charset=UTF-8",
              "Referrer-Policy": "no-referrer",
              "Cache-Control": "public, max-age=300"
            }
          });
        }

        // Shortcode not found - let Pages handle 404
        return fetch(request);
      }

      // Everything else on main domain goes to Pages
      // (this includes /p/stop, which Pages serves from p/stop.html)
      return fetch(request);
    }

    // ==========================================
    // 5. FALLBACK
    // ==========================================
    return Response.json(
      { error: "Not found" },
      { status: 404, headers: corsHeaders }
    );
  }
};

// ==========================================
// Safety check (Google Web Risk)
// ==========================================
//
// Uses hashes:search, so only 4-byte hash prefixes of the destination's
// canonical expressions leave the Worker. Google returns full hashes that
// share those prefixes and we compare them locally. The full URL is never sent.

const WEB_RISK_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"];
const WEB_RISK_TIMEOUT_MS = 3000;

// Returns { status, threats, checkedAt }.
// status: "clean" | "flagged" | "unchecked" (no key, bad URL, or lookup failed).
// Never throws, and a failed lookup never blocks link creation.
async function checkSafety(env, targetUrl) {
  const unchecked = { status: "unchecked", threats: null, checkedAt: null };
  if (!env.WEB_RISK_API_KEY) return unchecked;

  let digests;
  try {
    const expressions = canonicalExpressions(targetUrl);
    if (!expressions.length) return unchecked;
    digests = await Promise.all(expressions.map((x) => sha256(x)));
  } catch (_) {
    return unchecked;
  }

  const fullHashes = new Set(digests.map((d) => normB64(toBase64(d))));
  const prefixes = [...new Set(digests.map((d) => toBase64(d.subarray(0, 4))))];

  const params = new URLSearchParams();
  for (const p of prefixes) params.append("hashPrefix", p);
  for (const t of WEB_RISK_THREAT_TYPES) params.append("threatTypes", t);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WEB_RISK_TIMEOUT_MS);

  try {
    const res = await fetch(`https://webrisk.googleapis.com/v1/hashes:search?${params}`, {
      method: "GET",
      headers: {
        "x-goog-api-key": env.WEB_RISK_API_KEY,
        "Accept": "application/json"
      },
      signal: controller.signal
    });

    if (!res.ok) {
      // Log the response body too: Google's error JSON usually names the
      // actual problem (bad key, disabled API, malformed hash prefix).
      const errorBody = await res.text();

      console.error("Web Risk API error:", {
        status: res.status,
        body: errorBody
      });

      return unchecked;
    }

    const data = await res.json();
    const threatList = data.threats || [];

    // If Google returns matches without the hash field we can't confirm them.
    // Treat that as unchecked rather than silently clean.
    if (threatList.length && !threatList.some((t) => t.hash)) {
      console.error("Web Risk response had no hash fields; response shape may have changed");
      return unchecked;
    }

    const hits = threatList.filter((t) => fullHashes.has(normB64(t.hash || "")));
    const checkedAt = new Date().toISOString();

    if (!hits.length) return { status: "clean", threats: [], checkedAt };

    const threats = [...new Set(hits.flatMap((t) => t.threatTypes || []))];
    return { status: "flagged", threats, checkedAt };
  } catch (error) {
    console.error("Web Risk lookup error:", error);
    return unchecked;
  } finally {
    clearTimeout(timer);
  }
}

// Safe Browsing canonical expressions: host suffixes x path prefixes.
// Throws on input it can't parse, which the caller treats as unchecked.
function canonicalExpressions(targetUrl) {
  let raw = String(targetUrl).replace(/[\t\r\n]/g, "");

  const hashAt = raw.indexOf("#");
  if (hashAt !== -1) raw = raw.slice(0, hashAt);

  // Unescape until stable, so %25 and %2525 resolve the same way.
  for (let i = 0; i < 10; i++) {
    let decoded;
    try {
      decoded = decodeURIComponent(raw);
    } catch (_) {
      break;
    }
    if (decoded === raw) break;
    raw = decoded;
  }

  const u = new URL(raw);
  if (u.protocol !== "http:" && u.protocol !== "https:") return [];

  const host = u.hostname.toLowerCase().replace(/\.\./g, ".").replace(/^\.|\.$/g, "");
  const path = u.pathname.replace(/\/{2,}/g, "/") || "/";
  const search = u.search;

  const escapeChars = (s) =>
    s.replace(/[\x00-\x20\x7f#%]|[^\x00-\x7f]/gu, (c) => encodeURIComponent(c));

  // Hosts: the exact host, then up to four suffixes of its last five labels.
  const isIp = /^[\d.]+$/.test(host) || host.includes(":");
  const hosts = [host];
  if (!isIp) {
    const labels = host.split(".");
    for (let i = Math.max(labels.length - 5, 0); i <= labels.length - 2; i++) {
      const suffix = labels.slice(i).join(".");
      if (!hosts.includes(suffix)) hosts.push(suffix);
    }
  }

  // Paths: exact path with query, path without query, then directory prefixes.
  const paths = [path + search];
  if (search) paths.push(path);
  paths.push("/");
  const segments = path.split("/").filter(Boolean);
  for (let i = 0; i < segments.length; i++) {
    const isLast = i === segments.length - 1;
    if (isLast && !path.endsWith("/")) break;
    paths.push("/" + segments.slice(0, i + 1).join("/") + "/");
  }
  const uniquePaths = [...new Set(paths)].slice(0, 6);

  const expressions = [];
  for (const h of hosts) {
    for (const p of uniquePaths) {
      expressions.push(escapeChars(h) + escapeChars(p));
    }
  }
  return expressions;
}

async function sha256(input) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input)));
}

function toBase64(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

// Normalise base64 / base64url with padding so hashes compare reliably.
function normB64(value) {
  return String(value).replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
}

const THREAT_LABELS = {
  MALWARE: "malware",
  SOCIAL_ENGINEERING: "phishing or other social engineering",
  UNWANTED_SOFTWARE: "unwanted software"
};

// Shown instead of a redirect. Deliberately does not link to the destination.
function renderBlockedPage(shortcode, row, headOnly) {
  let threats = [];
  try {
    threats = JSON.parse(row.safety_threats || "[]");
  } catch (_) {
    threats = [];
  }

  const reasons = [...new Set(threats.map((t) => THREAT_LABELS[t] || "a security risk"))];
  const reasonText = reasons.length ? reasons.join(" and ") : "a security risk";

  let host = "this site";
  try {
    host = new URL(row.url).hostname.replace(/^www\./, "");
  } catch (_) {
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
      "Cache-Control": "public, max-age=300"
    }
  });
}

// Cached wrapper used by /api/check. Verdicts are kept for an hour under a
// hashed key, so the address itself is never stored.
async function checkSafetyCached(env, ctx, targetUrl) {
  const digest = await sha256(targetUrl);
  const hex = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
  const key = new Request(`https://privo.fyi/__safety/${hex}`);
  const cache = caches.default;

  const hit = await cache.match(key);
  if (hit) {
    try {
      return await hit.json();
    } catch (_) {
      // fall through and re-check
    }
  }

  const result = await checkSafety(env, targetUrl);

  // Failed lookups aren't cached, so the next request tries again.
  if (result.status !== "unchecked") {
    ctx.waitUntil(
      cache.put(
        key,
        new Response(JSON.stringify(result), {
          headers: { "Content-Type": "application/json", "Cache-Control": "max-age=3600" }
        })
      )
    );
  }

  return result;
}

// ==========================================
// Scheduled re-check (cron, every 12 hours)
// ==========================================

// Re-checks the links that have gone longest without a verdict, oldest first,
// so every link is covered over time. A failed lookup keeps the previous
// verdict. The default batch stays under the Workers free-plan limit of 50
// subrequests per run; raise RECHECK_BATCH on a paid plan.
async function recheckLinks(env) {
  if (!env.WEB_RISK_API_KEY) {
    console.log("Re-check skipped: WEB_RISK_API_KEY is not set");
    return;
  }

  const limit = Math.max(1, Math.min(Number(env.RECHECK_BATCH) || 40, 900));

  const { results } = await env.ACCOUNTS
    .prepare(
      "SELECT id, shortcode, url, safety_status FROM links ORDER BY safety_checked_at IS NOT NULL, safety_checked_at ASC LIMIT ?"
    )
    .bind(limit)
    .all();

  let checked = 0;
  let newlyFlagged = 0;
  let cleared = 0;

  // Small groups keep us well inside concurrent-connection limits.
  for (let i = 0; i < results.length; i += 5) {
    await Promise.all(
      results.slice(i, i + 5).map(async (row) => {
        const result = await checkSafety(env, row.url);
        if (result.status === "unchecked") return;

        checked++;

        await env.ACCOUNTS
          .prepare(
            "UPDATE links SET safety_status = ?, safety_threats = ?, safety_checked_at = ? WHERE id = ?"
          )
          .bind(
            result.status,
            result.threats && result.threats.length ? JSON.stringify(result.threats) : null,
            result.checkedAt,
            row.id
          )
          .run();

        if (result.status === "flagged" && row.safety_status !== "flagged") {
          newlyFlagged++;
          console.warn(`Link flagged: ${row.shortcode} (${(result.threats || []).join(", ")})`);

          // Stop serving the destination's preview image from our domain.
          if (env.IMAGES) {
            await env.IMAGES.delete(imageKey(row.shortcode)).catch(() => {});
            await env.ACCOUNTS
              .prepare("UPDATE links SET image_cached = 2 WHERE id = ?")
              .bind(row.id)
              .run();
          }
        }

        if (result.status === "clean" && row.safety_status === "flagged") cleared++;
      })
    );
  }

  console.log(
    `Re-check done: ${checked}/${results.length} checked, ${newlyFlagged} newly flagged, ${cleared} cleared`
  );
}

// ==========================================
// Account sign in: Google OAuth 2.0 (authorization code + PKCE)
// ==========================================
//
// Storage (env.ACCOUNTS, a separate D1 database):
//   users       id = verified email (lowercase), name, picture
//   identities  one row per sign-in method: (provider, provider_user_id) -> user
//   sessions    SHA-256 of the session token -> user, with an expiry
//
// Google's tokens are used once to read the profile and are never stored.
// Requires: GOOGLE_CLIENT_ID (var), GOOGLE_CLIENT_SECRET (secret), ACCOUNTS (D1).
//
// Redirect URIs: this Worker runs on api.privo.fyi, so the OAuth callback is
// https://api.privo.fyi/cloud/auth/google/callback. Successful sign-in (and
// errors, and logout) send the user back to the Pages frontend on privo.fyi.

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";

// "openid" comes with any Google sign-in and adds nothing to the consent screen.
const GOOGLE_SCOPES = [
  "openid",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile"
].join(" ");

const SESSION_COOKIE = "privo_session";
const OAUTH_COOKIE = "privo_oauth"; // state + PKCE verifier while the user is at Google
const SESSION_DAYS = 30;
const OAUTH_TTL_SECONDS = 600;

async function handleAuth(request, env, url) {
  const path = url.pathname;
  const isGet = request.method === "GET";

  if (path === "/cloud/auth/google" && isGet) return googleStart(env, url);
  if (path === "/cloud/auth/google/callback" && isGet) return googleCallback(request, env, url);
  if (path === "/cloud/auth/logout" && request.method === "POST") return logout(request, env, url);

  // Sign-in methods that aren't built yet send people back with a friendly message.
  if (isGet && /^\/cloud\/auth\/(create|coffee-and-code|github|bluesky)$/.test(path)) {
    return authRedirect(url, "unavailable");
  }

  return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
}

// Secrets and vars can end up with stray leading/trailing whitespace (copy
// paste in the dashboard, .dev.vars, etc.), which breaks Google's auth and
// token endpoints. Trim once, centrally.
function googleCredentials(env) {
  return {
    clientId: String(env.GOOGLE_CLIENT_ID || "").trim(),
    clientSecret: String(env.GOOGLE_CLIENT_SECRET || "").trim()
  };
}

function authConfigured(env) {
  const { clientId, clientSecret } = googleCredentials(env);
  return Boolean(clientId && clientSecret && env.ACCOUNTS);
}

function googleRedirectUri(url) {
  return `${url.origin}/cloud/auth/google/callback`;
}

async function googleStart(env, url) {
  if (!authConfigured(env)) return authRedirect(url, "unavailable");

  const { clientId } = googleCredentials(env);
  const state = randomToken(24);
  const verifier = randomToken(48);
  const challenge = base64url(await sha256(verifier));

  const authUrl = new URL(GOOGLE_AUTH_URL);
  authUrl.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: googleRedirectUri(url),
    response_type: "code",
    scope: GOOGLE_SCOPES,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account"
  }).toString();

  return redirectResponse(authUrl.toString(), [
    buildCookie(OAUTH_COOKIE, `${state}.${verifier}`, {
      maxAge: OAUTH_TTL_SECONDS,
      path: "/cloud/auth",
      secure: url.protocol === "https:"
    })
  ]);
}

async function googleCallback(request, env, url) {
  const secure = url.protocol === "https:";
  const clearOauth = buildCookie(OAUTH_COOKIE, "", { maxAge: 0, path: "/cloud/auth", secure });

  if (!authConfigured(env)) return authRedirect(url, "unavailable", [clearOauth]);

  const params = url.searchParams;

  if (params.get("error")) {
    return authRedirect(url, params.get("error") === "access_denied" ? "denied" : "failed", [clearOauth]);
  }

  const { clientId, clientSecret } = googleCredentials(env);

  const code = params.get("code");
  const state = params.get("state");
  const saved = (getCookie(request, OAUTH_COOKIE) || "").split(".");

  // The state must match the one we set in this browser, or the request isn't ours.
  if (!code || !state || saved.length !== 2 || !safeEqual(saved[0], state)) {
    return authRedirect(url, "expired", [clearOauth]);
  }

  try {
    const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: googleRedirectUri(url),
        grant_type: "authorization_code",
        code_verifier: saved[1]
      })
    });

    if (!tokenRes.ok) {
      console.error("Google token exchange failed:", tokenRes.status);
      return authRedirect(url, "failed", [clearOauth]);
    }

    const tokens = await tokenRes.json();
    if (!tokens.access_token) return authRedirect(url, "failed", [clearOauth]);

    const infoRes = await fetch(GOOGLE_USERINFO_URL, {
      headers: { "Authorization": `Bearer ${tokens.access_token}`, "Accept": "application/json" }
    });

    if (!infoRes.ok) {
      console.error("Google userinfo failed:", infoRes.status);
      return authRedirect(url, "failed", [clearOauth]);
    }

    const info = await infoRes.json();
    if (!info.sub || !info.email) return authRedirect(url, "failed", [clearOauth]);

    // Only a verified address may be used as an account ID.
    if (info.email_verified !== true && info.email_verified !== "true") {
      return authRedirect(url, "unverified", [clearOauth]);
    }

    const user = await upsertGoogleUser(env, info);
    const session = await createSession(env, user.id);
    await logSignIn(env, request, user.id, "google");

    // Success: back to the Pages frontend, with the session cookie set on
    // api.privo.fyi so /api/me can read it.
    return redirectResponse("https://privo.fyi/cloud/app/dashboard", [
      clearOauth,
      buildCookie(SESSION_COOKIE, session.token, {
        maxAge: session.maxAge,
        path: "/",
        secure
      })
    ]);
  } catch (error) {
    console.error("Google sign in error:", error && error.message);
    return authRedirect(url, "failed", [clearOauth]);
  }
}

// Find or create the user for a Google sign in.
//   1. Known Google account (matched on Google's stable ID): refresh name/photo.
//   2. Known email, new Google account: link it as another sign-in method.
//   3. Otherwise: create the user with the email as ID.
async function upsertGoogleUser(env, info) {
  const db = env.ACCOUNTS;
  const email = String(info.email).trim().toLowerCase();
  const name = clean(info.name || info.given_name || "", 100);
  const photo = absoluteHttpUrl(info.picture, "https://lh3.googleusercontent.com");
  const picture = photo && photo.startsWith("https://") ? photo : null;
  const now = new Date().toISOString();

  const identity = await db
    .prepare("SELECT user_id FROM identities WHERE provider = 'google' AND provider_user_id = ?")
    .bind(info.sub)
    .first();

  if (identity) {
    await db
      .prepare("UPDATE users SET name = ?, picture = ?, last_login_at = ? WHERE id = ?")
      .bind(name, picture, now, identity.user_id)
      .run();
    return { id: identity.user_id, created: false };
  }

  const existing = await db.prepare("SELECT id FROM users WHERE id = ?").bind(email).first();

  if (existing) {
    await db.batch([
      db
        .prepare("INSERT INTO identities (provider, provider_user_id, user_id, created_at) VALUES ('google', ?, ?, ?)")
        .bind(info.sub, email, now),
      db
        .prepare("UPDATE users SET name = COALESCE(name, ?), picture = COALESCE(picture, ?), last_login_at = ? WHERE id = ?")
        .bind(name, picture, now, email)
    ]);
    return { id: email, created: false };
  }

  await db.batch([
    db
      .prepare("INSERT INTO users (id, name, picture, created_at, last_login_at) VALUES (?, ?, ?, ?, ?)")
      .bind(email, name, picture, now, now),
    db
      .prepare("INSERT INTO identities (provider, provider_user_id, user_id, created_at) VALUES ('google', ?, ?, ?)")
      .bind(info.sub, email, now)
  ]);

  return { id: email, created: true };
}

async function createSession(env, userId) {
  const token = randomToken(32);
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_DAYS * 86400 * 1000);

  await env.ACCOUNTS.batch([
    // Tidy this person's expired sessions while we're here.
    env.ACCOUNTS
      .prepare("DELETE FROM sessions WHERE user_id = ? AND expires_at <= ?")
      .bind(userId, now.toISOString()),
    env.ACCOUNTS
      .prepare("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
      .bind(await hashToken(token), userId, now.toISOString(), expires.toISOString())
  ]);

  return { token, maxAge: SESSION_DAYS * 86400 };
}

// Returns { id, name, picture } for a valid session cookie, otherwise null.
async function getSessionUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token || !env.ACCOUNTS) return null;

  return env.ACCOUNTS
    .prepare(
      "SELECT users.id AS id, users.name AS name, users.picture AS picture FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?"
    )
    .bind(await hashToken(token), new Date().toISOString())
    .first();
}

async function logout(request, env, url) {
  // Only our own pages may sign a user out: this host, or the privo.fyi
  // frontend (which posts here from the dashboard).
  const origin = request.headers.get("Origin");
  if (origin && origin !== url.origin && origin !== "https://privo.fyi") {
    return new Response("Forbidden", { status: 403, headers: { "Cache-Control": "no-store" } });
  }

  const token = getCookie(request, SESSION_COOKIE);
  if (token && env.ACCOUNTS) {
    await env.ACCOUNTS
      .prepare("DELETE FROM sessions WHERE token_hash = ?")
      .bind(await hashToken(token))
      .run();
  }

  return redirectResponse(
    "https://privo.fyi/cloud/signin",
    [buildCookie(SESSION_COOKIE, "", { maxAge: 0, path: "/", secure: url.protocol === "https:" })],
    303
  );
}

// Any sign-in problem sends the user back to the frontend's sign-in page
// with a short error code it can present a friendly message for.
function authRedirect(url, code, cookies = []) {
  return redirectResponse(
    `https://privo.fyi/cloud/signin?error=${encodeURIComponent(code)}`,
    cookies
  );
}

function redirectResponse(location, cookies = [], status = 302) {
  const headers = new Headers({
    "Location": location,
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer"
  });
  for (const cookie of cookies) headers.append("Set-Cookie", cookie);
  return new Response(null, { status, headers });
}

// The cookie is set by (and sent to) api.privo.fyi, so the session token is
// never exposed to JavaScript on privo.fyi.
function buildCookie(name, value, { maxAge, path = "/", secure = true }) {
  return `${name}=${value}; Path=${path}; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie");
  if (!header) return null;

  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }

  return null;
}

function randomToken(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

function base64url(bytes) {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hashToken(token) {
  return [...(await sha256(token))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ==========================================
// Sign-in log + dashboard
// ==========================================

// Writes one audit row per sign in: method, country, OS and browser only.
// No IP address is read or stored. Never blocks the sign in.
async function logSignIn(env, request, userId, method) {
  try {
    const { os, browser } = parseUserAgent(request.headers.get("User-Agent") || "");
    const country = (request.cf && request.cf.country) || null;

    await env.ACCOUNTS
      .prepare(
        "INSERT INTO audit_logs (user_id, category, action, signin_method, country, os, browser) VALUES (?, 'signin', 'login', ?, ?, ?, ?)"
      )
      .bind(userId, method, country, os, browser)
      .run();
  } catch (error) {
    console.error("Sign-in log failed:", error && error.message);
  }
}

function parseUserAgent(ua) {
  let os = "Unknown";
  if (/Windows/i.test(ua)) os = "Windows";
  else if (/iPhone|iPad|iPod/i.test(ua)) os = "iOS";
  else if (/Android/i.test(ua)) os = "Android";
  else if (/CrOS/i.test(ua)) os = "ChromeOS";
  else if (/Mac OS X|Macintosh/i.test(ua)) os = "macOS";
  else if (/Linux/i.test(ua)) os = "Linux";

  // Order matters: Edge and Opera also say "Chrome", Chrome also says "Safari".
  let browser = "Unknown";
  if (/Edg\//i.test(ua)) browser = "Edge";
  else if (/OPR\/|Opera/i.test(ua)) browser = "Opera";
  else if (/Firefox|FxiOS/i.test(ua)) browser = "Firefox";
  else if (/Chrome|CriOS/i.test(ua)) browser = "Chrome";
  else if (/Safari/i.test(ua)) browser = "Safari";

  return { os, browser };
}

// Deletes are the only thing marked Medium; everything else is routine.
function riskLevel(action) {
  return action === "delete" ? "Medium" : "Low";
}

const LOG_PAGE_SIZE = 50;
const LOG_CATEGORIES = ["signin", "link", "r2", "d1"];

// One page of the account's audit log. `next` is the id to pass as ?before= for the following page.
async function loadLogs(env, user, params) {
  const category = params.get("category");
  const before = Number.parseInt(params.get("before"), 10);

  let sql =
    "SELECT id, category, action, created_at, signin_method, country, os, browser, short_link, direct_url, r2_key, file_url, bytes, db_table FROM audit_logs WHERE user_id = ?";
  const binds = [user.id];

  if (LOG_CATEGORIES.includes(category)) {
    sql += " AND category = ?";
    binds.push(category);
  }
  if (Number.isFinite(before)) {
    sql += " AND id < ?";
    binds.push(before);
  }

  sql += " ORDER BY id DESC LIMIT ?";
  binds.push(LOG_PAGE_SIZE + 1);

  const { results } = await env.ACCOUNTS.prepare(sql).bind(...binds).all();
  const more = results.length > LOG_PAGE_SIZE;
  const page = more ? results.slice(0, LOG_PAGE_SIZE) : results;

  return {
    logs: page.map((r) => ({
      id: r.id,
      category: r.category,
      action: r.action,
      risk: riskLevel(r.action),
      at: r.created_at,
      method: r.signin_method,
      country: r.country,
      os: r.os,
      browser: r.browser,
      shortLink: r.short_link,
      directUrl: r.direct_url,
      r2Key: r.r2_key,
      fileUrl: r.file_url,
      bytes: r.bytes,
      table: r.db_table
    })),
    next: more ? page[page.length - 1].id : null
  };
}

// Everything the dashboard shows, in one round trip.
async function loadDashboard(env, user) {
  const db = env.ACCOUNTS;

  const [usage, links, logs, domains] = await db.batch([
    db.prepare("SELECT * FROM usage WHERE user_id = ?").bind(user.id),
    db
      .prepare(
        `SELECT l.domain, l.shortcode, l.url, l.updated_at, u.name AS by_name, COALESCE(l.updated_by, l.created_by) AS by_id
         FROM links l LEFT JOIN users u ON u.id = COALESCE(l.updated_by, l.created_by)
         WHERE l.created_by = ? ORDER BY l.updated_at DESC, l.id DESC LIMIT 200`
      )
      .bind(user.id),
    db
      .prepare(
        `SELECT category, action, created_at, signin_method, short_link, r2_key, db_table
         FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT 100`
      )
      .bind(user.id),
    db
      .prepare(
        `SELECT d.hostname, d.verified, d.created_at, u.name AS by_name, d.owner_id AS by_id
         FROM domains d LEFT JOIN users u ON u.id = d.owner_id
         WHERE d.owner_id = ? ORDER BY d.created_at DESC LIMIT 50`
      )
      .bind(user.id)
  ]);

  const u = usage.results[0] || {};

  return {
    user: { email: user.id, name: user.name, picture: user.picture },
    usage: {
      links: u.links || 0,
      domains: u.domains || 0,
      maxDomains: u.max_domains || 10,
      teams: u.teams || 0,
      maxTeams: u.max_teams || 10,
      r2Bytes: u.r2_bytes || 0,
      maxR2Bytes: u.max_r2_bytes || 3221225472,
      d1Bytes: u.d1_bytes || 0,
      maxD1Bytes: u.max_d1_bytes || 1073741824
    },
    links: links.results.map((r) => ({
      shortLink: `${r.domain}/${r.shortcode}`,
      url: r.url,
      modifiedAt: r.updated_at,
      modifiedBy: r.by_name || r.by_id
    })),
    logs: logs.results.map((r) => ({
      category: r.category,
      action: r.action,
      risk: riskLevel(r.action),
      at: r.created_at,
      method: r.signin_method,
      shortLink: r.short_link,
      r2Key: r.r2_key,
      table: r.db_table
    })),
    domains: domains.results.map((r) => ({
      hostname: r.hostname,
      verified: Boolean(r.verified),
      modifiedAt: r.created_at,
      modifiedBy: r.by_name || r.by_id
    }))
  };
}

// ==========================================
// Destination metadata
// ==========================================

const META_TIMEOUT_MS = 3500;
const META_MAX_BYTES = 262144; // 256 KB is plenty to cover <head>

// Fetch a destination page and pull out its title, description, image and
// site name (Open Graph first, then Twitter, then plain HTML). Returns
// nulls for anything it can't find; never throws.
async function fetchPageMeta(targetUrl) {
  const empty = { title: null, description: null, image: null, siteName: null };

  let target;
  try {
    target = new URL(targetUrl);
  } catch (_) {
    return empty;
  }

  // Don't scrape ourselves.
  if (target.hostname === "privo.fyi" || target.hostname.endsWith(".privo.fyi")) {
    return empty;
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
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
        "Accept-Language": "en"
      }
    });

    const contentType = res.headers.get("content-type") || "";
    if (!res.ok || !/text\/html|application\/xhtml/i.test(contentType) || !res.body) {
      return empty;
    }

    const html = await readHead(res, contentType);

    const tags = {};
    let titleText = "";
    let titleDone = false;

    await new HTMLRewriter()
      .on("title", {
        text(chunk) {
          if (titleDone) return;
          titleText += chunk.text;
          if (chunk.lastInTextNode) titleDone = true;
        }
      })
      .on("meta", {
        element(el) {
          const key = (el.getAttribute("property") || el.getAttribute("name") || "").toLowerCase();
          const content = el.getAttribute("content");
          if (key && content && !(key in tags)) tags[key] = content;
        }
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
      siteName: clean(tags["og:site_name"], 100)
    };
  } catch (_) {
    return empty;
  } finally {
    clearTimeout(timer);
  }
}

// Read only as much of the response as needed to cover <head>.
async function readHead(res, contentType) {
  const charset = (contentType.match(/charset=([^;\s]+)/i) || [])[1];
  let decoder;
  try {
    decoder = new TextDecoder(charset || "utf-8");
  } catch (_) {
    decoder = new TextDecoder("utf-8");
  }

  const reader = res.body.getReader();
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

// image_cached: 0 = not attempted, 1 = copy stored in R2, 2 = attempted and failed.
async function saveMeta(env, shortcode, meta, imageState) {
  await env.ACCOUNTS
    .prepare(
      "UPDATE links SET title = CASE WHEN seo_custom = 1 THEN COALESCE(title, ?) ELSE ? END, description = CASE WHEN seo_custom = 1 THEN COALESCE(description, ?) ELSE ? END, image = CASE WHEN seo_custom = 1 OR image LIKE 'https://privo.fyi/i/u/%' THEN COALESCE(image, ?) ELSE ? END, site_name = CASE WHEN seo_custom = 1 THEN COALESCE(site_name, ?) ELSE ? END, image_cached = ?, meta_fetched_at = datetime('now') WHERE domain = 'privo.fyi' AND shortcode = ?"
    )
    .bind(
      meta.title, meta.title,
      meta.description, meta.description,
      meta.image, meta.image,
      meta.siteName, meta.siteName,
      imageState, shortcode
    )
    .run();
}

// Fill in whatever a link is missing. Saved even when the result is empty or
// failed so a dead destination isn't re-fetched on every visit.
async function backfill(env, shortcode, row) {
  try {
    if (!row.meta_fetched_at) {
      const fetchedMeta = await fetchPageMeta(row.url);
      const meta = row.seo_custom || uploadedImageKeyFromUrl(row.image)
        ? {
            title: row.title || fetchedMeta.title,
            description: row.description || fetchedMeta.description,
            image: row.image || fetchedMeta.image,
            siteName: row.site_name || fetchedMeta.siteName
          }
        : fetchedMeta;
      const imageState = await cacheImageState(env, shortcode, meta.image);
      await saveMeta(env, shortcode, meta, imageState);
      return;
    }

    // Metadata exists but the image was never copied.
    const imageState = await cacheImageState(env, shortcode, row.image);
    await env.ACCOUNTS
      .prepare("UPDATE links SET image_cached = ? WHERE domain = 'privo.fyi' AND shortcode = ?")
      .bind(imageState, shortcode)
      .run();
  } catch (error) {
    console.error("Backfill error:", error);
  }
}

// ==========================================
// Preview image cache (R2)
// ==========================================

const IMAGE_TIMEOUT_MS = 3000;
const IMAGE_MAX_BYTES = 5 * 1024 * 1024; // 5 MB

function imageKey(shortcode) {
  return `og/${shortcode}`;
}

function imageExtension(contentType) {
  return ({
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/avif": ".avif"
  })[contentType];
}

function uploadedImageKeyFromUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" ||
      url.hostname !== "privo.fyi" ||
      url.port ||
      url.username ||
      url.password ||
      url.search ||
      url.hash) return null;

    const dated = url.pathname.match(/^\/og\/(\d{4}-\d{2}-\d{2})\/([a-f0-9-]{36}\.(?:png|jpg|gif|webp|avif))$/i);
    if (dated) return `og/${dated[1]}/${dated[2].toLowerCase()}`;

    const legacy = url.pathname.match(/^\/i\/u\/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/i);
    return legacy
      ? `user-preview/${legacy[1].toLowerCase()}`
      : null;
  } catch (_) {
    return null;
  }
}

// Our own URL when a copy exists, otherwise the destination's original.
function publicImage(shortcode, source, imageState) {
  if (!source) return null;
  if (uploadedImageKeyFromUrl(source)) return source;
  return Number(imageState) === 1 ? `https://privo.fyi/i/${shortcode}` : source;
}

// Returns the image_cached value to store: 0 (no image), 1 (cached), 2 (failed).
async function cacheImageState(env, shortcode, imageUrl) {
  if (!imageUrl) return 0;
  const uploadedKey = uploadedImageKeyFromUrl(imageUrl);
  if (uploadedKey) {
    if (!env.IMAGES) return 2;
    return (await env.IMAGES.head(uploadedKey)) ? 1 : 2;
  }
  return (await cacheImage(env, shortcode, imageUrl)) ? 1 : 2;
}

// Copy a destination's preview image into R2. Returns true on success.
// Only real raster images are kept (type is sniffed from the bytes, not
// trusted from headers) and SVG is refused, since it can carry script and
// would be served from privo.fyi.
async function cacheImage(env, shortcode, imageUrl) {
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
        "Accept": "image/avif,image/webp,image/png,image/jpeg,image/gif,*/*;q=0.1"
      }
    });

    if (!res.ok || !res.body) return false;

    const declared = Number(res.headers.get("content-length"));
    if (declared && declared > IMAGE_MAX_BYTES) return false;

    const bytes = await readLimitedBytes(res, IMAGE_MAX_BYTES);
    if (!bytes) return false;

    const contentType = sniffImageType(bytes);
    if (!contentType) return false;

    await env.IMAGES.put(imageKey(shortcode), bytes, {
      httpMetadata: { contentType },
      customMetadata: { source: imageUrl.slice(0, 1000) }
    });

    return true;
  } catch (_) {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

// Read a body fully, or return null if it exceeds maxBytes.
async function readLimitedBytes(res, maxBytes) {
  const reader = res.body.getReader();
  const chunks = [];
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
  } catch (_) {
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

async function readLimitedRequestBody(request, maxBytes) {
  if (!request.body) return null;

  const reader = request.body.getReader();
  const chunks = [];
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

// Identify PNG / JPEG / GIF / WebP / AVIF from magic bytes.
function sniffImageType(b) {
  if (!b || b.length < 12) return null;

  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return "image/gif";

  const tag = (start) => String.fromCharCode(b[start], b[start + 1], b[start + 2], b[start + 3]);
  if (tag(0) === "RIFF" && tag(8) === "WEBP") return "image/webp";
  if (tag(4) === "ftyp" && (tag(8) === "avif" || tag(8) === "avis")) return "image/avif";

  return null;
}

async function serveCachedImage(env, shortcode, headOnly) {
  const notFound = () => new Response("Not found", { status: 404 });

  if (!env.IMAGES) return notFound();

  const object = await env.IMAGES.get(imageKey(shortcode));
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

async function serveUploadedImage(env, key, headOnly) {
  const notFound = () => new Response("Not found", {
    status: 404,
    headers: { "X-Content-Type-Options": "nosniff" }
  });

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

// ==========================================
// Shortlink page
// ==========================================

function renderLinkPage(shortcode, row) {
  const destination = new URL(row.url);
  const host = destination.hostname.replace(/^www\./, "");
  const shortUrl = `https://privo.fyi/${shortcode}`;
  const stopUrl = buildStopUrl(row.url);

  const title = row.title || host;
  const description = row.description || `Shortened link to ${host}`;
  const siteName = row.site_name || host;
  const image = publicImage(shortcode, row.image, row.image_cached);

  const e = escapeHtml;

  // Safe to embed in a <script>: stopUrl is fully percent-encoded, and "<" is escaped anyway.
  const stopJs = JSON.stringify(stopUrl).replace(/</g, "\u003c");

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

// ==========================================
// Helpers
// ==========================================

// Build the interstitial URL for a stored destination.
// URLSearchParams handles all encoding, so destinations containing
// ?, &, # or unicode survive the round trip intact.
function buildStopUrl(destination) {
  const stop = new URL("https://privo.fyi/p/stop");
  stop.searchParams.set("url", destination);
  stop.searchParams.set("viaPrivo", "true");
  return stop.toString();
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const NAMED_ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

// HTMLRewriter hands back raw text, so <title> entities need decoding.
function decodeEntities(value) {
  return value.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, entity) => {
    if (entity[0] === "#") {
      const code = entity[1].toLowerCase() === "x"
        ? parseInt(entity.slice(2), 16)
        : parseInt(entity.slice(1), 10);
      try {
        return String.fromCodePoint(code);
      } catch (_) {
        return match;
      }
    }
    const key = entity.toLowerCase();
    return Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, key)
      ? NAMED_ENTITIES[key]
      : match;
  });
}

// Decode, strip control characters, collapse whitespace, cap the length.
function clean(value, max) {
  if (!value) return null;
  const text = decodeEntities(String(value))
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!text) return null;
  return text.length > max ? text.slice(0, max - 1).trimEnd() + "…" : text;
}

// Resolve a possibly-relative URL and keep it only if it's http(s).
function absoluteHttpUrl(value, base) {
  if (!value) return null;
  try {
    const resolved = new URL(value.trim(), base);
    if (resolved.protocol !== "http:" && resolved.protocol !== "https:") return null;
    return resolved.href.length <= 2000 ? resolved.href : null;
  } catch (_) {
    return null;
  }
}

// Helper: Validate URL
function isValidUrl(value) {
  try {
    const parsedUrl = new URL(value);
    return parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:";
  } catch (_) {
    return false;
  }
}

// Helper: Generate random shortcode
function generateShortCode() {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "";
  const array = new Uint32Array(6);
  crypto.getRandomValues(array);
  for (let i = 0; i < array.length; i++) {
    result += chars[array[i] % chars.length];
  }
  return result;
}