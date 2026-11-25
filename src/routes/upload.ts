// POST /api/cloud/upload-image — account-owned preview image into R2.

import type { Env } from "../env";
import { error, json, sameOrigin } from "../lib/http";
import { getSessionUser } from "../lib/account";
import {
  IMAGE_MAX_BYTES,
  imageExtension,
  readLimitedRequestBody,
  sniffImageType,
} from "../lib/images";

export async function uploadImage(request: Request, env: Env, url: URL): Promise<Response> {
  if (!sameOrigin(request, url)) {
    return error("Uploads must come from Privo Cloud.", 403);
  }

  const user = await getSessionUser(request, env);
  if (!user) return error("Not signed in", 401);

  if (!env.IMAGES) return error("Image storage is unavailable right now.", 503);

  const requestContentType = request.headers.get("Content-Type") || "";
  if (!/^multipart\/form-data\s*;/i.test(requestContentType)) {
    return error("Choose an image file to upload.");
  }

  const contentLength = Number(request.headers.get("Content-Length"));
  if (contentLength && contentLength > IMAGE_MAX_BYTES + 65536) {
    return error("Preview images must be 5 MB or smaller.", 413);
  }

  let form: FormData;
  try {
    const body = await readLimitedRequestBody(request, IMAGE_MAX_BYTES + 65536);
    if (!body) return error("Preview images must be 5 MB or smaller.", 413);
    const formRequest = new Request(request.url, {
      method: "POST",
      headers: { "Content-Type": requestContentType },
      body,
    });
    form = await formRequest.formData();
  } catch (e) {
    console.error("Preview image form error:", e);
    return error("Choose an image file to upload.");
  }

  const file = form.get("image");
  if (!(file instanceof File) || !file.size) {
    return error("Choose an image file to upload.");
  }
  if (file.size > IMAGE_MAX_BYTES) {
    return error("Preview images must be 5 MB or smaller.", 413);
  }

  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await file.arrayBuffer());
  } catch (e) {
    console.error("Preview image read error:", e);
    return error("Could not read the selected image.");
  }

  const contentType = sniffImageType(bytes);
  if (!contentType) {
    return error("Use a PNG, JPEG, GIF, WebP, or AVIF image.", 415);
  }

  const date = new Date().toISOString().slice(0, 10);
  const imageName = crypto.randomUUID() + imageExtension(contentType)!;
  const key = `og/${date}/${imageName}`;
  const imageUrl = `https://privo.fyi/${key}`;

  try {
    await env.IMAGES.put(key, bytes, {
      httpMetadata: { contentType },
      customMetadata: { owner: user.id, kind: "custom-preview" },
    });
  } catch (e) {
    console.error("Preview image upload error:", e);
    return error("Could not upload the image. Try again.", 500);
  }

  try {
    await env.ACCOUNTS
      .prepare("INSERT INTO r2_files (user_id, r2_key, file_url, content_type, size_bytes) VALUES (?, ?, ?, ?, ?)")
      .bind(user.id, key, imageUrl, contentType, bytes.byteLength)
      .run();
  } catch (e) {
    try {
      await env.IMAGES.delete(key);
    } catch (cleanupError) {
      console.error("Preview image cleanup error:", cleanupError);
      return error(
        "Upload could not be recorded and its temporary file could not be removed. Contact support.",
        500
      );
    }

    const message = String((e as Error)?.message);
    if (message.includes("LIMIT_R2")) {
      return error("Your account has reached its R2 storage limit.", 403);
    }
    if (message.includes("LIMIT_D1")) {
      return error("Your account has reached its 300 MB database limit.", 403);
    }
    console.error("Preview image record error:", e);
    return error("The image uploaded, but its account record could not be saved.", 500);
  }

  return json({ image: imageUrl, contentType, size: bytes.byteLength }, { status: 201 });
}
