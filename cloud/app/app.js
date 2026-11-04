/* Privo Cloud: helpers shared by the pages under /cloud/app. */
window.Privo = (() => {
  "use strict";

  // The Worker lives on api.privo.fyi; the session cookie goes with credentials: "include".
  const API = "https://api.privo.fyi";

  const $ = (id) => document.getElementById(id);

  let toastTimer;
  function showToast(message) {
    const toast = $("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 3500);
  }

  function formatBytes(n) {
    const units = ["B", "KB", "MB", "GB"];
    let v = Number(n) || 0;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (v >= 10 || i === 0 ? Math.round(v) : Math.round(v * 10) / 10) + units[i];
  }

  // The database stores UTC as "YYYY-MM-DD HH:MM:SS"; show it in the viewer's time zone.
  function formatTime(utc) {
    const d = new Date(String(utc).replace(" ", "T") + "Z");
    if (isNaN(d)) return "";
    const parts = new Intl.DateTimeFormat("en-US", {
      month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
      hourCycle: "h23", timeZoneName: "short"
    }).formatToParts(d);
    const get = (t) => (parts.find((p) => p.type === t) || {}).value || "";
    return `${get("month")}/${get("day")} @ ${get("hour")}:${get("minute")}:${get("second")} ${get("timeZoneName")}`;
  }

  function shorten(text, max) {
    const t = String(text || "").replace(/^https?:\/\//, "");
    return t.length > max ? t.slice(0, max - 1) + "…" : t;
  }

  // Signed out -> sign in page. Otherwise fill the sidebar card and return the user.
  async function loadMe() {
    const form = $("logoutForm");
    if (form) form.action = API + "/cloud/auth/logout";

    try {
      const res = await fetch(API + "/api/me", { credentials: "include", cache: "no-store" });

      if (res.status === 401) {
        window.location.replace("/cloud/login");
        return null;
      }
      if (!res.ok) throw new Error("HTTP " + res.status);

      const { user } = await res.json();
      const name = user.name || user.email;

      for (const el of document.querySelectorAll("[data-name]")) el.textContent = name;
      if (user.picture) {
        for (const img of document.querySelectorAll("[data-avatar]")) {
          img.src = user.picture;
          img.hidden = false;
        }
      }
      return user;
    } catch (_) {
      showToast("Couldn’t reach Privo Cloud. Try refreshing.");
      return null;
    }
  }

  return { API, $, showToast, formatBytes, formatTime, shorten, loadMe };
})();