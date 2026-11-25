/* Privo Cloud: helpers shared by the pages under /cloud/app. */
window.Privo = (() => {
  "use strict";

  // Same origin as the pages now — the session cookie travels automatically.
  const API = "";

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
      const res = await fetch(API + "/api/me", { credentials: "same-origin", cache: "no-store" });

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
/* Collapsible sidebar — shrinks to icons + avatar, remembered per browser. */
(() => {
  "use strict";
  const app = document.querySelector(".app");
  const sidebar = document.querySelector(".sidebar");
  if (!app || !sidebar) return;

  const KEY = "privo-nav-collapsed";

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "collapse-btn";
  btn.setAttribute("aria-label", "Collapse sidebar");
  btn.innerHTML =
    '<i class="fa-solid fa-angles-left" aria-hidden="true"></i><span class="lbl">Collapse</span>';
  sidebar.insertBefore(btn, sidebar.children[1] || null);

  const set = (on) => {
    app.classList.toggle("nav-collapsed", on);
    btn.setAttribute("aria-label", on ? "Expand sidebar" : "Collapse sidebar");
    btn.querySelector("i").className = on
      ? "fa-solid fa-angles-right"
      : "fa-solid fa-angles-left";
    try { localStorage.setItem(KEY, on ? "1" : "0"); } catch {}
  };

  btn.addEventListener("click", () =>
    set(!app.classList.contains("nav-collapsed"))
  );

  try { set(localStorage.getItem(KEY) === "1"); } catch {}
})();
