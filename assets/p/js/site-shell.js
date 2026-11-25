"use strict";

(() => {
  const headerHost = document.querySelector("[data-site-header]");
  const footerHost = document.querySelector("[data-site-footer]");
  if (!headerHost && !footerHost) return;

if (headerHost) {

  const header = document.createElement("header");
  header.className = "header";

  const brand = document.createElement("a");
  brand.href = "/";
  brand.className = "brand";
  brand.setAttribute("aria-label", "Privo home");
  brand.append("privo.");
  const brandDomain = document.createElement("em");
  const brandSuffix = document.createElement("i");
  brandSuffix.textContent = "fyi";
  brandDomain.append(brandSuffix);
  brand.append(brandDomain);

  const nav = document.createElement("nav");
  nav.className = "nav";
  nav.setAttribute("aria-label", "Primary navigation");

  const links = [
    { href: "/p/about", text: "About" },
    { href: "/docs", text: "API Docs" },
    { href: "/report", text: "Report a Link" },
    { href: "/cloud", text: "Privo Cloud" },
    { href: "/cloud/login", text: "Sign in", className: "signin" },
  ];

  for (const item of links) {
    const a = document.createElement("a");
    a.href = item.href;
    a.textContent = item.text;
    if (item.className) a.className = item.className;
    if (location.pathname === item.href || location.pathname === item.href + ".html") {
      a.setAttribute("aria-current", "page");
    }
    nav.append(a);
  }

  header.append(brand, nav);
  headerHost.replaceWith(header);
} /* end header */

if (footerHost) {
  const footer = document.createElement("footer");
  footer.className = "footer";

  const details = document.createElement("div");
  const footerBrand = document.createElement("div");
  footerBrand.className = "footer-brand";
  footerBrand.append("privo.");
  const footerDomain = document.createElement("em");
  footerDomain.textContent = "fyi";
  footerBrand.append(footerDomain);

  const copy = document.createElement("p");
  copy.className = "footer-copy";
  const copyright = document.createElement("i");
  copyright.className = "fa-regular fa-copyright";
  copyright.setAttribute("aria-hidden", "true");
  const year = document.createElement("span");
  year.textContent = String(new Date().getFullYear());
  const company = document.createElement("a");
  company.href = "https://coffeencode.cc";
  company.textContent = "Coffee & Code";
  copy.append(copyright, " ", year, " ", company, document.createElement("br"));
  copy.append("Contact support via Email ");
  const support = document.createElement("a");
  support.href = "mailto:support@privo.fyi";
  support.textContent = "support@privo.fyi";
  copy.append(support, document.createElement("br"), "Report Abuse via email ");
  const abuse = document.createElement("a");
  abuse.href = "mailto:abuse@privo.fyi";
  abuse.textContent = "abuse@privo.fyi";
  copy.append(abuse);
  details.append(footerBrand, copy);

  const footerLinks = document.createElement("div");
  footerLinks.className = "footer-links";
  const terms = document.createElement("a");
  terms.href = "/legal/terms";
  terms.textContent = "Terms of Service";
  const privacy = document.createElement("a");
  privacy.href = "/legal/privacy";
  privacy.textContent = "Privacy Policy";
  footerLinks.append(terms, privacy);

  footer.append(details, footerLinks);
  const footerBottom = document.createElement("div");
  footerBottom.className = "footer-bottom";
  footerHost.replaceWith(footer, footerBottom);
} /* end footer */
})();

/* Dynamic header: compact on scroll, hamburger menu on small screens. */
(() => {
  const header = document.querySelector(".header");
  const nav = document.querySelector(".header .nav");
  if (!header || !nav) return;

  const onScroll = () => header.classList.toggle("scrolled", window.scrollY > 12);
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "nav-toggle";
  toggle.setAttribute("aria-label", "Menu");
  toggle.setAttribute("aria-expanded", "false");
  toggle.innerHTML = '<i class="fa-solid fa-bars" aria-hidden="true"></i>';
  header.append(toggle);

  const setOpen = (open) => {
    nav.classList.toggle("open", open);
    toggle.setAttribute("aria-expanded", String(open));
    toggle.innerHTML = open
      ? '<i class="fa-solid fa-xmark" aria-hidden="true"></i>'
      : '<i class="fa-solid fa-bars" aria-hidden="true"></i>';
  };

  toggle.addEventListener("click", () => setOpen(!nav.classList.contains("open")));

  document.addEventListener("click", (e) => {
    if (!header.contains(e.target)) setOpen(false);
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") setOpen(false);
  });

  nav.addEventListener("click", (e) => {
    if (e.target.closest("a")) setOpen(false);
  });
})();
