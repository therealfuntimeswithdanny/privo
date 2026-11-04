"use strict";

(() => {
  const headerHost = document.querySelector("[data-site-header]");
  const footerHost = document.querySelector("[data-site-footer]");
  if (!headerHost || !footerHost) return;

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

  const about = document.createElement("a");
  about.href = "/p/about.html";
  about.textContent = "About";
  if (location.pathname.endsWith("/about.html")) about.setAttribute("aria-current", "page");

  const report = document.createElement("a");
  report.href = "mailto:abuse@privo.fyi";
  report.className = "signin";
  report.textContent = "Report a Link";
  nav.append(about, report);
  header.append(brand, nav);
  headerHost.replaceWith(header);

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
})();
