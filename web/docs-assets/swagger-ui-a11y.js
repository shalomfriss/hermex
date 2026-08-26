(() => {
  const PATCHED = "data-hermes-swagger-link-patched";

  function promoteSummaryPathLinks(root = document) {
    for (const anchor of root.querySelectorAll(`.opblock-summary-control .opblock-summary-path a.nostyle[href]:not([${PATCHED}])`)) {
      const href = anchor.getAttribute("href");
      if (!href) continue;
      const replacement = document.createElement("span");
      replacement.className = anchor.className;
      replacement.setAttribute(PATCHED, "true");
      replacement.dataset.swaggerHref = href;
      for (const child of Array.from(anchor.childNodes)) {
        replacement.appendChild(child.cloneNode(true));
      }
      replacement.addEventListener("click", () => {
        window.location.hash = href.startsWith("#") ? href.slice(1) : href;
      });
      anchor.replaceWith(replacement);
    }
  }

  function install() {
    promoteSummaryPathLinks(document);
    const container = document.getElementById("swagger-ui");
    if (!container) return;
    const observer = new MutationObserver(() => promoteSummaryPathLinks(container));
    observer.observe(container, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", install, { once: true });
  } else {
    install();
  }
})();
