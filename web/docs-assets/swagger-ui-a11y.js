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
      const permalink = document.createElement("a");
      permalink.className = "hermes-swagger-permalink";
      permalink.href = href;
      permalink.textContent = "#";
      const operationName = anchor.textContent?.trim() || "operation";
      permalink.setAttribute("aria-label", `Permalink to ${operationName}`);
      permalink.title = `Permalink to ${operationName}`;
      anchor.replaceWith(replacement);
      replacement.closest(".opblock-summary-control")?.insertAdjacentElement("afterend", permalink);
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
