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
      const summary = anchor.closest(".opblock-summary");
      const method = summary?.querySelector(".opblock-summary-method")?.textContent?.trim();
      const path = anchor.textContent?.trim() || "operation";
      const baseLabel = `Permalink to ${method ? `${method} ` : ""}${path}`;
      const usedLabels = new Set(
        Array.from(document.querySelectorAll(".hermes-swagger-permalink[aria-label]"), (link) =>
          link.getAttribute("aria-label"),
        ),
      );
      let label = baseLabel;
      for (let duplicate = 2; usedLabels.has(label); duplicate += 1) {
        label = `${baseLabel} (${duplicate})`;
      }
      permalink.setAttribute("aria-label", label);
      permalink.title = label;
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
