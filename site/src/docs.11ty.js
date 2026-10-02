import { shell } from "../lib/layout.js";
import { url, repository } from "../lib/config.js";
import { docs } from "../lib/content.js";

const esc = (s) =>
  String(s).replace(
    /[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c],
  );

// The book's own table of contents, as a sidebar. Entries with no route are
// SUMMARY.md section headings — they group the pages beneath them without
// being pages themselves, so they render as labels rather than dead links.
function sidebar(nav, current) {
  const items = nav
    .map((item) => {
      if (!item.route) return `<span class="group">${esc(item.title)}</span>`;
      const cls = item.nested ? ' class="nested"' : "";
      const here = item.route === current ? ' aria-current="page"' : "";
      return `<a href="${url(item.route)}"${cls}${here}>${esc(item.title)}</a>`;
    })
    .join("\n        ");
  return `<aside class="docs-nav">
      <nav aria-label="Documentation">
        ${items}
      </nav>
    </aside>`;
}

export const data = {
  pagination: { data: "entries", size: 1, alias: "entry" },
  entries: docs(),
  permalink: (data) => data.entry.route,
};

export function render({ entry }) {
  const source = `${repository}/blob/main/docs/src/${entry.file}`;
  return shell({
    title: `${entry.title} — Sekisho IAP`,
    description: `${entry.title}. Documentation for Sekisho IAP, an identity-aware proxy in Rust.`,
    permalink: entry.route,
    mainClass: "docs",
    body: `${sidebar(entry.nav, entry.route)}
    <article>
      <h1>${esc(entry.title)}</h1>
      ${entry.html}
      <p class="doc-source"><a href="${source}">Edit this page on GitHub ↗</a></p>
    </article>`,
  });
}
