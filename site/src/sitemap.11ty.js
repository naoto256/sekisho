import { canonical } from "../lib/config.js";
import { guides, docs } from "../lib/content.js";

export const data = {
  permalink: "sitemap.xml",
  eleventyExcludeFromCollections: true,
};

export function render() {
  // The docs routes come from `docs()` rather than being listed again here.
  // It is the same function `src/docs.11ty.js` paginates over, so a chapter
  // added to SUMMARY.md appears in the sitemap for the same reason it appears
  // on the site — there is no second enumeration to fall out of step.
  const paths = [
    "index.html",
    "guides/index.html",
    ...guides().map((g) => `guides/${g.slug}.html`),
    ...docs().map((d) => d.route),
  ];
  const urls = paths
    .map((p) => `  <url><loc>${canonical(p)}</loc></url>`)
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;
}
