import { shell } from "../lib/layout.js";
import { url } from "../lib/config.js";
import { guides, renderMarkdown } from "../lib/content.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// One page per guide, plus the index. Eleventy pagination over the
// collection keeps the shell in a single place.
export const data = {
  pagination: {
    data: "entries",
    size: 1,
    alias: "entry",
  },
  entries: [
    {
      slug: "index",
      title: "Guides",
      html: renderMarkdown(
        readFileSync(
          fileURLToPath(new URL("./guides/index.md", import.meta.url)),
          "utf8",
        ),
      ),
    },
    ...guides(),
  ],
  permalink: (data) =>
    data.entry.slug === "index"
      ? "guides/index.html"
      : `guides/${data.entry.slug}.html`,
};

export function render({ entry }) {
  const permalink =
    entry.slug === "index" ? "guides/index.html" : `guides/${entry.slug}.html`;
  return shell({
    title: `${entry.title} — Sekisho IAP`,
    description:
      entry.slug === "index"
        ? "Worked examples: complete setups from a fresh install to a protected route."
        : `${entry.title}. A complete, runnable Sekisho setup.`,
    permalink,
    body: `<div class="wrap">\n${entry.html}\n<p class="back"><a href="${url("guides/")}">← All guides</a></p>\n</div>`,
  });
}
