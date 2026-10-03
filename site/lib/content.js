import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import MarkdownIt from "markdown-it";
import anchor from "markdown-it-anchor";
import { highlight } from "./highlight.js";
import { url } from "./config.js";

/**
 * mdBook's heading-id rule, reproduced.
 *
 * The docs were written against mdBook and their cross-references are
 * hand-written against the ids it produces, so the ids have to survive the
 * change of renderer — otherwise every `#some-heading` link in the book
 * silently stops landing. mdBook keeps letters, digits, `_`, `-` and spaces,
 * turns spaces into hyphens, and lowercases; notably it *drops* punctuation
 * rather than encoding it, so `### 3. API-version-gated clients` is
 * `3-api-version-gated-clients` and not `3.-api-version-gated-clients`.
 *
 * markdown-it-anchor appends `-1`, `-2`, … to duplicates, which is also what
 * mdBook does, so collisions need no special handling here.
 */
export const slugify = (text) =>
  [...String(text)]
    .filter((ch) => /[\p{L}\p{N}_\- ]/u.test(ch))
    .join("")
    .replace(/ /g, "-")
    .toLowerCase();

const md = new MarkdownIt({ html: true, linkify: false }).use(anchor, {
  level: [2, 3],
  slugify,
});

const dir = fileURLToPath(new URL("../src/guides/", import.meta.url));

// Guides are plain markdown. The first `# ` line is the title and is not
// repeated in the body, so the shell can own the page heading.
export function guides() {
  return readdirSync(dir)
    .filter((f) => f.endsWith(".md") && f !== "index.md")
    .sort()
    .map((file) => {
      const raw = readFileSync(dir + file, "utf8");
      const title = /^#\s+(.+)$/m.exec(raw)?.[1] ?? file;
      return {
        slug: file.replace(/\.md$/, ""),
        title,
        html: md.render(raw),
      };
    });
}

export const renderMarkdown = (text) => md.render(text);

/* ── The book, rendered by the site ─────────────────────────────────────
 *
 * The documentation lives in docs/src as an mdBook source tree and is also
 * the site's /docs/ section. It is rendered here rather than mounting
 * mdBook's own output, so that a reader walking from the landing page into
 * the reference does not cross into different chrome halfway through.
 *
 * docs/book.toml still works — `mdbook build docs` is untouched and remains
 * the local preview path. The site simply does not consume its output.
 */

/**
 * `docs/src` is the boundary, and this is the only thing that enforces it.
 *
 * Two kinds of path reach the filesystem or a URL from here: chapter targets
 * read out of `SUMMARY.md`, and link/image targets written inside a chapter.
 * Both are repository content rather than user input, but nothing upstream of
 * this file checks them, and the failure modes differ: a `..` in SUMMARY reads
 * a file outside the book, while a `..` in a chapter link emits a
 * `docs/../something` URL that points outside the published tree. One
 * validator on both paths, and a build that stops rather than producing either.
 *
 * Deliberately not a general-purpose sandbox — it answers one question about
 * one directory, which is what makes it possible to apply it everywhere it
 * matters without anyone having to remember to.
 */
export function containedDocPath(target, context) {
  const normalized = path.posix.normalize(target);
  if (
    path.posix.isAbsolute(normalized) ||
    normalized === ".." ||
    normalized.startsWith("../")
  ) {
    throw new Error(
      `docs path escapes docs/src: ${JSON.stringify(target)} (from ${context})`,
    );
  }
  return normalized;
}

const docsDir = fileURLToPath(new URL("../../docs/src/", import.meta.url));
const readDoc = (file) => readFileSync(docsDir + file, "utf8");

/** `configuration/routes.md` → `docs/configuration/routes.html`.
 *  The book's first chapter becomes `docs/index.html` so that a link to
 *  `docs/` lands somewhere, the way mdBook's own index does. */
export function docRoute(file) {
  if (file === "introduction.md") return "docs/index.html";
  return "docs/" + file.replace(/\.md$/, ".html");
}

/**
 * Parse `SUMMARY.md` into a flat list that still knows its shape.
 *
 * mdBook's format allows a bracketed entry with an empty target — a heading
 * that groups the pages under it without being a page itself (`- [Install]()`
 * here). Those carry no route, so they are kept as group labels rather than
 * dropped, which would otherwise orphan the pages nested beneath them.
 */
export function docsNav() {
  const items = [];
  let group = null;
  for (const line of readDoc("SUMMARY.md").split("\n")) {
    const entry = /^(\s*)(?:- )?\[([^\]]+)\]\(([^)]*)\)/.exec(line);
    if (!entry) continue;
    const [, indent, title, target] = entry;
    const nested = indent.length > 0;
    if (!target) {
      // Section heading with no page of its own.
      group = title;
      items.push({ title, group, nested: false, route: null });
      continue;
    }
    const file = containedDocPath(target.replace(/^\.\//, ""), "SUMMARY.md");
    if (!nested) group = title;
    items.push({ title, file, group, nested, route: docRoute(file) });
  }
  return items;
}

/**
 * Rewrite a link written for mdBook so it resolves in the built site.
 *
 * Targets in the source are relative to the file they appear in, and point at
 * `.md` files. Both facts have to be undone: resolve against the source tree
 * to get a book-relative path, map it through `docRoute`, then hand it to
 * `url()` so the Pages path prefix is applied. Anything absolute, external or
 * a bare fragment is left exactly as written.
 */
function resolveDocLink(href, file) {
  if (!href || /^[a-z]+:/i.test(href) || href.startsWith("//")) return href;
  if (href.startsWith("#")) return href;
  if (href.startsWith("/")) return href;

  const [target, fragment] = href.split("#");
  if (!target) return href;

  const fromDir = path.posix.dirname(file);
  const resolved = containedDocPath(path.posix.join(fromDir, target), file);

  const mapped = resolved.endsWith(".md")
    ? docRoute(resolved)
    : "docs/" + resolved;
  return url(mapped) + (fragment ? "#" + fragment : "");
}

/**
 * A markdown-it instance per page: the link and image rules need to know
 * which file they are rendering to resolve relative targets, and rules are
 * instance state rather than per-render state.
 */
function docRenderer(file) {
  const inst = new MarkdownIt({
    // `html: true` is safe here and only here: the source is docs/src, which
    // is repository content reviewed like code, and the book legitimately uses
    // raw HTML. It is not a general Markdown renderer and must not be pointed
    // at anything a reader can write. Locked by a test.
    html: true,
    linkify: false,
    highlight: (code, lang) =>
      `<pre><code>${highlight(code.replace(/\n$/, ""), lang)}</code></pre>`,
  }).use(anchor, { level: [2, 3], slugify });

  inst.renderer.rules.link_open = (tokens, idx, options, env, renderer) => {
    tokens[idx].attrSet(
      "href",
      resolveDocLink(tokens[idx].attrGet("href"), file),
    );
    return renderer.renderToken(tokens, idx, options);
  };
  const image = inst.renderer.rules.image;
  inst.renderer.rules.image = (tokens, idx, options, env, renderer) => {
    tokens[idx].attrSet(
      "src",
      resolveDocLink(tokens[idx].attrGet("src"), file),
    );
    tokens[idx].attrSet("loading", "lazy");
    return image(tokens, idx, options, env, renderer);
  };
  return inst;
}

/** One entry per page in SUMMARY.md, ready for pagination. */
export function docs() {
  const nav = docsNav();
  return nav
    .filter((item) => item.route)
    .map((item) => {
      const raw = readDoc(item.file);
      // The book repeats its title as an `# ` heading; the shell renders the
      // title itself, so the duplicate is dropped from the body.
      const body = raw.replace(/^#\s+.+\n+/, "");
      return {
        ...item,
        title: /^#\s+(.+)$/m.exec(raw)?.[1] ?? item.title,
        html: docRenderer(item.file).render(body),
        nav,
      };
    });
}
