// Verifies every internal link in dist/ resolves to a file that was built.
// External links are listed but not fetched: the build must not depend on
// the network, and a flaky third party must not fail a docs deploy.
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { base } from "../lib/config.js";

const dist = fileURLToPath(new URL("../dist/", import.meta.url));

const walk = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(dir + e.name + "/") : [dir + e.name],
  );

const pages = walk(dist).filter((f) => f.endsWith(".html"));
if (pages.length === 0) {
  console.error("no pages in dist/ — run the build first");
  process.exit(1);
}

const problems = [];
let internal = 0;
let external = 0;
let fragments = 0;

// Every id in every built page, so a link into another page's heading can be
// checked and not just the file it lands in. Swapping the Markdown renderer
// changes how heading ids are generated, which is exactly the kind of break
// that resolves as a valid file and still drops the reader at the top.
const idsByPage = new Map();
for (const page of pages) {
  idsByPage.set(
    page.slice(dist.length),
    new Set(
      [...readFileSync(page, "utf8").matchAll(/\bid="([^"]+)"/g)].map(
        (m) => m[1],
      ),
    ),
  );
}

for (const page of pages) {
  const html = readFileSync(page, "utf8");
  const rel = page.slice(dist.length);
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));

  // Unquoted attribute values are legal HTML and were slipping past an
  // earlier quoted-only pattern, so a whole page's links went unchecked.
  for (const [, quoted, bare] of html.matchAll(
    /(?:href|src)=(?:"([^"]+)"|([^\s"'>]+))/g,
  )) {
    const href = quoted ?? bare;
    if (/^(https?:|mailto:|#)/.test(href)) {
      if (href.startsWith("#")) {
        internal++;
        if (!ids.has(href.slice(1)))
          problems.push(`${rel}: dead in-page anchor ${href}`);
      } else external++;
      continue;
    }
    internal++;
    // Strip the fragment and the cache-busting query: both address the same
    // built file, and only the path decides whether it exists.
    const [path] = href.split(/[#?]/);
    const fragment = href.includes("#")
      ? href.slice(href.indexOf("#") + 1)
      : "";

    // Resolve both absolute (base-prefixed) and relative hrefs to a path
    // under dist/. Relative links are legitimate and survive a base change,
    // so the checker resolves them rather than rejecting them.
    let resolved;
    if (href.startsWith(base)) {
      resolved = path.slice(base.length);
    } else if (href.startsWith("/")) {
      problems.push(`${rel}: absolute link outside base ${base}: ${href}`);
      continue;
    } else {
      const from = rel.includes("/")
        ? rel.slice(0, rel.lastIndexOf("/") + 1)
        : "";
      resolved = new URL(path, "file:///" + from).pathname.slice(1);
    }

    let target = dist + resolved;
    if (target.endsWith("/")) target += "index.html";
    if (!existsSync(target) || !statSync(target).isFile()) {
      problems.push(`${rel}: ${href} -> missing ${resolved}`);
      continue;
    }

    if (fragment) {
      fragments++;
      const targetIds = idsByPage.get(target.slice(dist.length));
      if (targetIds && !targetIds.has(fragment))
        problems.push(`${rel}: dead cross-page anchor ${href}`);
    }
  }
}

console.log(
  `${pages.length} pages, ${internal} internal links checked ` +
    `(${fragments} cross-page anchors), ${external} external links listed`,
);
if (problems.length) {
  for (const p of problems) console.error("  " + p);
  process.exit(1);
}
console.log("all internal links resolve");
