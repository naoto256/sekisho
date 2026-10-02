import { url, canonical, repository } from "./config.js";
import { asset } from "./asset.js";

const esc = (s) =>
  String(s).replace(
    /[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c],
  );

export const MARK = `<svg viewBox="0 -4 180 88" role="img" aria-label="Sekisho IAP"><text x="8" y="60" text-anchor="start" font-family="'Hiragino Mincho ProN','Hiragino Mincho Pro','Yu Mincho','YuMincho','Noto Serif CJK JP','Noto Serif JP','MS Mincho',serif" font-size="76" font-weight="300" fill="currentColor">[</text><text x="172" y="60" text-anchor="end" font-family="'Hiragino Mincho ProN','Hiragino Mincho Pro','Yu Mincho','YuMincho','Noto Serif CJK JP','Noto Serif JP','MS Mincho',serif" font-size="76" font-weight="300" fill="currentColor">]</text><text x="90" y="54" text-anchor="middle" font-family="'Hiragino Mincho ProN','Hiragino Mincho Pro','Yu Mincho','YuMincho','Noto Serif CJK JP','Noto Serif JP','MS Mincho',serif" font-size="54" font-weight="500" fill="currentColor">関所</text><text x="90" y="78" text-anchor="middle" font-family="system-ui,-apple-system,'Segoe UI','Helvetica Neue',Arial,sans-serif" font-size="16" letter-spacing="4" fill="currentColor">sekisho</text></svg>`;

// Single page shell. Every page on the site renders through this so the
// barrier motif, the nav and the metadata stay in one place.
export function shell({
  title,
  description,
  permalink,
  body,
  wide = false,
  mainClass,
}) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<link rel="canonical" href="${canonical(permalink)}">
<meta name="description" content="${esc(description)}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:type" content="website">
<meta property="og:url" content="${canonical(permalink)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:site_name" content="Sekisho IAP">
<!-- summary, not summary_large_image: there is no social preview raster
     to point at, and a large-image card with no image renders worse
     than a small one. See site/README.md "Known gaps". -->
<meta name="twitter:card" content="summary">
<link rel="stylesheet" href="${asset("style.css")}">
<link rel="icon" type="image/svg+xml" href="${asset("mark.svg")}">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header${mainClass === "docs" ? ' class="wide"' : ""}>
  <div class="wrap">
    <a class="brand" href="${url()}">${MARK}Sekisho IAP</a>
    <nav aria-label="Main">
      <a href="${url("docs/")}">Docs</a>
      <a href="${url("guides/")}">Guides</a>
      <a href="${repository}">GitHub ↗</a>
    </nav>
  </div>
</header>
<main id="main"${mainClass ? ` class="${mainClass}"` : wide ? "" : ' class="prose"'}>
${body}
</main>
<footer${mainClass === "docs" ? ' class="wide"' : ""}>
  <div class="wrap">
    <a class="brand" href="${url()}">Sekisho IAP</a>
    <span>An identity-aware proxy in Rust.</span>
    <span class="sep">MIT / Apache-2.0</span>
  </div>
</footer>
</body>
</html>
`;
}
