import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { url } from "./config.js";

// Static assets are served from a stable path, so a browser that fetched an
// earlier build has no reason to ask again. Appending a hash of the current
// bytes makes the URL change exactly when the file does — no manual version
// bumping, and no cache-busting on files that did not move.
const dir = fileURLToPath(new URL("../src/", import.meta.url));

export function asset(file) {
  const digest = createHash("sha256")
    .update(readFileSync(dir + file))
    .digest("hex")
    .slice(0, 8);
  return `${url(file)}?v=${digest}`;
}
