// A custom domain would use SITE_BASE=/; GitHub project Pages uses /sekisho/.
export const base = process.env.SITE_BASE || "/sekisho/";
if (!/^\/(?:[a-zA-Z0-9_-]+\/)*$/.test(base))
  throw new Error("SITE_BASE must be an absolute directory path ending in /");

export const url = (path = "") => base + path.replace(/^\//, "");

export const origin = process.env.SITE_ORIGIN || "https://naoto256.github.io";
if (new URL(origin).origin !== origin || !origin.startsWith("https://"))
  throw new Error(
    "SITE_ORIGIN must be an HTTPS origin without a trailing slash",
  );

export const canonical = (path) =>
  origin + url(path.replace(/index\.html$/, ""));

export const repository = "https://github.com/naoto256/sekisho";
