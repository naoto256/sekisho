// The sitemap and the site must agree on what exists. They are built from the
// same route authority, and this is what keeps that true.
import { test } from "node:test";
import assert from "node:assert/strict";

import { docs } from "../lib/content.js";
import { render } from "../src/sitemap.11ty.js";
import { canonical } from "../lib/config.js";

const sitemapLocs = () =>
  [...render().matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);

test("every docs route is in the sitemap", () => {
  const locs = new Set(sitemapLocs());
  const routes = docs().map((d) => d.route);
  assert.ok(routes.length > 0, "expected the book to produce routes");
  for (const route of routes) {
    assert.ok(locs.has(canonical(route)), `sitemap is missing ${route}`);
  }
});

test("the sitemap claims no docs page the site does not build", () => {
  const routes = new Set(docs().map((d) => canonical(d.route)));
  const strays = sitemapLocs().filter(
    (loc) => loc.includes("/docs/") && !routes.has(loc),
  );
  assert.deepEqual(strays, [], "sitemap lists docs URLs that are not built");
});

test("the book index is listed, not just the chapters", () => {
  // docs/index.html comes from the first SUMMARY entry rather than a file
  // called index.md, so it is the one most likely to be dropped.
  assert.ok(sitemapLocs().includes(canonical("docs/index.html")));
});

test("no duplicate entries", () => {
  const locs = sitemapLocs();
  assert.equal(new Set(locs).size, locs.length);
});
