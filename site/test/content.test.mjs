// Contracts that the build depends on and that a reader of lib/content.js
// would otherwise have to infer: docs/src is a boundary, and raw HTML is
// allowed only because the source is repository content.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { containedDocPath, docs, docsNav, docRoute } from "../lib/content.js";

test("a traversal target is refused rather than read", () => {
  for (const target of [
    "../../../etc/passwd",
    "..",
    "../outside.md",
    "configuration/../../escape.md",
    "/etc/passwd",
  ]) {
    assert.throws(
      () => containedDocPath(target, "test"),
      /escapes docs\/src/,
      `expected ${target} to be refused`,
    );
  }
});

test("a nested path inside the book is accepted and normalised", () => {
  assert.equal(
    containedDocPath("configuration/routes.md", "t"),
    "configuration/routes.md",
  );
  assert.equal(containedDocPath("./auth/oidc.md", "t"), "auth/oidc.md");
  // Climbing and returning stays inside, so it is legal.
  assert.equal(
    containedDocPath("auth/../configuration/global.md", "t"),
    "configuration/global.md",
  );
  assert.equal(
    containedDocPath("assets/webui-setup.png", "t"),
    "assets/webui-setup.png",
  );
});

test("the error names the offending target and where it came from", () => {
  assert.throws(
    () => containedDocPath("../secrets.md", "SUMMARY.md"),
    (e) =>
      e.message.includes("../secrets.md") && e.message.includes("SUMMARY.md"),
  );
});

test("no rendered link or image escapes the published docs tree", () => {
  // The validator runs during render; this checks the output as well, so a
  // future change that bypasses it still fails here.
  for (const page of docs()) {
    for (const [, url] of page.html.matchAll(/(?:href|src)="([^"]+)"/g)) {
      assert.ok(
        !url.includes("/../") && !url.endsWith("/.."),
        `${page.file} emits an escaping URL: ${url}`,
      );
    }
  }
});

test("raw HTML stays enabled, and the source it trusts is repository content", () => {
  const source = readFileSync(
    fileURLToPath(new URL("../lib/content.js", import.meta.url)),
    "utf8",
  );
  // If someone turns this off, the book's existing raw HTML breaks silently.
  // If someone points this renderer at non-repository input, the comment
  // above the flag is the thing they need to have read.
  assert.match(source, /html: true/);
  assert.match(source, /repository content reviewed like code/);
  assert.equal(
    source.includes("docs/src"),
    true,
    "the trusted source directory should be named in the file",
  );
});

test("every SUMMARY entry with a target resolves to a route, and none are orphaned", () => {
  const nav = docsNav();
  const routed = nav.filter((i) => i.route);
  assert.ok(routed.length > 0);
  for (const item of routed) {
    assert.equal(item.route, docRoute(item.file));
    assert.ok(item.route.startsWith("docs/"));
  }
  // Section headings carry no route and must not pretend to.
  for (const item of nav.filter((i) => !i.route)) {
    assert.equal(item.file, undefined);
  }
});
