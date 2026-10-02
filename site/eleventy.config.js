import { base } from "./lib/config.js";

export default function (config) {
  config.addWatchTarget("src/guides/");
  config.addWatchTarget("../docs/src/");
  config.addWatchTarget("lib/");
  config.addPassthroughCopy({
    "src/style.css": "style.css",
    "src/mark.svg": "mark.svg",
    // The book's figures live with the book source, not with the site.
    "../docs/src/assets": "docs/assets",
  });
  return {
    dir: { input: "src", output: "dist" },
    pathPrefix: base,
    // Only JS templates are rendered. Markdown under src/guides/ is content
    // read by lib/content.js, not a template Eleventy should pick up.
    templateFormats: ["11ty.js"],
  };
}
