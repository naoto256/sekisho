// Runtime glue for sekisho-webui. Loaded after htmx.min.js from the same
// origin so our CSP can stay `script-src 'self'` with no inline scripts
// or nonce plumbing.
//
// Responsibilities:
//   1. Tighten htmx defaults so a swapped HTML fragment cannot execute
//      arbitrary JS (no eval, no <script>-tag execution, no inline-script
//      nonce propagation — see htmx CSP caveats).
//   2. Wire CSRF: copy the value from `<meta name="csrf-token">` into the
//      `X-CSRF-Token` header on every htmx-issued request, including
//      `hx-boost`-promoted form submissions.

(function () {
  if (typeof window.htmx === "undefined") return;
  htmx.config.allowEval = false;
  htmx.config.allowScriptTags = false;
  htmx.config.inlineScriptNonce = "";
  htmx.config.selfRequestsOnly = true;

  document.addEventListener("htmx:configRequest", function (e) {
    var m = document.querySelector('meta[name="csrf-token"]');
    if (m) {
      e.detail.headers["X-CSRF-Token"] = m.content;
    }
  });

  // Danger-Zone confirmation: a button decorated with
  // `data-confirm-name="<word>"` requires the operator to type that
  // word verbatim into a prompt before its enclosing form submits.
  // Mirrors GitHub's "type the repo name to delete" pattern; a plain
  // `prompt()` is enough on a same-origin admin page where the
  // operator is already authenticated.
  document.addEventListener("submit", function (e) {
    var submitter = e.submitter;
    if (!submitter || !submitter.dataset || !submitter.dataset.confirmName) {
      return;
    }
    var expected = submitter.dataset.confirmName;
    var prompt_text =
      submitter.dataset.confirmPrompt ||
      'Type "' + expected + '" to confirm';
    var typed = window.prompt(prompt_text);
    if (typed !== expected) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);
})();
