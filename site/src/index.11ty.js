import { shell, MARK } from "../lib/layout.js";
import { url } from "../lib/config.js";

export const data = { permalink: "index.html" };

export function render() {
  return shell({
    title: "Every request presents credentials — Sekisho IAP",
    description:
      "Sekisho is an identity-aware proxy. One binary in front of your internal tools: TLS, SSO, per-route policy, and an identity the upstream can verify.",
    permalink: "index.html",
    wide: true,
    body: `<section class="hero">
    <div class="wrap">
      <h1>Every request<br>presents its credentials.<br><em>Then it may pass.</em></h1>
      <p class="lede">
        A <em>sekisho</em> was a checkpoint station on the highways of Edo-period
        Japan. No traveller went through without showing a pass. This one sits in
        front of your internal web tools and does the same thing to HTTP.
      </p>

      <div class="toll">
        <ul>
          <li>A dashboard whose only protection is a shared password in a wiki page.</li>
          <li>A VPN rolled out so that four people can reach one Grafana.</li>
          <li>OIDC bolted into five applications, five different ways, five times to fix.</li>
          <li>An appliance web UI that will never support SSO, and never be replaced.</li>
        </ul>
        <p class="verdict">Put a checkpoint in front of them instead.</p>
      </div>

      <div class="actions">
        <a class="button" href="${url("docs/quick-start.html")}">Quick start</a>
        <a class="button ghost" href="${url("docs/")}">Read the docs</a>
      </div>
    </div>
  </section>

  <section class="gate" aria-labelledby="gate-title">
    <div class="wrap">
      <h2 id="gate-title">What happens at the barrier</h2>

      <div class="road">
        <div class="post">
          <h3>Browser</h3>
          <p>Arrives at <code>grafana.example.com</code> with no session.</p>
        </div>
        <div class="checkpoint">
          <h3 class="mark">${MARK}<span class="sr">Sekisho</span></h3>
          <ol>
            <li>TLS terminated, certificate chosen by SNI</li>
            <li>Route matched on host and path</li>
            <li>Sent to the IdP; assertion verified on return</li>
            <li>Policy evaluated against claims and network</li>
            <li>Identity headers signed and attached</li>
          </ol>
        </div>
        <div class="post">
          <h3>Upstream</h3>
          <p>Receives an authenticated request it can verify, on loopback.</p>
        </div>
      </div>

      <p class="road-note">
        All of that is one route object. Below is how you make it.
      </p>
    </div>
  </section>

  <section class="gate" aria-labelledby="cli-title">
    <div class="wrap">
      <h2 id="cli-title">Setting that up</h2>

      <pre><code>sekisho@iap<span class="k">&gt;</span> configure
<span class="c">entering configuration mode</span>
sekisho@iap<span class="k">#</span> create route grafana
<span class="c">creating new route 'grafana' — use 'set' to configure, then 'commit'</span>
sekisho@iap edit route/grafana<span class="k">&gt;</span> set from https://grafana.example.com
<span class="c">  from = "https://grafana.example.com"</span>
sekisho@iap edit route/grafana<span class="k">&gt;</span> set to http://127.0.0.1:3000
<span class="c">  to = ["http://127.0.0.1:3000"]</span>
sekisho@iap edit route/grafana<span class="k">&gt;</span> set access.policy claim.groups in ["platform", "sre"]
<span class="c">  access.policy = {"policy":"claim.groups in [\\"platform\\", \\"sre\\"]"}</span>
sekisho@iap edit route/grafana<span class="k">&gt;</span> set enable-signed-identity true
<span class="c">  enable-signed-identity = true</span>
sekisho@iap edit route/grafana<span class="k">&gt;</span> commit
sekisho@iap<span class="k">#</span> exit
sekisho@iap<span class="k">&gt;</span> show route grafana
{
  <span class="s">"name"</span>: <span class="s">"grafana"</span>,
  <span class="s">"from"</span>: <span class="s">"https://grafana.example.com"</span>,
  <span class="s">"to"</span>: [<span class="s">"http://127.0.0.1:3000"</span>],
  <span class="s">"access"</span>: {
    <span class="s">"policy"</span>: <span class="s">"claim.groups in [\\"platform\\", \\"sre\\"]"</span>,
    <span class="s">"allow_public_unauthenticated_access"</span>: false
  },
  <span class="s">"enable_signed_identity"</span>: true,
<span class="c">  … 20 more fields, every one of them defaulted</span>
}</code></pre>
      <p class="code-note">
        Operational mode reads and switches things on. Configuration mode is the
        only place the shape of a resource changes, and edits are staged until
        <code>commit</code> — so a half-typed route never reaches the data plane.
        What <code>show</code> prints afterwards is not a file being echoed back;
        there is no file. It is the stored resource, which is why the same
        twenty-odd fields exist whether or not you ever mentioned them.
      </p>

      <h3 class="alt-surface">Or the same route in a browser</h3>
      <p>
        The web UI is not a second configuration system. It is the same resource
        over the same API — <code>from</code> and <code>to</code> are the fields
        the shell was <code>set</code>ting, the access policy and the
        signed-identity toggle follow in the card below them, and the secrets it
        holds stay redacted here exactly as they do in the shell.
      </p>
      <figure class="shot">
        <img src="${url("docs/assets/webui-route-edit-window.png")}" alt="A browser showing the Sekisho web UI editing a route: its name, public URL and upstream in the identity card, with the access card beginning below" width="2654" height="2186" loading="lazy">
      </figure>
      <p class="code-note">
        Pick whichever suits the moment. There is no import step and no drift
        between them, because neither owns the configuration — the daemon does.
        <a href="${url("guides/grafana-entra-saml.html")}">Build this route step by step →</a>
      </p>
    </div>
  </section>

  <section class="stances">
    <div class="wrap">

      <div class="stance">
        <div class="seal">Stance 01</div>
        <div>
          <h3>The data model is the truth.</h3>
          <p>
            Every interface — the shell, the web UI, curl, whatever you write next —
            is a projection of the same resources over the same HTTP API. There is no
            config file that a UI secretly rewrites behind your back, and no state that
            only one of them can reach.
          </p>
          <a href="${url("docs/design/architecture.html")}">How the pieces fit →</a>
        </div>
      </div>

      <div class="stance">
        <div class="seal">Stance 02</div>
        <div>
          <h3>Nothing serves until you say so.</h3>
          <p>
            A new route is created disabled. You stage the policy, the IdP binding and
            the DNS, and only then enable it — which is also the moment the certificate
            is obtained. A half-finished route is never briefly live.
          </p>
          <a href="${url("docs/configuration/routes.html")}">Route reference →</a>
        </div>
      </div>

      <div class="stance">
        <div class="seal">Stance 03</div>
        <div>
          <h3>Give the upstream something it can check.</h3>
          <p>
            Plain identity headers ask the upstream to trust the network. Sekisho can
            also sign a short-lived assertion with its Ed25519 identity key and publish
            the public half as JWKS, so an upstream that wants proof can verify instead
            of trusting. The claim set is fixed and the audience is the route itself.
          </p>
          <a href="${url("docs/configuration/routes.html#identity-headers")}">Identity headers →</a>
        </div>
      </div>

      <div class="stance">
        <div class="seal">Stance 04</div>
        <div>
          <h3>One binary, and it speaks ACME and SAML itself.</h3>
          <p>
            No sidecar terminating TLS, no plugin waiting on a vendor release. Certificates are issued and renewed in-process over HTTP-01.
            SAML signatures are verified by a pure-Rust exclusive canonicalizer over a
            parsed DOM, with no path that skips verification.
          </p>
          <a href="${url("docs/configuration/tls.html")}">TLS and ACME →</a>
        </div>
      </div>

    </div>
  </section>`,
  });
}
