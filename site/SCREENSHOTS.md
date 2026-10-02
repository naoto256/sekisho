# Screenshots

All eight are taken, cropped and placed, and a ninth — the landing page's
browser window — was captured by the owner afterwards. This file is kept as
the record of what was captured, under what conditions, and which of the
original asks turned out not to be answerable — so the next person does not
re-litigate it.

## Status

Complete as of 2026-09-28. The figures live in `docs/src/assets/` and are
referenced from the book; the landing page carries one of its own.

| Figure | Page |
|---|---|
| `webui-routes-list` | `configuration/routes.md` — Enabling and disabling |
| `webui-route-edit-access` | `configuration/routes.md` — Access |
| `webui-policy-edit` | `configuration/policies.md` — Namespaces and fields |
| `webui-api-keys` | `configuration/api-keys.md` — Listing and revoking |
| `webui-cert-table` | `configuration/tls.md` — Listing and deleting certificates |
| `webui-acme-leader` | `configuration/tls.md` — HA behaviour |
| `webui-danger-zone` | `security.md` — DEK ring rotation |
| `webui-setup` | `install/docker.md` — Compose |
| `webui-route-edit-window` | landing page — "Or the same route in a browser" |

Two of the original asks are answered as text rather than images, and two
were dropped. Both decisions are recorded at the bottom.

## Capture conditions (all shots)

- **Theme:** light. The web UI hardcodes `data-theme="light"` and has no
  dark mode, so there is nothing to choose.
- **Viewport:** 1440×900, 2× DPR. Crop browser chrome — no URL bar, no
  tabs, no bookmarks. `webui-route-edit-window` is exempt; see above. The existing captures are 1728 CSS px wide rather
  than 1440; the content column is centred and fixed-width, so the extra
  is margin and crops away. Not worth a retake on its own.
- **Data:** everything visible must be disposable. `example.com`
  hostnames, RFC 5737 addresses (`192.0.2.0/24`) or RFC 1918, no real
  tenant GUIDs, no real group names. The jump hosts are fine to drive
  but not to photograph.
- **Secrets:** the management API already redacts IdP client secrets to
  `**REDACTED**` — that is worth showing rather than hiding. Do not
  capture an API key value, including the one-shot value on creation.
- **Format:** one full-resolution PNG per figure, no 1×/2× pair. The
  book scales them to the column; a second asset buys nothing and is a
  second thing to keep in step. Originals are kept outside the repo.

## What each figure had to show, and what it cost

**`webui-routes-list`** came out exactly as asked: `console`, `grafana`
and `status` enabled, `kibana` disabled, all on `example.com`. It is the
single most useful image here — it shows the core object and makes the
explicit-activation stance visible without explaining it.

**`webui-route-edit-access`** is cropped so `access.policy`, the
signed-identity toggle and the TLS mode are in one frame. That is the
"every UI is a projection of the same resource" claim, made concrete.

**`webui-route-edit-window`** is the one deliberate exception to the
crop-the-chrome rule below. The landing page is not reference material: it
has to show that this is a real product someone opens in a browser, so the
window, the title bar and the address bar are the point rather than noise.
It was captured by the owner in Safari at the top of the route editor and is
used exactly as taken — not cropped, not scaled, drop shadow included. Only
the PNG encoding was redone, and the pixels are asserted identical to the
original. It is the one figure with no 1px frame: the window supplies its own
edge, and a CSS shadow could not replace the captured one because it follows
the image box rather than the rounded corners. It is laid out at the full
content column, the same width as the shell transcript it sits under.

**`webui-cert-table` and `webui-acme-leader`** replace an ask that could
not be answered. The original was a row with source `acme`; that is not
producible here, because `source` is a field of the `Certificate` struct
and travels inside the encrypted `data` column, so it cannot be seeded by
touching the database. In production only the ACME issuance path writes
`CertSource::Acme` (`tls/acme/storage.rs`, `tls/acme/queue.rs`). Showing
one for real would mean standing up a local ACME server with a reachable
HTTP-01 challenge — disproportionate for one table row, and faking it was
not on the table. The leader-election panel is real data and is the actual
ACME story; the `upload` row is honest about what it is.

**`webui-danger-zone`** is cropped from a page 8413 px tall. The ring's
`CREATED` and `RETIRED` columns render as `—`; that is expected, not a
defect — `created_at` / `retired_at` are not carried on `MasterKeyRow`
yet, acknowledged in `api/encryption_keys.rs`. The crop is framed so the
empty columns are not the subject.

**`webui-api-keys` and `webui-policy-edit`** were each taken twice. The
first pair photographed defects the screenshots themselves exposed: the
scope checkboxes rendered as full-width empty boxes, and the policy hint
listed a DSL namespace (`session`) that does not exist while omitting two
that do. Both were fixed in code first; these are the retakes. Taking the
picture is what found them, which is an argument for doing this earlier
rather than at the end.

## Why the CLI is text, not a screenshot

**2 (`sekisho-cli` session) and 5 (`show idp` redaction) are done** — as
text blocks in the CLI section of the landing page, not images.

Commands are meant to be copied. An image forces retyping, carries no
search weight, needs 1× and 2× assets, and goes stale silently when the
CLI's wording changes. A text block can be diffed and checked in CI. The
only thing lost is terminal colour, which is decoration.

Both blocks were taken from the running binary rather than written from
memory, which caught three errors in the guides in the process:

- The prompt is `sekisho@<server-host>>` / `sekisho@<server-host>#`, not
  `sekisho>` / `sekisho#`. The host is the *daemon's*, fetched over the
  management API. (`shell/mod.rs`, and `edit_prompt` in `shell/edit.rs`,
  whose own doc comment is also missing the `@host` — worth mentioning to
  the lead, but it is source, not site.)
- `set` takes the rest of the line verbatim — `parts[2..].join(" ")`. A
  shell-style quoted policy stores the outer quotes and the backslashes,
  and the expression then fails to parse. Both guides had this.
- `show idp` on a SAML provider has no `client_secret` at all
  (`oidc_config` is null), so the redaction example has to use an OIDC
  provider. `google-workspace`, not `entra`.

## Dropped

**10. The 403 a denied user sees — the owner does not want the shot.**
When this was first attempted there was nothing to photograph: every
proxy error was a fixed JSON body and no HTML error page existed. That
has since changed — a browser now gets a small fixed page — so the
figure is capturable today.

It is still not being taken. The owner ruled it unnecessary, and
captures are the owner's own work, so this stays dropped. Do not
re-propose it.

The refusal path is covered in prose instead: the reader-facing half in
Troubleshooting, and the operator-facing half in the Grafana guide (a
`WARN` line carrying user and route, and the
`sekisho_proxy_policy_denied_total` counter).

## Not needed

- `/sessions` — a list of who is logged in is mostly PII with little to
  say visually.
- `/healthz` — it returns `ok`.
- Anything from the proxy data plane. There is nothing to see; that is
  the point.
- The `Dashboard` capture taken alongside the others is not on this list,
  but it is clean and can be used if a general "here is the UI" image is
  wanted.
