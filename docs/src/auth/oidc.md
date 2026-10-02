# OIDC

OIDC is the simplest path. If your IdP has a public discovery
document at `<issuer>/.well-known/openid-configuration`, configuration
in Sekisho is essentially just three values: issuer URL, client ID, and
client secret.

## Register Sekisho with the IdP

Create an OAuth client in your IdP. The values you typically need to
set on the IdP side:

- **Application type**: web application (confidential client).
- **Redirect URI**:
  `https://<auth_domain>/.sekisho/callback`
- **Allowed scopes**: `openid`, `email`, `profile`. Add `groups` (or
  whatever group claim your IdP uses) if you intend to use
  group-based policies.

Capture the issued client ID and client secret.

## Create the IdP in Sekisho

```text
sekisho@iap# create idp google-workspace
sekisho@iap edit idp/google-workspace> set type oidc
sekisho@iap edit idp/google-workspace> set oidc-config.issuer-url https://accounts.google.com
sekisho@iap edit idp/google-workspace> set oidc-config.client-id 1234.apps.googleusercontent.com
sekisho@iap edit idp/google-workspace> set oidc-config.client-secret <secret>
sekisho@iap edit idp/google-workspace> commit
```

The discovery document is fetched lazily on the first authentication
attempt. If you want to fail fast, trigger one yourself.

## Make it the default

Most deployments have one IdP for everything. Make it the default:

```text
sekisho@iap# edit sekisho
sekisho@iap edit sekisho> set default-idp-id <id of google-workspace>
sekisho@iap edit sekisho> commit
```

Routes that do not set their own `idp_id` will then use this one.

## Common issuer URLs

| Provider             | Issuer URL                                                   |
|----------------------|--------------------------------------------------------------|
| Google Workspace     | `https://accounts.google.com`                                |
| Microsoft Entra ID   | `https://login.microsoftonline.com/<tenant-id>/v2.0`         |
| Keycloak             | `https://<host>/realms/<realm>`                              |
| Auth0                | `https://<your-tenant>.auth0.com/`                           |

For Microsoft Entra, the OIDC route works but most enterprise
deployments end up using SAML for richer group claims; see
[SAML with Microsoft Entra ID](./saml-entra.md).

## Group claims

Group-based policies — anything that references `claim.groups` —
require the IdP to return a group claim on the ID token or userinfo
response. The exact claim name varies:

- Google Workspace: groups are not in the ID token by default. Use
  Google's directory API or the `groups` claim of a Workspace OIDC
  app with the Cloud Identity API enabled.
- Keycloak: enable the "groups" mapper on the client.

Sekisho reads whatever the IdP populates and exposes it as the
session's `groups`.

## Sign-out (RP-initiated logout)

Hitting `https://<host>/.sekisho/sign-out` always:

1. Revokes the local Sekisho session (deleted from the session store).
2. Clears the `_sekisho_session` cookie on that host.

If the session was created by an OIDC IdP that advertises an
`end_session_endpoint` in its discovery document (Entra, Keycloak,
Auth0), Sekisho then 302s the browser to that endpoint with
`id_token_hint` and `post_logout_redirect_uri=https://<host>/.sekisho/signed-out`.
The IdP ends its SSO session and redirects the browser back to
`/.sekisho/signed-out`, which serves the terminal "Signed out" page.

Without this, the IdP's SSO session survives and the next protected
request silently re-authenticates the user — the exact UX bug this
feature closes.

### IdP configuration

Entra only accepts the logout redirect if it is pre-registered as
an allowed URL. Register one entry per host that serves a Sekisho
route (including the auth domain if users ever sign out while on it):

```bash
# Entra ID
az ad app update --id <client_id> \
  --web-redirect-uris "https://<auth_domain>/.sekisho/callback" \
  --set "web.logoutUrl=https://<host>/.sekisho/signed-out"
```

### IdPs without `end_session_endpoint`

Google Workspace does not expose an RP-initiated logout endpoint in
its OIDC discovery. For those IdPs, `/.sekisho/sign-out` falls back
to the local-only behaviour (revoke + cookie clear + terminal HTML).
The IdP-side SSO session is not affected; the user stays signed in
to Google.

### SAML

SAML sessions use SAML Single Logout when the IdP supports it.
Sekisho captures the `NameID` and the `AuthnStatement/@SessionIndex`
at login precisely so it can build a `LogoutRequest` later, and
registers both the Redirect and POST bindings on
`/.sekisho/saml/slo` because IdPs differ in which they use. A session
falls back to the local-only path when the IdP's metadata advertises
no SLO endpoint, or when the stored `SessionIndex` is absent. See
[SAML](./saml.md).

## Troubleshooting

- **`invalid issuer`** — `iss` mismatch. Many IdPs put the trailing
  slash in the issuer; copy it exactly as published.
- **`no matching kid`** — JWKS rotation. Sekisho refetches automatically;
  if the error persists, the IdP is publishing a token signed by a key
  it does not advertise.
- **`nonce mismatch`** — usually a stale browser tab. Restart the flow.
- **`code expired`** — clock skew or a slow callback. Check NTP on the
  Sekisho host.

For protocol-level debugging, set `log_level` to `debug` and watch the
journal during the failing flow.
