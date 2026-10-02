# Identity Providers

An `IdentityProvider` (IdP) describes how to authenticate users
against an external identity service. Routes reference IdPs by `id`,
falling back to the global `default_idp_id` if none is set.

For full provider walkthroughs, see [Authentication](../auth/index.md).
This page is the field reference.

## Common fields

| Field          | Type     | Notes                                                        |
|----------------|----------|--------------------------------------------------------------|
| `name`         | string   | Unique identifier, used in `sekisho-cli` and logs.              |
| `type`         | enum     | `oidc` or `saml`. Cannot be changed after creation.          |
| `oidc_config`  | object   | Required when `type = oidc`. See below.                      |
| `saml_config`  | object   | Required when `type = saml`. See below.                      |

## `oidc_config`

| Field                       | Type     | Notes                                                                                  |
|-----------------------------|----------|----------------------------------------------------------------------------------------|
| `issuer_url`                | string   | OIDC issuer (e.g. `https://accounts.google.com`). Discovery happens on first use.     |
| `client_id`                 | string   | OAuth client ID.                                                                       |
| `client_secret`             | string   | Plaintext on write; returned as `**REDACTED**` on read. The at-rest field (`client_secret_encrypted`) is never exposed, and a caller that sends it has it dropped — the daemon will not accept ciphertext it cannot verify. |
| `scopes`                    | string[] | Default `["openid", "email", "profile"]`. Add `groups` if your IdP supports it.       |
| `prompt`                    | string   | Optional `prompt` parameter passed to the authorization endpoint.                     |

### Example

```text
sekisho@iap# create idp google-workspace
sekisho@iap edit idp/google-workspace> set type oidc
sekisho@iap edit idp/google-workspace> set oidc-config.issuer-url https://accounts.google.com
sekisho@iap edit idp/google-workspace> set oidc-config.client-id 1234.apps.googleusercontent.com
sekisho@iap edit idp/google-workspace> set oidc-config.client-secret <secret>
sekisho@iap edit idp/google-workspace> commit
```

The IdP's redirect URI must be `https://<auth_domain>/.sekisho/callback`.

## `saml_config`

| Field               | Type             | Notes                                                                                  |
|---------------------|------------------|----------------------------------------------------------------------------------------|
| `metadata_url`      | string           | URL of the IdP's federation metadata XML.                                              |
| `slo_url`           | string or null   | Optional Single Logout endpoint.                                                       |
| `name_id_format`    | string or null   | Override the requested NameID format.                                                  |
| `attribute_mapping` | map[string]string or null per entry | Map IdP attribute names to internal claim names (e.g. `groups`, `email`). On update, an entry whose value is `null` is **deleted** from the mapping; see [Update semantics](#update-semantics). |

The SP entity ID and ACS URL are not configurable per-IdP — the
daemon always uses `https://<auth_domain>` and
`https://<auth_domain>/.sekisho/saml/acs`. Match these on the IdP
side when registering Sekisho as a SAML SP.

See [SAML](../auth/saml.md) for what `attribute_mapping` controls,
and [SAML with Microsoft Entra ID](../auth/saml-entra.md) for a full
example.

## Editing an IdP

IdPs are created, edited and deleted from `sekisho-cli` (`create idp`,
`edit idp` in configuration mode) or from the Identity Providers page
of the web UI (`sekisho-webui`), which has the same fields in a form. Either is fine;
they are editing the same object.

One behaviour is worth knowing before you use the form: **leaving the
client-secret box empty keeps the stored secret.** It does not blank
it. That is the same rule the API follows, described under [Update
semantics](#update-semantics), and it is what makes it safe to open an
IdP, change the scopes, and save without re-typing the credential.

## Operational notes

### Secret redaction

When you `show idp <name>`, secrets are returned as the literal string
`**REDACTED**`, and the web UI leaves the secret box blank. The actual
ciphertext is never exposed. To rotate a secret, set the cleartext
value again on update.

### Update semantics

`PATCH /idps/{id}` distinguishes three states per field — absent, explicit
`null`, and a value — and what `null` means depends on the field.

**`null` is rejected** on fields the configuration cannot do without. The
response is `400` with `<field> must not be null`:

`oidc_config.issuer_url`, `oidc_config.client_id`, `oidc_config.scopes`,
`saml_config.metadata_url`, `saml_config.attribute_mapping`.

**`null` clears** the stored value on genuinely optional fields:

`oidc_config.prompt`, `saml_config.slo_url`, `saml_config.name_id_format`.

**`null` preserves** on one field, `oidc_config.client_secret`. This is the
exception to the rule above, so it is worth stating plainly:

| `client_secret` sent as | Result                  |
|-------------------------|-------------------------|
| absent                  | stored secret preserved |
| `null`                  | stored secret preserved |
| `""`                    | stored secret preserved |
| `"**REDACTED**"`        | stored secret preserved |
| any other non-empty string | secret rotated       |

The four preserving spellings exist so that a fetch, edit, and PATCH-back
round trip is safe: a client that re-sends the `**REDACTED**` it was given
does not destroy the credential. The consequence is that **a secret cannot
be cleared through the API** — only replaced. Remove the IdP if you need the
secret gone.

Within `attribute_mapping`, a `null` *entry value* deletes that entry and
leaves the rest of the map intact. This is the only way to remove a single
mapping:

```json
{ "saml_config": { "attribute_mapping": { "department": null } } }
```

A patch whose nested object ends up empty — including one that contains
nothing but a secret-preserving spelling — is discarded before anything is
encrypted or written. Such a request succeeds and changes nothing.

### Cache invalidation

Sekisho caches OIDC and SAML clients (with their fetched JWKS /
metadata) per IdP. The cache is invalidated automatically whenever
any IdP is created, updated, or deleted. You do not need to restart
the daemon when changing IdP configuration.

### Referential integrity

Deleting an IdP that something still points at is refused with
`409 Conflict`. Two references are checked:

- the global `default_idp_id`, and
- any route's `idp_id`.

Clear or repoint the reference first, then delete. No manual pre-check is
needed — a dangling `idp_id` is not a state the daemon will let you reach.
