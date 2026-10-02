# SAML

SAML 2.0 is the second supported protocol. Sekisho acts as a SAML
**Service Provider (SP)** and authenticates users against an IdP that
posts back signed assertions to the ACS endpoint.

This page covers the protocol-level details. For a complete
end-to-end walkthrough against a real IdP, see
[SAML with Microsoft Entra ID](./saml-entra.md).

## SP endpoints

When you create a SAML IdP in Sekisho, the SP-side endpoints are:

| Purpose                       | URL                                                  |
|-------------------------------|------------------------------------------------------|
| Assertion Consumer Service    | `https://<auth_domain>/.sekisho/saml/acs`             |
| Single Logout (optional)      | `https://<auth_domain>/.sekisho/saml/slo`             |
| SP entity ID                  | `https://<auth_domain>` — derived, not configurable  |

The ACS URL must be registered with the IdP exactly as above.

## What is signed and what is verified

Sekisho verifies the XML signature on **either** the SAML response
**or** the assertion (whichever the IdP signs). The verification:

- Uses the X.509 certificate published in the IdP's federation
  metadata.
- Applies Exclusive XML Canonicalization (`xml-exc-c14n#`, without
  comments) to the parsed DOM before computing the digest.
- Is unconditional — there is no path through the parser that skips
  signature validation, even on debug builds.

Signature algorithms accepted: RSA with SHA-256, SHA-384 or SHA-512
(`rsa-sha256`, `rsa-sha384`, `rsa-sha512`). **RSA-SHA1 is refused**
with an explicit error rather than being accepted for compatibility;
an IdP still signing with SHA-1 must be reconfigured.

In addition to the signature, Sekisho checks:

- `Issuer` matches the configured IdP.
- `Conditions/NotBefore` and `NotOnOrAfter` (with a small clock-skew
  tolerance).
- `Conditions/AudienceRestriction/Audience` matches the SP entity ID.
- `InResponseTo` matches an outstanding `AuthnRequest` ID generated
  by Sekisho.
- The XML stream contains no DTD or external entities (XXE-safe;
  DTDs are rejected by the parser).

## Field reference

```json
{
  "metadata_url":      "https://idp.example.com/federationmetadata.xml",
  "slo_url":           null,
  "name_id_format":    null,
  "attribute_mapping": {
    "email":  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "groups": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
  }
}
```

The SP's entity ID and ACS URL are **derived at runtime** from the
daemon's `auth_domain` global config — they are always
`https://<auth_domain>` and `https://<auth_domain>/.sekisho/saml/acs`
respectively and cannot be overridden per-IdP.

`attribute_mapping` is a map from **internal claim name** (left) to
**SAML attribute name as sent by the IdP** (right). The internal
names that drive policy evaluation are:

| Internal name | Used for                                    |
|---------------|---------------------------------------------|
| `email`       | The user's email (also exposed as `X-Sekisho-User`). |
| `groups`      | Group membership (exposed to policy expressions as `claim.groups`). |
| `name`        | Display name (informational).               |

Any additional attributes the IdP sends are kept in the session and are
available to policy expressions as `claim.<name>`. They are **not** copied
into `X-Sekisho-Jwt` — that token carries a fixed claim set; see
[Routes](../configuration/routes.md#identity-headers).

## AuthnRequest

Sekisho sends a SAML 2.0 redirect-binding `AuthnRequest`:

- `ProtocolBinding`: HTTP-POST.
- `ID`: a UUIDv4 with a configured prefix, single-use, 10-minute TTL.
- `IsPassive`: false.
- `ForceAuthn`: false.
- `RequestedAuthnContext`: not set (let the IdP choose).

If `name_id_format` is set on the IdP config, it is included in the
request.

## Diagnostics

Set `SEKISHO_LOG_LEVEL=debug` and retry the flow; the verifier names the
specific check that failed. There is no dump-to-disk switch — the one that
earlier releases shipped was removed. See
[Troubleshooting](../operating/troubleshooting.md#a-saml-signature-will-not-verify).
