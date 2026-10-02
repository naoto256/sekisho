# SAML with Microsoft Entra ID

This is a complete, tested walkthrough for federating Sekisho with
Microsoft Entra ID (formerly Azure AD) over SAML 2.0. The procedure
has a few non-obvious steps; this page records all of them.

Throughout this page, replace placeholders:

- `<auth_domain>` — the hostname Sekisho uses for its own endpoints,
  e.g. `auth.example.com`.
- `<sp_object_id>` — the **Object ID** of the service principal
  representing your enterprise application (not the Application ID).
  You will obtain it in step 3.
- `<tenant_id>` — your Entra tenant GUID.

## 1. Create the Enterprise Application

In the Entra admin centre:

1. Go to **Enterprise applications** -> **New application**.
2. **Create your own application**.
3. Choose **Integrate any other application you don't find in the
   gallery (Non-gallery)**.
4. Give it a name (e.g. `Sekisho IAP`) and create.

This produces both an **Application** (in App registrations) and a
**Service principal** (the per-tenant instance of it, in Enterprise
applications). The SAML configuration lives on the service
principal.

## 2. Enable SAML SSO

1. Open the Enterprise application -> **Single sign-on**.
2. Pick **SAML**.
3. Edit **Basic SAML Configuration**:

   | Field                              | Value                                              |
   |------------------------------------|----------------------------------------------------|
   | Identifier (Entity ID)             | `https://<auth_domain>`                            |
   | Reply URL (Assertion Consumer Service) | `https://<auth_domain>/.sekisho/saml/acs`       |
   | Sign on URL                        | (optional) URL of an app you want IdP-initiated SSO to land on |
   | Logout URL                         | (optional) `https://<auth_domain>/.sekisho/saml/slo` |

   Save.

4. Edit **Attributes & Claims** if you want to send group membership.
   The default claim set already includes email; for groups, add a
   group claim and choose either security groups or all groups
   (depending on whether you intend to use group-based policies).

5. Note the **App Federation Metadata Url** under **SAML Certificates**.
   It looks like:

   ```text
   https://login.microsoftonline.com/<tenant_id>/federationmetadata/2007-06/federationmetadata.xml?appid=<application_id>
   ```

   **Important**: use the tenant-wide form **without** the `?appid=...`
   query parameter:

   ```text
   https://login.microsoftonline.com/<tenant_id>/federationmetadata/2007-06/federationmetadata.xml
   ```

   The app-scoped URL has historically been less reliable than the
   tenant-scoped one. The tenant-scoped metadata exposes all signing
   certificates the tenant publishes, which is what Sekisho needs in
   order to find the right key for assertions signed by your app.

## 3. Create an app-specific signing certificate

Entra's portal will offer to create a signing certificate for you,
but the resulting certificate is **not** automatically marked as the
preferred signing key on the service principal. As a result,
assertions can come back signed by a different key than the one
published in the per-app metadata, and signature verification fails.

The reliable fix is to create the certificate and set
`preferredTokenSigningKeyThumbprint` explicitly via Microsoft Graph.

First, find the service principal's object ID (different from the
Application ID):

```bash
az ad sp list --display-name "Sekisho IAP" \
  --query "[].{id:id, appId:appId, displayName:displayName}" -o table
```

Then create an app-specific signing certificate on the service
principal:

```bash
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/<sp_object_id>/addTokenSigningCertificate" \
  --body '{
    "displayName": "CN=Sekisho IAP signing",
    "endDateTime": "2027-04-17T00:00:00Z"
  }'
```

The response contains a `thumbprint`. Capture it.

Then set it as the preferred token signing key:

```bash
az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/<sp_object_id>" \
  --body '{
    "preferredTokenSigningKeyThumbprint": "<thumbprint from previous response>"
  }'
```

After this, every assertion the service principal issues is signed
with this certificate, and the certificate is published in the
tenant federation metadata.

## 4. Assign users

In Enterprise applications -> **Users and groups**, assign the users
and groups that should be allowed through the IdP at all. Without
assignment, Entra refuses authentication regardless of what Sekisho's
policy says.

## 5. Register the IdP in Sekisho

```text
sekisho@iap# create idp entra-id
sekisho@iap edit idp/entra-id> set type saml
sekisho@iap edit idp/entra-id> set saml-config.metadata-url https://login.microsoftonline.com/<tenant_id>/federationmetadata/2007-06/federationmetadata.xml
sekisho@iap edit idp/entra-id> set saml-config.attribute-mapping.email http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
sekisho@iap edit idp/entra-id> set saml-config.attribute-mapping.groups http://schemas.microsoft.com/ws/2008/06/identity/claims/groups
sekisho@iap edit idp/entra-id> commit
```

There is no `entity-id` or `acs-url` field to set. Both are derived at
runtime from `auth_domain` — `https://<auth_domain>` and
`https://<auth_domain>/.sekisho/saml/acs` — which is exactly what step 2
registers on the Entra side. They must match, and the SP side is not
adjustable.

If you want this to be the default IdP for routes that do not
specify one:

```text
sekisho@iap# edit sekisho
sekisho@iap edit sekisho> set default-idp-id <id of entra-id>
sekisho@iap edit sekisho> commit
```

## 6. Verify

Hit a protected route in a private browser window. You should be
redirected to `login.microsoftonline.com`, complete sign-in, and be
bounced back to your route with a session.

If something fails, see the diagnostic dumps in
[Troubleshooting](../operating/troubleshooting.md#a-saml-signature-will-not-verify) — in particular
raising `SEKISHO_LOG_LEVEL` to `debug`,
which writes the raw SAML response and the exact bytes that
signature verification was run over.

## Common failure modes

| Symptom                                            | Likely cause                                                  |
|----------------------------------------------------|---------------------------------------------------------------|
| `signature verification failed`                    | Per-app cert exists in metadata but assertion was signed by another key. Apply step 3 (`preferredTokenSigningKeyThumbprint`). |
| `unknown signing key`                              | Using the `?appid=...` metadata URL but the app is not yet published there. Switch to the tenant-wide URL. |
| `audience mismatch`                                | The Identifier (Entity ID) on the Entra side does not match `https://<auth_domain>` (the SP entity ID Sekisho derives from `auth_domain`). |
| `InResponseTo not found` after a successful login  | The pending request the response refers to is gone or does not match. It expires 10 minutes after the AuthnRequest, and it is consumed once the response validates, so a replayed or re-submitted response finds nothing. A `RelayState` that is missing, malformed or unknown, a pending entry recorded for a different flow than login, and an `InResponseTo` that does not equal the AuthnRequest ID recorded for that `RelayState` all land here too. The pending state lives in the service database, so a daemon restart on its own does not lose it. |
| Loop back to login                                 | The route's own host is not minting a cookie. Hosts do not need to be siblings of `auth_domain` — the session is carried across by a single-use handoff to the route's registered host, which sets its own cookie. Check that the target host is a registered, enabled route. |
