//! Durable ACME account capability and credential boundary.

use std::{fmt, sync::Arc, time::Duration};

use instant_acme::{Account, AccountBuilder, NewAccount};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ChallengeProvider, Error, IssuedCertificate, RenewalInformation, Result, ari, protocol,
};

const CREDENTIAL_FORMAT_VERSION: u32 = 1;

/// Opaque persisted credentials for one ACME account and directory.
///
/// The serialized envelope is zeroized when dropped. It is intentionally
/// non-cloneable and does not implement implicit formatting or serialization;
/// callers cross the persistence boundary explicitly through [`Self::as_bytes`]
/// or [`Self::into_zeroizing`].
pub struct AcmeAccountCredentials {
    encoded: Zeroizing<Vec<u8>>,
}

impl AcmeAccountCredentials {
    /// Wrap persisted opaque bytes without copying them.
    #[must_use]
    pub fn from_zeroizing(encoded: Zeroizing<Vec<u8>>) -> Self {
        Self { encoded }
    }

    /// Borrow the opaque envelope for encrypted persistence.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Transfer the opaque envelope without copying it.
    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.encoded
    }

    /// Wipe the envelope before its normal drop point.
    pub fn zeroize(&mut self) {
        self.encoded.zeroize();
    }
}

impl fmt::Debug for AcmeAccountCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeAccountCredentials")
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize)]
struct CredentialEnvelopeRef<'a> {
    format_version: u32,
    directory: &'a str,
    credentials: &'a instant_acme::AccountCredentials,
}

#[derive(Deserialize)]
struct CredentialEnvelope<'a> {
    format_version: u32,
    directory: &'a str,
    #[serde(borrow)]
    credentials: &'a RawValue,
}

struct ValidatedCredentialEnvelope {
    directory: String,
    credentials: instant_acme::AccountCredentials,
}

// Borrowed raw JSON avoids materializing secret-bearing credentials into a
// generic owned Value tree. This deliberately projects only the directory
// from instant-acme's opaque credential JSON and accepts its other fields. It
// couples restore to the pinned instant-acme 0.8 credential wire format, so
// dependency updates must re-check the typed roundtrip guard.
#[derive(Deserialize)]
struct UpstreamCredentialDirectory<'a> {
    directory: Option<&'a str>,
}

/// Authenticated ACME account used for orders and ARI polling.
///
/// Construct it with [`Self::create`] only when durable credentials are
/// missing, or restore it with [`Self::restore`] when they exist. The type is
/// intentionally non-cloneable so account ownership remains explicit.
pub struct AcmeAccount {
    inner: Account,
    directory: String,
}

impl AcmeAccount {
    /// Create a new account and return its durable opaque credentials.
    pub async fn create(
        directory: &str,
        email: Option<&str>,
    ) -> Result<(Self, AcmeAccountCredentials)> {
        let builder = Account::builder().map_err(map_instant_error)?;
        Self::create_with_builder(directory, email, builder).await
    }

    async fn create_with_builder(
        directory: &str,
        email: Option<&str>,
        builder: AccountBuilder,
    ) -> Result<(Self, AcmeAccountCredentials)> {
        let directory = normalize_directory(directory)?;
        let contacts = email
            .map(|value| vec![format!("mailto:{value}")])
            .unwrap_or_default();
        let contact_refs: Vec<&str> = contacts.iter().map(String::as_str).collect();
        let (inner, credentials) = builder
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory.clone(),
                None,
            )
            .await
            .map_err(map_instant_error)?;
        let credentials = encode_credentials(&directory, &credentials)?;
        Ok((Self { inner, directory }, credentials))
    }

    /// Restore an existing account from a moved credential capability.
    ///
    /// Invalid envelopes are rejected before the default HTTP/TLS client is
    /// constructed. Valid restores use the crypto provider selected by the
    /// host binary.
    pub async fn restore(directory: &str, credentials: AcmeAccountCredentials) -> Result<Self> {
        Self::restore_with_factory(directory, credentials, Account::builder).await
    }

    async fn restore_with_factory<F>(
        directory: &str,
        credentials: AcmeAccountCredentials,
        builder_factory: F,
    ) -> Result<Self>
    where
        F: FnOnce() -> std::result::Result<AccountBuilder, instant_acme::Error>,
    {
        let validated = validate_credentials(directory, credentials)?;
        let builder = builder_factory().map_err(map_instant_error)?;
        Self::restore_validated(validated, builder).await
    }

    async fn restore_validated(
        validated: ValidatedCredentialEnvelope,
        builder: AccountBuilder,
    ) -> Result<Self> {
        let ValidatedCredentialEnvelope {
            directory,
            credentials,
        } = validated;
        let inner = builder
            .from_credentials(credentials)
            .await
            .map_err(map_instant_error)?;
        Ok(Self { inner, directory })
    }

    /// Issue a certificate, optionally replacing a predecessor under ARI.
    pub async fn issue<C: ChallengeProvider>(
        &self,
        domain: &str,
        challenge: &Arc<C>,
        predecessor_der: Option<&[u8]>,
    ) -> Result<IssuedCertificate> {
        protocol::issue(&self.inner, domain, challenge, predecessor_der, None).await
    }

    /// Issue a certificate with an outer timeout and the same cleanup contract.
    pub async fn issue_with_timeout<C: ChallengeProvider>(
        &self,
        domain: &str,
        challenge: &Arc<C>,
        predecessor_der: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<IssuedCertificate> {
        protocol::issue(
            &self.inner,
            domain,
            challenge,
            predecessor_der,
            Some(timeout),
        )
        .await
    }

    /// Fetch renewal advice for an issued certificate.
    pub async fn renewal_info(&self, certificate_der: &[u8]) -> Result<RenewalInformation> {
        ari::renewal_info(&self.inner, certificate_der).await
    }

    /// Return the normalized directory bound to this account.
    #[must_use]
    pub fn directory(&self) -> &str {
        &self.directory
    }
}

fn validate_credentials(
    directory: &str,
    credentials: AcmeAccountCredentials,
) -> Result<ValidatedCredentialEnvelope> {
    let directory = normalize_directory(directory)?;
    let envelope: CredentialEnvelope<'_> =
        serde_json::from_slice(credentials.as_bytes()).map_err(|_| Error::InvalidCredentials)?;
    if envelope.format_version != CREDENTIAL_FORMAT_VERSION {
        return Err(Error::InvalidCredentials);
    }
    if normalize_directory(envelope.directory).map_err(|_| Error::InvalidCredentials)? != directory
    {
        return Err(Error::CredentialDirectoryMismatch);
    }
    let raw_credentials = envelope.credentials.get();
    let stored: UpstreamCredentialDirectory<'_> =
        serde_json::from_str(raw_credentials).map_err(|_| Error::InvalidCredentials)?;
    let stored = stored.directory.ok_or(Error::InvalidCredentials)?;
    let stored = normalize_directory(stored).map_err(|_| Error::InvalidCredentials)?;
    if stored != directory {
        return Err(Error::CredentialDirectoryMismatch);
    }
    let credentials =
        serde_json::from_str(raw_credentials).map_err(|_| Error::InvalidCredentials)?;
    Ok(ValidatedCredentialEnvelope {
        directory,
        credentials,
    })
}

fn normalize_directory(directory: &str) -> Result<String> {
    Url::parse(directory)
        .map(|url| url.to_string())
        .map_err(|_| Error::Internal("invalid ACME directory URL".into()))
}

fn encode_credentials(
    directory: &str,
    credentials: &instant_acme::AccountCredentials,
) -> Result<AcmeAccountCredentials> {
    let mut encoded = Zeroizing::new(Vec::new());
    serde_json::to_writer(
        &mut *encoded,
        &CredentialEnvelopeRef {
            format_version: CREDENTIAL_FORMAT_VERSION,
            directory,
            credentials,
        },
    )
    .map_err(|_| Error::Internal("failed to encode ACME account credentials".into()))?;
    Ok(AcmeAccountCredentials { encoded })
}

pub(crate) fn map_instant_error(error: instant_acme::Error) -> Error {
    match error {
        instant_acme::Error::Api(_) => Error::Rejected("ACME directory rejected request".into()),
        instant_acme::Error::Unsupported(feature) => Error::Unsupported(feature),
        instant_acme::Error::Timeout(_) => Error::Transient("ACME operation timed out".into()),
        instant_acme::Error::Crypto
        | instant_acme::Error::KeyRejected
        | instant_acme::Error::Json(_)
        | instant_acme::Error::Str(_) => Error::Internal("ACME protocol data was invalid".into()),
        _ => Error::Transient("ACME transport operation failed".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        future::Future,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use bytes::Bytes;
    use http::{Method, Request, Response, StatusCode, header};
    use http_body_util::BodyExt;
    use instant_acme::{BodyWrapper, BytesResponse, HttpClient};
    use rustls_pki_types::pem::PemObject;

    use super::*;

    struct RequestRecord {
        method: Method,
        uri: String,
        body: Bytes,
    }

    #[derive(Clone, Default)]
    struct ScriptedClient {
        responses: Arc<Mutex<VecDeque<BytesResponse>>>,
        requests: Arc<Mutex<Vec<RequestRecord>>>,
    }

    impl ScriptedClient {
        fn push(&self, response: Response<BodyWrapper<Bytes>>) {
            self.responses
                .lock()
                .unwrap()
                .push_back(BytesResponse::from(response));
        }
    }

    impl HttpClient for ScriptedClient {
        fn request(
            &self,
            request: Request<BodyWrapper<Bytes>>,
        ) -> Pin<
            Box<
                dyn Future<Output = std::result::Result<BytesResponse, instant_acme::Error>> + Send,
            >,
        > {
            let (parts, body) = request.into_parts();
            let requests = self.requests.clone();
            let response = self.responses.lock().unwrap().pop_front();
            Box::pin(async move {
                let body = body.collect().await.unwrap().to_bytes();
                requests.lock().unwrap().push(RequestRecord {
                    method: parts.method,
                    uri: parts.uri.to_string(),
                    body,
                });
                response.ok_or(instant_acme::Error::Str("unexpected request"))
            })
        }
    }

    fn response(status: StatusCode, body: impl Into<Vec<u8>>) -> Response<BodyWrapper<Bytes>> {
        Response::builder()
            .status(status)
            .body(BodyWrapper::from(body.into()))
            .unwrap()
    }

    fn directory_response() -> Response<BodyWrapper<Bytes>> {
        response(
            StatusCode::OK,
            br#"{"newNonce":"https://ca.invalid/new-nonce","newAccount":"https://ca.invalid/new-account","newOrder":"https://ca.invalid/new-order","renewalInfo":"https://ca.invalid/renewal"}"#
                .to_vec(),
        )
    }

    fn directory_without_ari_response() -> Response<BodyWrapper<Bytes>> {
        response(
            StatusCode::OK,
            br#"{"newNonce":"https://ca.invalid/new-nonce","newAccount":"https://ca.invalid/new-account","newOrder":"https://ca.invalid/new-order"}"#
                .to_vec(),
        )
    }

    fn predecessor_certificate() -> Vec<u8> {
        const RFC_9773_CERTIFICATE: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt
cGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS
BgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu
7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf
qzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B
yNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb
+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK
-----END CERTIFICATE-----
"#;
        rustls_pki_types::CertificateDer::from_pem_slice(RFC_9773_CERTIFICATE)
            .unwrap()
            .to_vec()
    }

    const RFC_9773_CERTIFICATE_ID: &str = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";

    fn order_response(replaces: Option<&str>) -> Response<BodyWrapper<Bytes>> {
        let mut value = serde_json::json!({
            "status": "pending",
            "authorizations": [],
            "error": null,
            "finalize": "https://ca.invalid/order/1/finalize",
            "certificate": null
        });
        if let Some(replaces) = replaces {
            value["replaces"] = serde_json::Value::String(replaces.into());
        }
        Response::builder()
            .status(StatusCode::CREATED)
            .header("replay-nonce", "order-nonce-2")
            .header(header::LOCATION, "https://ca.invalid/order/1")
            .body(BodyWrapper::from(serde_json::to_vec(&value).unwrap()))
            .unwrap()
    }

    fn push_order_nonce(client: &ScriptedClient) {
        client.push(
            Response::builder()
                .status(StatusCode::OK)
                .header("replay-nonce", "order-nonce")
                .body(BodyWrapper::default())
                .unwrap(),
        );
    }

    fn decoded_jws_payload(body: &[u8]) -> serde_json::Value {
        use base64::Engine;

        let jws: serde_json::Value = serde_json::from_slice(body).unwrap();
        let encoded = jws["payload"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .unwrap();
        serde_json::from_slice(&decoded).unwrap()
    }

    async fn create_with_script(client: &ScriptedClient) -> (AcmeAccount, AcmeAccountCredentials) {
        client.push(directory_response());
        client.push(
            Response::builder()
                .status(StatusCode::OK)
                .header("replay-nonce", "nonce-1")
                .body(BodyWrapper::default())
                .unwrap(),
        );
        client.push(
            Response::builder()
                .status(StatusCode::CREATED)
                .header("replay-nonce", "nonce-2")
                .header(header::LOCATION, "https://ca.invalid/account/1")
                .body(BodyWrapper::default())
                .unwrap(),
        );
        AcmeAccount::create_with_builder(
            "https://ca.invalid/directory",
            Some("operator@example.invalid"),
            Account::builder_with_http(Box::new(client.clone())),
        )
        .await
        .unwrap()
    }

    async fn restore_with_counted_factory(
        directory: &str,
        credentials: AcmeAccountCredentials,
        client: ScriptedClient,
        factory_calls: &AtomicUsize,
    ) -> Result<AcmeAccount> {
        AcmeAccount::restore_with_factory(directory, credentials, || {
            factory_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Account::builder_with_http(Box::new(client)))
        })
        .await
    }

    #[test]
    fn credential_debug_is_redacted_and_explicit_zeroize_works() {
        let secret = b"credential-sentinel".to_vec();
        let mut credentials =
            AcmeAccountCredentials::from_zeroizing(Zeroizing::new(secret.clone()));
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("credential-sentinel"));
        credentials.zeroize();
        assert!(credentials.as_bytes().iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn malformed_credentials_fail_before_network() {
        let factory_calls = AtomicUsize::new(0);
        let error = match restore_with_counted_factory(
            "https://example.invalid/directory",
            AcmeAccountCredentials::from_zeroizing(Zeroizing::new(b"not-json".to_vec())),
            ScriptedClient::default(),
            &factory_calls,
        )
        .await
        {
            Ok(_) => panic!("malformed credentials were accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::InvalidCredentials));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);

        let credentials =
            AcmeAccountCredentials::from_zeroizing(Zeroizing::new(b"not-json".to_vec()));
        let error =
            match AcmeAccount::restore("https://example.invalid/directory", credentials).await {
                Ok(_) => panic!("malformed credentials were accepted"),
                Err(error) => error,
            };
        assert!(matches!(error, Error::InvalidCredentials));
    }

    #[tokio::test]
    async fn credentials_restore_the_same_account_identity() {
        let create_client = ScriptedClient::default();
        let (created, credentials) = create_with_script(&create_client).await;
        let account_id = created.inner.id().to_owned();
        let restore_client = ScriptedClient::default();
        restore_client.push(directory_response());
        let factory_calls = AtomicUsize::new(0);
        let restored = restore_with_counted_factory(
            "https://ca.invalid/directory",
            credentials,
            restore_client.clone(),
            &factory_calls,
        )
        .await
        .unwrap();
        assert_eq!(restored.inner.id(), account_id);
        assert_eq!(restored.directory(), "https://ca.invalid/directory");
        assert_eq!(factory_calls.load(Ordering::SeqCst), 1);
        assert_eq!(restore_client.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn directory_mismatch_fails_before_network() {
        let create_client = ScriptedClient::default();
        let (_, credentials) = create_with_script(&create_client).await;
        let restore_client = ScriptedClient::default();
        let factory_calls = AtomicUsize::new(0);
        let error = match restore_with_counted_factory(
            "https://other.invalid/directory",
            credentials,
            restore_client.clone(),
            &factory_calls,
        )
        .await
        {
            Ok(_) => panic!("directory mismatch was accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::CredentialDirectoryMismatch));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(restore_client.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unsupported_credential_version_fails_before_network() {
        let create_client = ScriptedClient::default();
        let (_, credentials) = create_with_script(&create_client).await;
        let mut envelope: serde_json::Value =
            serde_json::from_slice(credentials.as_bytes()).unwrap();
        envelope["format_version"] = serde_json::Value::from(CREDENTIAL_FORMAT_VERSION + 1);
        let credentials = AcmeAccountCredentials::from_zeroizing(Zeroizing::new(
            serde_json::to_vec(&envelope).unwrap(),
        ));
        let restore_client = ScriptedClient::default();
        let factory_calls = AtomicUsize::new(0);
        let error = match restore_with_counted_factory(
            "https://ca.invalid/directory",
            credentials,
            restore_client.clone(),
            &factory_calls,
        )
        .await
        {
            Ok(_) => panic!("unsupported credential version was accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::InvalidCredentials));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(restore_client.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn nested_upstream_directory_mismatch_fails_before_network() {
        let create_client = ScriptedClient::default();
        let (_, credentials) = create_with_script(&create_client).await;
        let mut envelope: serde_json::Value =
            serde_json::from_slice(credentials.as_bytes()).unwrap();
        envelope["credentials"]["directory"] =
            serde_json::Value::String("https://attacker.invalid/directory".into());
        let credentials = AcmeAccountCredentials::from_zeroizing(Zeroizing::new(
            serde_json::to_vec(&envelope).unwrap(),
        ));
        let restore_client = ScriptedClient::default();
        let factory_calls = AtomicUsize::new(0);
        let error = match restore_with_counted_factory(
            "https://ca.invalid/directory",
            credentials,
            restore_client.clone(),
            &factory_calls,
        )
        .await
        {
            Ok(_) => panic!("nested directory mismatch was accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::CredentialDirectoryMismatch));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(restore_client.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn renewal_information_uses_unauthenticated_get_and_clamps_retry_after() {
        let client = ScriptedClient::default();
        let (account, _) = create_with_script(&client).await;
        client.push(
            Response::builder()
                .status(StatusCode::OK)
                .header(header::RETRY_AFTER, "0")
                .body(BodyWrapper::from(
                    br#"{"suggestedWindow":{"start":"2030-01-01T00:00:00Z","end":"2030-01-02T00:00:00Z"},"explanationURL":"https://ca.invalid/explanation"}"#
                        .to_vec(),
                ))
                .unwrap(),
        );
        let information = account
            .renewal_info(&predecessor_certificate())
            .await
            .unwrap();
        let RenewalInformation::Supported(advice) = information else {
            panic!("ARI-capable directory reported unsupported");
        };
        assert_eq!(advice.retry_after, Duration::from_secs(60));
        assert!(advice.window_end > advice.window_start);
        let requests = client.requests.lock().unwrap();
        let request = requests.last().unwrap();
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request.uri,
            format!("https://ca.invalid/renewal/{RFC_9773_CERTIFICATE_ID}")
        );
        assert!(request.body.is_empty());
    }

    #[tokio::test]
    async fn unsupported_ari_is_capability_aware_and_does_not_fetch() {
        let create_client = ScriptedClient::default();
        let (_, credentials) = create_with_script(&create_client).await;
        let restore_client = ScriptedClient::default();
        restore_client.push(directory_without_ari_response());
        let factory_calls = AtomicUsize::new(0);
        let account = restore_with_counted_factory(
            "https://ca.invalid/directory",
            credentials,
            restore_client.clone(),
            &factory_calls,
        )
        .await
        .unwrap();
        assert_eq!(factory_calls.load(Ordering::SeqCst), 1);
        let information = account
            .renewal_info(&predecessor_certificate())
            .await
            .unwrap();
        assert_eq!(information, RenewalInformation::Unsupported);
        assert_eq!(restore_client.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unsupported_ari_falls_back_to_one_normal_order_request() {
        let create_client = ScriptedClient::default();
        let (_, credentials) = create_with_script(&create_client).await;
        let client = ScriptedClient::default();
        client.push(directory_without_ari_response());
        let factory_calls = AtomicUsize::new(0);
        let account = restore_with_counted_factory(
            "https://ca.invalid/directory",
            credentials,
            client.clone(),
            &factory_calls,
        )
        .await
        .unwrap();
        assert_eq!(factory_calls.load(Ordering::SeqCst), 1);
        push_order_nonce(&client);
        client.push(order_response(None));
        let certificate = predecessor_certificate();
        let identifier = instant_acme::CertificateIdentifier::try_from(
            &rustls_pki_types::CertificateDer::from(certificate.as_slice()),
        )
        .unwrap()
        .into_owned();
        crate::protocol::new_order(
            &account.inner,
            &[instant_acme::Identifier::Dns(
                "service.example.invalid".into(),
            )],
            Some(&identifier),
        )
        .await
        .unwrap();
        let requests = client.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.uri == "https://ca.invalid/new-order")
                .count(),
            1
        );
        let order = requests
            .iter()
            .find(|request| request.uri == "https://ca.invalid/new-order")
            .unwrap();
        assert!(decoded_jws_payload(&order.body).get("replaces").is_none());
    }

    #[tokio::test]
    async fn supported_order_sends_and_accepts_exact_replaces_identifier() {
        let client = ScriptedClient::default();
        let (account, _) = create_with_script(&client).await;
        push_order_nonce(&client);
        client.push(order_response(Some(RFC_9773_CERTIFICATE_ID)));
        let identifier = instant_acme::CertificateIdentifier::try_from(
            &rustls_pki_types::CertificateDer::from(predecessor_certificate().as_slice()),
        )
        .unwrap()
        .into_owned();
        crate::protocol::new_order(
            &account.inner,
            &[instant_acme::Identifier::Dns("example.com".into())],
            Some(&identifier),
        )
        .await
        .unwrap();
        let requests = client.requests.lock().unwrap();
        let order = requests
            .iter()
            .find(|request| request.uri == "https://ca.invalid/new-order")
            .unwrap();
        assert_eq!(
            decoded_jws_payload(&order.body)["replaces"],
            RFC_9773_CERTIFICATE_ID
        );
    }

    #[tokio::test]
    async fn replaces_echo_mismatch_does_not_fallback_to_normal_order() {
        let client = ScriptedClient::default();
        let (account, _) = create_with_script(&client).await;
        push_order_nonce(&client);
        client.push(order_response(Some("wrong.identifier")));
        let identifier = instant_acme::CertificateIdentifier::try_from(
            &rustls_pki_types::CertificateDer::from(predecessor_certificate().as_slice()),
        )
        .unwrap()
        .into_owned();
        let error = match crate::protocol::new_order(
            &account.inner,
            &[instant_acme::Identifier::Dns("example.com".into())],
            Some(&identifier),
        )
        .await
        {
            Ok(_) => panic!("mismatched replaces echo was accepted"),
            Err(error) => error,
        };
        assert!(!matches!(error, Error::Unsupported(_)));
        assert_eq!(
            client
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request.uri == "https://ca.invalid/new-order")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn replaces_order_error_does_not_fallback_to_normal_order() {
        let client = ScriptedClient::default();
        let (account, _) = create_with_script(&client).await;
        push_order_nonce(&client);
        client.push(
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("replay-nonce", "order-nonce-2")
                .body(BodyWrapper::from(
                    br#"{"type":"urn:ietf:params:acme:error:serverInternal","detail":"unavailable","status":500}"#
                        .to_vec(),
                ))
                .unwrap(),
        );
        let identifier = instant_acme::CertificateIdentifier::try_from(
            &rustls_pki_types::CertificateDer::from(predecessor_certificate().as_slice()),
        )
        .unwrap()
        .into_owned();
        let error = match crate::protocol::new_order(
            &account.inner,
            &[instant_acme::Identifier::Dns("example.com".into())],
            Some(&identifier),
        )
        .await
        {
            Ok(_) => panic!("failed replaces order was accepted"),
            Err(error) => error,
        };
        assert!(!matches!(error, Error::Unsupported(_)));
        assert_eq!(
            client
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request.uri == "https://ca.invalid/new-order")
                .count(),
            1
        );
    }
}
