//! WebSocket upgrade detection and bidirectional tunneling.
//!
//! A separate path from ordinary proxying, because the two want opposite
//! things from the same headers: `Connection` and `Upgrade` are hop-by-hop and
//! must be stripped from a forwarded request, but they *are* the handshake
//! here. So this module does not run the standard transform pipeline. It calls
//! the identity and forwarding transforms explicitly, strips the client's
//! spoofable headers first, and then builds a fresh handshake toward the
//! upstream rather than relaying the downstream one.
//!
//! The consequence worth remembering when adding a transform: a new identity
//! or forwarding rule added to [`super::transform::default_pipeline`] does
//! **not** reach WebSocket requests until it is also added to the explicit
//! list here.
//!
//! ## Budget and timeouts
//!
//! A tunnel takes a permit from [`super::WebSocketBudget`] before the upstream
//! connection is opened, and holds it for the tunnel's life. The route's
//! `timeout_ms` bounds the handshake only — an established tunnel is
//! deliberately unbounded, since an idle interactive session (a terminal left
//! open) is normal rather than a fault, and the permit is what limits how many
//! of those can exist.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use metrics::{counter, gauge, histogram};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::OwnedSemaphorePermit;

use crate::models::route::Route;

use super::ObservedWebSocketPermit;
use super::handler::build_upstream_uri;
use super::header_boundary::WebSocketHandshake;
use super::transform::{
    AddIdentityHeaders, AddProxyHeaders, AddSignedIdentityToken, RequestTransform,
    TransformContext, strip_session_cookie,
};

/// Handle a WebSocket upgrade: connect to upstream, perform handshake,
/// and establish a bidirectional tunnel.
///
/// Identity, proxy, and route header transforms are applied
/// explicitly here rather than via the regular `TransformPipeline`. The
/// boundary classifier records the validated handshake on the request, and
/// this path removes downstream hop authority before pinning the new upstream
/// connection and applying trusted identity and forwarding transforms.
pub(super) async fn handle_websocket(
    mut req: Request<Body>,
    upstream_base: &str,
    route: &Route,
    ctx: &TransformContext<'_>,
    ctl: &Arc<crate::shutdown::ShutdownController>,
    route_permit: &mut Option<OwnedSemaphorePermit>,
    websocket_permit: ObservedWebSocketPermit,
) -> Result<Response<Body>, StatusCode> {
    let websocket_handshake = req
        .extensions_mut()
        .remove::<WebSocketHandshake>()
        .ok_or(StatusCode::BAD_REQUEST)?;
    // Extract the client's OnUpgrade before consuming the request.
    let client_on_upgrade = req
        .extensions_mut()
        .remove::<hyper::upgrade::OnUpgrade>()
        .ok_or_else(|| {
            tracing::error!("no upgrade extension on client request");
            StatusCode::BAD_REQUEST
        })?;

    let upstream_uri = build_upstream_uri(upstream_base, req.uri())?;
    let upstream_url =
        url::Url::parse(&upstream_uri.to_string()).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let host = upstream_url.host_str().ok_or(StatusCode::BAD_GATEWAY)?;
    let default_port = if upstream_url.scheme() == "https" {
        443
    } else {
        80
    };
    let port = upstream_url.port().unwrap_or(default_port);
    let addr = format!("{host}:{port}");

    // Bound the handshake phase by route.timeout_ms. The bidirectional tunnel
    // that follows is intentionally unbounded — that's the point of WebSocket.
    let handshake_timeout = std::time::Duration::from_millis(route.timeout_ms);
    let (mut parts, body) = req.into_parts();

    prepare_websocket_request_headers(&mut parts, route, ctx);
    let upstream_req = Request::from_parts(parts, body);

    let upstream_is_tls = upstream_url.scheme() == "https";
    let route_skip_verify = route.tls_skip_verify;
    let server_name_owned = host.to_string();

    let handshake = async {
        let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(|e| {
            tracing::error!(error = %e, route = %route.name, "failed to connect to upstream for websocket");
            StatusCode::BAD_GATEWAY
        })?;
        // Disable Nagle on the upstream socket. A WebSocket tunnel
        // carries interactive payloads (keystrokes, mouse events,
        // terminal echo, etc.) as tiny frames. With Nagle on AND a
        // peer whose stack uses long delayed-ACK, sekisho holds the
        // second small frame waiting for an ACK of the first, while
        // the peer holds the ACK waiting to piggyback on outgoing
        // data — a classic deadlock that surfaces as "interactive
        // input wedges until another session generates traffic on
        // the same connection". Setting NODELAY is the standard fix
        // for interactive proxies; the cost is a slight uptick in
        // small-packet count that is irrelevant for a WS tunnel
        // that's already framed at the application layer. We swallow
        // the error: if the kernel refuses (very rare; would only
        // happen on an OS without TCP_NODELAY at all), the tunnel
        // still works, just laggily — same as before this fix.
        let _ = tcp.set_nodelay(true);
        // Wrap in TLS if upstream is HTTPS. Without this, a wss://
        // route to a TLS upstream would speak plain HTTP/1.1 to a
        // TLS port and never receive a 101 Switching Protocols.
        // Honour `tls_skip_verify` so self-signed device certs work
        // the same as on the ordinary proxy path.
        if upstream_is_tls {
            let stream = tls_connect(tcp, &server_name_owned, route_skip_verify)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, route = %route.name, host = %server_name_owned, "websocket upstream TLS handshake failed");
                    StatusCode::BAD_GATEWAY
                })?;
            run_handshake(stream, upstream_req).await
        } else {
            run_handshake(tcp, upstream_req).await
        }
    };

    let upstream_resp = match tokio::time::timeout(handshake_timeout, handshake).await {
        Ok(res) => res?,
        Err(_) => {
            tracing::warn!(
                route = %route.name,
                timeout_ms = route.timeout_ms,
                "websocket upstream handshake timed out"
            );
            return Err(StatusCode::GATEWAY_TIMEOUT);
        }
    };

    if upstream_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Non-101 upstream reply on the WebSocket path: the parsed
        // upstream response `parts` and `hyper::body::Incoming` body
        // are rewrapped directly into the returned `Response<Body>`.
        // Apply the connection-boundary sanitization used by the regular
        // HTTP path, then explicitly apply Via and Location immediately
        // afterward because the shared sanitizer owns only hop fields.
        let (mut parts, incoming) = upstream_resp.into_parts();
        super::header_boundary::sanitize_hop_by_hop(&mut parts.headers);
        super::header_boundary::append_via(&mut parts.headers, parts.version);
        super::transform::rewrite_response_location(&mut parts.headers, route, ctx.client_host);
        return Ok(Response::from_parts(parts, Body::new(incoming)));
    }

    // Snapshot upstream's 101 response headers BEFORE consuming the
    // response into `hyper::upgrade::on`. RFC 6455 §4.1 requires the
    // server's reply to carry `Sec-WebSocket-Accept` — derived from
    // the client's `Sec-WebSocket-Key` plus the WebSocket magic
    // string — and the client MUST close the connection if it's
    // missing or wrong. Plus `Sec-WebSocket-Protocol` (subprotocol
    // negotiation) and `Sec-WebSocket-Extensions` (per-message-deflate
    // etc.) need to flow through verbatim. Synthesizing our own 101
    // with just Connection / Upgrade made the browser reject every
    // upstream and surfaced as "WebSocket connects then immediately
    // closes".
    let upstream_version = upstream_resp.version();
    let mut upstream_headers = upstream_resp.headers().clone();
    super::header_boundary::sanitize_switching_response(
        &mut upstream_headers,
        &websocket_handshake,
        upstream_version,
    )?;

    let upstream_upgraded =
        match tokio::time::timeout(handshake_timeout, hyper::upgrade::on(upstream_resp)).await {
            Ok(Ok(u)) => u,
            Ok(Err(e)) => {
                tracing::error!(error = %e, "upstream upgrade failed");
                return Err(StatusCode::BAD_GATEWAY);
            }
            Err(_) => {
                tracing::warn!(
                    route = %route.name,
                    timeout_ms = route.timeout_ms,
                    "websocket upstream upgrade timed out"
                );
                return Err(StatusCode::GATEWAY_TIMEOUT);
            }
        };

    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *resp.headers_mut() = upstream_headers;

    // Spawn bidirectional tunnel: client <-> upstream.
    //
    // Holding a `WsGuard` for the tunnel's lifetime lets the graceful
    // shutdown path poll `ws_inflight()` and drain before tearing the
    // process down. `shutdown_rx` gives us a cancellation handle so a
    // tunnel with no traffic doesn't block drain for the full WS grace
    // window — when the daemon is draining we stop waiting for the
    // client upgrade or the copy and let the guard drop.
    let tunnel_lease = WsTunnelLease::new(
        route.name.clone(),
        ctl.ws_guard(),
        route_permit.take(),
        Some(websocket_permit),
    );
    let shutdown = ctl.subscribe();
    let route_name = route.name.clone();
    counter!(
        "sekisho_ws_tunnels_total",
        "route" => route_name.clone(),
        "result" => "started"
    )
    .increment(1);
    let client_upgrade = async move { client_on_upgrade.await.map(hyper_util::rt::TokioIo::new) };
    let upstream_io = hyper_util::rt::TokioIo::new(upstream_upgraded);
    tokio::spawn(run_websocket_tunnel(
        client_upgrade,
        upstream_io,
        shutdown,
        tunnel_lease,
    ));

    Ok(resp)
}

/// Rebuild the request header set for the upstream leg of an upgrade.
///
/// A WebSocket handshake is an ordinary HTTP request until the 101 comes back,
/// so it needs exactly the same boundary treatment as a proxied request: strip
/// what the client must not assert, then have the proxy assert it. Keeping
/// that as its own function rather than reusing the transform chain wholesale
/// is what the handshake requires — [`super::header_boundary::
/// sanitize_websocket_request`] has to run between the strip and the additions,
/// because the upgrade fields are simultaneously hop-by-hop (so the generic
/// sanitiser would drop them) and load-bearing (so they must survive).
///
/// The ordering is the invariant: strip, sanitise, assert, then route headers
/// last so an operator's configured header cannot displace an identity field.
/// `Via` is appended at the end, after everything that could change the
/// message it describes.
fn prepare_websocket_request_headers(
    parts: &mut axum::http::request::Parts,
    route: &Route,
    ctx: &TransformContext<'_>,
) {
    // Strip client-supplied identity and forwarding authority, then remove
    // downstream hop authority and pin the new upstream WS connection.
    super::header_boundary::strip_client_proxy_owned_headers(&mut parts.headers);
    strip_session_cookie(&mut parts.headers, ctx.session_cookie_name);
    super::header_boundary::sanitize_websocket_request(&mut parts.headers);

    // Re-inject the trusted forms (X-Forwarded-* + Forwarded, plus identity
    // headers and the signed JWT when the route opts in).
    AddProxyHeaders.apply(parts, route, ctx);
    AddIdentityHeaders.apply(parts, route, ctx);
    AddSignedIdentityToken.apply(parts, route, ctx);

    // Apply permitted route header operations before appending the
    // proxy-owned Via field. Reserved fields are skipped.
    apply_route_headers(&mut parts.headers, route);
    super::header_boundary::append_via(&mut parts.headers, parts.version);
}

struct WsTunnelLease {
    route: String,
    started: std::time::Instant,
    outcome: &'static str,
    _ws_guard: crate::shutdown::WsGuard,
    _route_permit: Option<OwnedSemaphorePermit>,
    _websocket_permit: Option<ObservedWebSocketPermit>,
}

impl WsTunnelLease {
    fn new(
        route: String,
        ws_guard: crate::shutdown::WsGuard,
        route_permit: Option<OwnedSemaphorePermit>,
        websocket_permit: Option<ObservedWebSocketPermit>,
    ) -> Self {
        gauge!("sekisho_ws_active").increment(1.0);
        Self {
            route,
            started: std::time::Instant::now(),
            outcome: "cancelled",
            _ws_guard: ws_guard,
            _route_permit: route_permit,
            _websocket_permit: websocket_permit,
        }
    }

    fn set_outcome(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
}

impl Drop for WsTunnelLease {
    fn drop(&mut self) {
        gauge!("sekisho_ws_active").decrement(1.0);
        histogram!(
            "sekisho_proxy_websocket_connection_duration_seconds",
            "route" => self.route.clone(),
            "outcome" => self.outcome
        )
        .record(self.started.elapsed().as_secs_f64());
    }
}

async fn run_websocket_tunnel<F, C, U, E>(
    client_upgrade: F,
    mut upstream_io: U,
    mut shutdown: crate::shutdown::ShutdownSignal,
    mut lease: WsTunnelLease,
) where
    F: std::future::Future<Output = Result<C, E>>,
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
    E: std::fmt::Display,
{
    let mut client_io = match wait_for_client_upgrade(client_upgrade, &mut shutdown).await {
        Some(Ok(upgraded)) => upgraded,
        Some(Err(e)) => {
            lease.set_outcome("upgrade_error");
            tracing::error!(error = %e, "client websocket upgrade failed");
            return;
        }
        None => {
            lease.set_outcome("shutdown");
            tracing::debug!("websocket upgrade wait terminated by shutdown");
            return;
        }
    };

    let copy_result =
        match copy_until_shutdown(&mut client_io, &mut upstream_io, &mut shutdown).await {
            Some(result) => result,
            None => {
                lease.set_outcome("shutdown");
                // The TCP sockets on both ends close when the IO
                // values drop, which peers surface as EOF.
                tracing::debug!("websocket tunnel terminated by shutdown");
                return;
            }
        };

    match copy_result {
        Ok((client_to_upstream, upstream_to_client)) => {
            lease.set_outcome("closed");
            tracing::debug!(
                client_to_upstream,
                upstream_to_client,
                "websocket tunnel closed normally"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            lease.set_outcome("closed");
            // Many embedded device web stacks close TCP without sending
            // the TLS close_notify alert that rustls strictly requires.
            tracing::debug!(
                "websocket tunnel closed by upstream without TLS close_notify (normal for embedded servers)"
            );
        }
        Err(e) => {
            lease.set_outcome("io_error");
            tracing::debug!(error = %e, "websocket tunnel closed");
        }
    }
}

async fn wait_for_client_upgrade<F, T, E>(
    upgrade: F,
    shutdown: &mut crate::shutdown::ShutdownSignal,
) -> Option<Result<T, E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        _ = shutdown.wait() => None,
        result = upgrade => Some(result),
    }
}

async fn copy_until_shutdown<A, B>(
    client: &mut A,
    upstream: &mut B,
    shutdown: &mut crate::shutdown::ShutdownSignal,
) -> Option<std::io::Result<(u64, u64)>>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        biased;
        _ = shutdown.wait() => None,
        result = tokio::io::copy_bidirectional(client, upstream) => Some(result),
    }
}

/// Mirror of `proxy::transform::ApplyRouteHeaders` for the
/// WebSocket path, which short-circuits the regular transform
/// pipeline. Operationally critical for upstreams that gate even
/// the WS upgrade behind Basic auth.
fn apply_route_headers(headers: &mut axum::http::HeaderMap, route: &Route) {
    use axum::http::header::{HeaderName, HeaderValue};
    for (key, value) in &route.headers.add {
        if super::header_boundary::is_reserved_route_header(key) {
            continue;
        }
        if let (Ok(k), Ok(v)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(k, v);
        }
    }
    for key in &route.headers.remove {
        if super::header_boundary::is_reserved_route_header(key) {
            continue;
        }
        if let Ok(k) = HeaderName::from_bytes(key.as_bytes()) {
            headers.remove(k);
        }
    }
}

/// Drive the HTTP/1 upgrade handshake to upstream over `stream`,
/// returning the upstream's response so the caller can inspect
/// status / extract the upgraded connection. Generic over the
/// stream type so the same body works for plain TCP and TLS-wrapped
/// streams.
async fn run_handshake<S>(
    stream: S,
    upstream_req: Request<Body>,
) -> Result<Response<hyper::body::Incoming>, StatusCode>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "upstream websocket handshake failed");
                StatusCode::BAD_GATEWAY
            })?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::error!(error = %e, "upstream connection error");
        }
    });
    sender.send_request(upstream_req).await.map_err(|e| {
        tracing::error!(error = %e, "upstream websocket request failed");
        StatusCode::BAD_GATEWAY
    })
}

/// TLS-wrap a TCP stream toward an upstream. When `skip_verify` is
/// true — the route explicitly opted out via `tls_skip_verify` —
/// upstream server authentication is disabled and the connection is
/// accepted regardless of certificate. On the default
/// `skip_verify = false` path, trust roots come from the compiled-in
/// `webpki_roots::TLS_SERVER_ROOTS` (see the inline comment on the
/// verify branch below).
async fn tls_connect(
    tcp: tokio::net::TcpStream,
    server_name: &str,
    skip_verify: bool,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, std::io::Error> {
    let config = upstream_tls_client_config(skip_verify)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let dns = tokio_rustls::rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    connector.connect(dns, tcp).await
}

fn upstream_tls_client_config(
    skip_verify: bool,
) -> Result<tokio_rustls::rustls::ClientConfig, std::io::Error> {
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    let config = if skip_verify {
        // Custom verifier that accepts everything. Same posture as
        // reqwest's `danger_accept_invalid_certs(true)`. Only used
        // when the route opts in via `tls_skip_verify`.
        ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|error| {
            std::io::Error::other(format!("build upstream TLS client config: {error}"))
        })?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth()
    } else {
        // Verify path: the trust anchors are the compiled-in
        // `webpki_roots::TLS_SERVER_ROOTS` (Mozilla-derived set). The
        // OS trust store is not consulted, so a CA installed via
        // `update-ca-certificates` on Linux, or a certificate added
        // to the macOS / Windows keychains, is not visible on this
        // path.
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|error| {
            std::io::Error::other(format!("build upstream TLS client config: {error}"))
        })?
        .with_root_certificates(roots)
        .with_no_client_auth()
    };
    Ok(config)
}

/// Cert verifier that accepts every server certificate. Wired in
/// only when the route has `tls_skip_verify=true`. Lives here rather
/// than in a shared util because the rest of the codebase reaches
/// for `reqwest::Client::danger_accept_invalid_certs` for the same
/// purpose; keeping the websocket path's equivalent next to it makes
/// the security exception easy to grep for.
#[derive(Debug)]
struct NoVerify;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        use tokio_rustls::rustls::SignatureScheme as S;
        vec![
            S::RSA_PKCS1_SHA256,
            S::RSA_PKCS1_SHA384,
            S::RSA_PKCS1_SHA512,
            S::ECDSA_NISTP256_SHA256,
            S::ECDSA_NISTP384_SHA384,
            S::ECDSA_NISTP521_SHA512,
            S::RSA_PSS_SHA256,
            S::RSA_PSS_SHA384,
            S::RSA_PSS_SHA512,
            S::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_verified_tls_client_config_with_explicit_provider() {
        assert!(upstream_tls_client_config(false).is_ok());
    }

    #[test]
    fn builds_skip_verify_tls_client_config_with_explicit_provider() {
        assert!(upstream_tls_client_config(true).is_ok());
    }

    /// An upgrade must not be a hole in the header boundary. The request here
    /// carries every shape of forgery at once — an unknown `X-Sekisho-*`, an
    /// unknown `X-Forwarded-*`, a known forwarding field with an attacker's
    /// value, an RFC 7239 `Forwarded`, a nominated hop-by-hop field, and the
    /// session cookie — alongside the handshake fields that have to survive
    /// and an ordinary header that must be left alone.
    #[test]
    fn websocket_request_strips_untrusted_prefixes_before_rebuilding_trusted_boundary() {
        let req: axum::http::Request<()> = axum::http::Request::builder()
            .uri("/")
            .version(axum::http::Version::HTTP_11)
            .header("connection", "upgrade, x-hop")
            .header("upgrade", "websocket")
            .header("x-hop", "drop")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-version", "13")
            .header("x-sekisho-future-claim", "forged")
            .header("x-forwarded-future-hop", "forged")
            .header("x-forwarded-host", "evil.example")
            .header("forwarded", "for=attacker;host=evil.example")
            .header("cookie", "_sekisho_session=secret; app=keep")
            .header("x-safe", "keep")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let identity_key_ring = crate::crypto::IdentityKeyRingSnapshot::from_test_bytes([0; 32]);
        let ctx = TransformContext {
            tls_enabled: true,
            client_host: "app.example.com",
            client_ip: Some("192.0.2.10"),
            session: None,
            prepared_identity_claims: None,
            identity_key_ring: identity_key_ring.as_ref(),
            session_cookie_name: "_sekisho_session",
        };
        let route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::nil(),
            "name": "r",
            "from": "https://app.example.com",
            "to": ["http://backend.example.com:80"],
            "created_at": chrono::Utc::now(),
            "updated_at": chrono::Utc::now(),
        }))
        .unwrap();

        prepare_websocket_request_headers(&mut parts, &route, &ctx);

        assert!(parts.headers.get("x-sekisho-future-claim").is_none());
        assert!(parts.headers.get("x-forwarded-future-hop").is_none());
        assert!(parts.headers.get("x-hop").is_none());
        assert_eq!(parts.headers["connection"], "Upgrade");
        assert_eq!(parts.headers["upgrade"], "websocket");
        assert!(parts.headers.get("sec-websocket-key").is_some());
        assert!(parts.headers.get("sec-websocket-version").is_some());
        assert_eq!(parts.headers["x-forwarded-host"], "app.example.com");
        assert_eq!(parts.headers["x-forwarded-for"], "192.0.2.10");
        assert_eq!(parts.headers["x-forwarded-proto"], "https");
        assert!(
            !parts.headers["forwarded"]
                .to_str()
                .unwrap()
                .contains("attacker")
        );
        assert_eq!(parts.headers["cookie"], "app=keep");
        assert_eq!(parts.headers["x-safe"], "keep");
        assert_eq!(parts.headers[axum::http::header::VIA], "1.1 sekisho");
    }

    #[tokio::test]
    async fn pre_signalled_shutdown_ends_client_upgrade_wait_and_drops_ws_guard() {
        let ctl = Arc::new(crate::shutdown::ShutdownController::new());
        let lease = WsTunnelLease::new("_test".into(), ctl.ws_guard(), None, None);
        ctl.signal();
        let shutdown = ctl.subscribe();
        let (upstream_io, _upstream_peer) = tokio::io::duplex(64);
        let task = tokio::spawn(run_websocket_tunnel(
            std::future::pending::<Result<tokio::io::DuplexStream, std::io::Error>>(),
            upstream_io,
            shutdown,
            lease,
        ));

        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("pre-signalled upgrade wait did not stop")
            .expect("upgrade wait task panicked");
        assert_eq!(ctl.ws_inflight(), 0, "WebSocket guard was not dropped");
    }

    #[tokio::test]
    async fn shutdown_ends_bidirectional_copy() {
        let ctl = Arc::new(crate::shutdown::ShutdownController::new());
        let lease = WsTunnelLease::new("_test".into(), ctl.ws_guard(), None, None);
        let shutdown = ctl.subscribe();
        let (client, _client_peer) = tokio::io::duplex(64);
        let (upstream, _upstream_peer) = tokio::io::duplex(64);
        let task = tokio::spawn(run_websocket_tunnel(
            async move { Ok::<_, std::io::Error>(client) },
            upstream,
            shutdown,
            lease,
        ));

        tokio::task::yield_now().await;
        ctl.signal();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("copy phase did not stop")
            .expect("copy task panicked");
        assert_eq!(ctl.ws_inflight(), 0, "WebSocket guard was not dropped");
    }

    #[tokio::test]
    async fn tunnel_holds_route_and_websocket_permits_until_shutdown() {
        let ctl = Arc::new(crate::shutdown::ShutdownController::new());
        let route = Arc::new(tokio::sync::Semaphore::new(1));
        let websocket = super::super::WebSocketBudget::new(1);
        let lease = WsTunnelLease::new(
            "test-route".into(),
            ctl.ws_guard(),
            Some(route.clone().try_acquire_owned().unwrap()),
            Some(websocket.try_acquire().unwrap()),
        );
        let shutdown = ctl.subscribe();
        let (upstream, _upstream_peer) = tokio::io::duplex(64);
        let task = tokio::spawn(run_websocket_tunnel(
            std::future::pending::<Result<tokio::io::DuplexStream, std::io::Error>>(),
            upstream,
            shutdown,
            lease,
        ));
        tokio::task::yield_now().await;
        assert_eq!(route.available_permits(), 0);
        assert_eq!(websocket.0.available_permits(), 0);

        ctl.signal();
        task.await.expect("tunnel task");
        assert_eq!(route.available_permits(), 1);
        assert_eq!(websocket.0.available_permits(), 1);
        assert_eq!(ctl.ws_inflight(), 0);
    }
}
