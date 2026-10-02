//! Exactly-once decoding of the inbound request target.
//!
//! Path confusion between a proxy and its upstream is the root of the
//! `%2f`-traversal and path-prefix-authz-bypass families: the proxy matches a
//! route or a policy prefix against one reading of the path, and the upstream
//! acts on another. This module removes the ambiguity by decoding the target
//! once, before anything else looks at it, and rejecting whatever could still
//! be read two ways.
//!
//! The rules, all enforced by [`canonicalize_path`]:
//!
//! - Percent escapes are decoded **once**, and an escape that would produce a
//!   structural byte (`/`, `\`, `?`, `#`, NUL, any C0 control, DEL) is
//!   rejected rather than decoded. `%2f` therefore cannot become a segment
//!   separator after we have already matched the route on it.
//! - The decoded result must contain no remaining `%XX`
//!   ([`validate_canonical_path`]). This is what makes "exactly once" hold end
//!   to end: an upstream that decodes again finds nothing left to decode, so
//!   `%252f` never gets a second round in which to become `/`.
//! - `.` and `..` segments, empty segments (`//`) and `;` path parameters are
//!   rejected outright. Normalizing them would mean choosing one of several
//!   plausible readings; refusing is the only answer that cannot diverge from
//!   whatever the upstream would have chosen.
//! - The decoded bytes must be UTF-8, so route and policy matching operate on
//!   real text rather than a lossy reconstruction.
//!
//! Validation of the decoded form and serialization back onto the wire are
//! deliberately separate steps ([`validate_canonical_path`] vs
//! [`encode_canonical_path`]): everything inside the daemon reasons about the
//! decoded path, and only the outbound URI is re-escaped.
//!
//! [`middleware`] installs the result as a [`CanonicalRequestTarget`]
//! extension and leaves `Request::uri` untouched, so the handlers that
//! legitimately need the raw target — query strings, verbatim forwarding —
//! still have it.

use axum::body::Body;
use axum::http::{Method, Request, Response, Uri};
use axum::middleware::Next;

/// Validated, exactly-once decoded proxy request path.
#[derive(Clone, Debug)]
pub(crate) struct CanonicalRequestTarget {
    path: String,
}

impl CanonicalRequestTarget {
    /// The decoded path. Contains no percent escapes; safe to compare
    /// against route prefixes and policy paths directly.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }
}

/// Why a target was refused. Kept separate from the HTTP response because
/// callers must not leak which rule fired — every variant maps to a flat
/// 400 at the edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InvalidRequestTarget {
    /// Malformed or truncated `%XX`, or a `%XX` still present after decoding.
    Escape,
    /// The decoded bytes are not valid UTF-8.
    Utf8,
    /// Structurally unusable: not rooted, a forbidden byte, a dot segment,
    /// an empty segment, or a `;` path parameter.
    UnsafePath,
}

/// Decode and validate an inbound path, yielding the one reading the rest of
/// the daemon is allowed to use.
pub(crate) fn canonicalize_path(path: &str) -> Result<String, InvalidRequestTarget> {
    if !path.starts_with('/') {
        return Err(InvalidRequestTarget::UnsafePath);
    }

    let decoded = decode_once(path, false)?;
    validate_canonical_path(&decoded)?;
    Ok(decoded)
}

/// Decode the static bytes in a regex replacement before capture expansion.
/// A percent-encoded dollar remains literal rather than becoming capture
/// syntax; capture values are appended later and are never decoded again.
pub(crate) fn decode_rewrite_template(template: &str) -> Result<String, InvalidRequestTarget> {
    decode_once(template, true)
}

/// The single percent-decoding pass shared by paths and rewrite templates.
///
/// Structural bytes are rejected at decode time rather than after, so there
/// is no window in which a decoded `/` exists as data. `escape_decoded_dollar`
/// is set only for rewrite templates: a `$` that arrived percent-encoded was
/// meant literally, and doubling it to `$$` keeps the regex crate from
/// reading it as capture syntax.
fn decode_once(raw: &str, escape_decoded_dollar: bool) -> Result<String, InvalidRequestTarget> {
    let raw = raw.as_bytes();
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        let byte = raw[index];
        if byte == b'%' {
            if index + 2 >= raw.len() {
                return Err(InvalidRequestTarget::Escape);
            }
            let high = hex(raw[index + 1]).ok_or(InvalidRequestTarget::Escape)?;
            let low = hex(raw[index + 2]).ok_or(InvalidRequestTarget::Escape)?;
            let decoded_byte = (high << 4) | low;
            if matches!(decoded_byte, 0 | b'/' | b'\\' | b'?' | b'#')
                || decoded_byte < 0x20
                || decoded_byte == 0x7f
            {
                return Err(InvalidRequestTarget::UnsafePath);
            }
            if escape_decoded_dollar && decoded_byte == b'$' {
                decoded.extend_from_slice(b"$$");
            } else {
                decoded.push(decoded_byte);
            }
            index += 3;
        } else {
            if byte == 0 || byte < 0x20 || byte == 0x7f || matches!(byte, b'\\' | b'?' | b'#') {
                return Err(InvalidRequestTarget::UnsafePath);
            }
            decoded.push(byte);
            index += 1;
        }
    }

    String::from_utf8(decoded).map_err(|_| InvalidRequestTarget::Utf8)
}

/// Validate a path whose bytes have already been decoded exactly once.
///
/// Also the gate for paths the daemon produced itself (rewrites, redirect
/// targets), which is why it re-checks the "no surviving `%XX`" rule: a
/// rewrite that reintroduces an escape would hand the upstream a second
/// decoding round.
pub(crate) fn validate_canonical_path(path: &str) -> Result<(), InvalidRequestTarget> {
    if !path.starts_with('/')
        || path.contains(';')
        || path.contains("//")
        || path.as_bytes().iter().any(|byte| {
            *byte == 0 || *byte < 0x20 || *byte == 0x7f || matches!(byte, b'\\' | b'?' | b'#')
        })
    {
        return Err(InvalidRequestTarget::UnsafePath);
    }
    if path
        .as_bytes()
        .windows(3)
        .any(|window| window[0] == b'%' && hex(window[1]).is_some() && hex(window[2]).is_some())
    {
        return Err(InvalidRequestTarget::Escape);
    }
    if path
        .split('/')
        .skip(1)
        .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(InvalidRequestTarget::UnsafePath);
    }
    Ok(())
}

/// Serialize a validated decoded path for an HTTP origin-form URI.
///
/// Re-validates first: encoding an unvalidated path would faithfully escape
/// a traversal sequence and forward it.
pub(crate) fn encode_canonical_path(path: &str) -> Result<String, InvalidRequestTarget> {
    validate_canonical_path(path)?;
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte == b'/' || is_allowed_pchar(byte) {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    Ok(encoded)
}

/// RFC 3986 `pchar` minus `;`. The exclusion is intentional: the decoded form
/// already rejects literal `;`, so emitting one here could only reintroduce a
/// path parameter the upstream might split on.
fn is_allowed_pchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b'='
                | b':'
                | b'@'
        )
}

/// Value of a single hex digit, or `None` if it is not one.
fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Outermost layer of the proxy stack: reject targets we cannot read
/// unambiguously, and attach the canonical path for everything downstream.
///
/// `CONNECT` is refused because sekisho is an origin-facing reverse proxy,
/// never a forward tunnel; accepting it would mean serving arbitrary
/// authorities. Absolute-form targets are refused for the same reason — the
/// authority must come from SNI and `Host`, not from the request line.
///
/// Rejections here are built by [`crate::proxy::handler`] rather than locally,
/// so that a refusal from the transport edge is indistinguishable from one the
/// handler emits later: same bodies, same negotiation, same security headers.
/// Nothing request-derived reaches either representation — the bodies are fixed
/// literals selected by [`crate::proxy::handler::ProxyErrorKind`] — which is
/// what makes it safe to answer before any application state exists.
pub(crate) async fn middleware(mut request: Request<Body>, next: Next) -> Response<Body> {
    // Read the preferred representation before anything can reject: this layer
    // runs ahead of routing, so the `Accept` header is the only input available
    // and it must be sampled while the request is still intact.
    let representation = crate::proxy::handler::proxy_error_representation(request.headers());
    if request.method() == Method::CONNECT {
        return crate::proxy::handler::proxy_error_response(
            crate::proxy::handler::ProxyErrorKind::RequestTargetMethodNotAllowed,
            representation,
        );
    }
    let uri = request.uri();
    if !is_origin_form(uri) {
        return crate::proxy::handler::proxy_error_response(
            crate::proxy::handler::ProxyErrorKind::RequestTargetBadRequest,
            representation,
        );
    }
    let path = match canonicalize_path(uri.path()) {
        Ok(path) => path,
        Err(_) => {
            return crate::proxy::handler::proxy_error_response(
                crate::proxy::handler::ProxyErrorKind::RequestTargetBadRequest,
                representation,
            );
        }
    };
    request
        .extensions_mut()
        .insert(CanonicalRequestTarget { path });
    next.run(request).await
}

/// Whether the target is RFC 9112 origin-form (`/path?query`). Also excludes
/// asterisk-form, which only has meaning for `OPTIONS *`.
fn is_origin_form(uri: &Uri) -> bool {
    uri.scheme().is_none()
        && uri.authority().is_none()
        && uri.path().starts_with('/')
        && uri.path() != "*"
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{StatusCode, header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn canonical_path_contract() {
        for (raw, expected) in [
            ("/", "/"),
            ("/a/", "/a/"),
            ("/%61dmin", "/admin"),
            ("/%E2%98%83", "/☃"),
            ("/%25literal", "/%literal"),
        ] {
            assert_eq!(canonicalize_path(raw).as_deref(), Ok(expected));
        }
        for raw in [
            "/%2f", "/%5c", "/%252f", "/%FF", "/%3f", "/%23", "/a?b", "/a#b", "/./", "/../",
            "/a//b", "/a;b", "/a\\b", "/%00",
        ] {
            assert!(canonicalize_path(raw).is_err(), "accepted {raw}");
        }
    }

    #[test]
    fn decoded_validation_and_uri_serialization_are_separate() {
        for (decoded, encoded) in [
            ("/100%", "/100%25"),
            ("/☃", "/%E2%98%83"),
            ("/a b", "/a%20b"),
            ("/admin/", "/admin/"),
        ] {
            assert_eq!(validate_canonical_path(decoded), Ok(()));
            assert_eq!(encode_canonical_path(decoded).as_deref(), Ok(encoded));
        }
        assert_eq!(decode_rewrite_template("/%61dmin").as_deref(), Ok("/admin"));
        assert_eq!(
            decode_rewrite_template("/%24literal").as_deref(),
            Ok("/$$literal")
        );
    }

    #[test]
    fn origin_form_contract() {
        assert!(is_origin_form(&"/a?b=c".parse().unwrap()));
        assert!(!is_origin_form(&"https://example.com/a".parse().unwrap()));
        assert!(!is_origin_form(&"*".parse().unwrap()));
    }

    #[tokio::test]
    async fn middleware_keeps_raw_uri_and_attaches_canonical_path() {
        async fn inspect(request: Request<Body>) -> Response<Body> {
            let canonical = request
                .extensions()
                .get::<CanonicalRequestTarget>()
                .expect("canonical request target");
            Response::new(Body::from(format!(
                "{}|{}",
                request.uri(),
                canonical.path()
            )))
        }
        let app = axum::Router::new()
            .fallback(inspect)
            .layer(axum::middleware::from_fn(middleware));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/%61dmin/?raw=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"/%61dmin/?raw=1|/admin/");
    }

    #[tokio::test]
    async fn middleware_rejects_invalid_targets_and_connect() {
        let app = axum::Router::new()
            .fallback(|| async { StatusCode::NO_CONTENT })
            .layer(axum::middleware::from_fn(middleware));
        for uri in [
            "/%2f",
            "/%252f",
            "/%3f",
            "/%23",
            "/a//b",
            "https://example.com/a",
            "*",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "accepted {uri}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(response.headers()[header::VARY], "Accept");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], br#"{"error":"bad request"}"#);
        }
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::CONNECT)
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()[header::VARY], "Accept");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], br#"{"error":"method not allowed"}"#);

        for (method, uri, status) in [
            (Method::GET, "/%2f", StatusCode::BAD_REQUEST),
            (
                Method::GET,
                "/.sekisho/callback/%2f",
                StatusCode::BAD_REQUEST,
            ),
            (Method::CONNECT, "/", StatusCode::METHOD_NOT_ALLOWED),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header(
                            header::ACCEPT,
                            "text/html, application/json;q=0.1; hostile=not-reflected",
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "text/html; charset=utf-8"
            );
            assert_eq!(response.headers()[header::VARY], "Accept");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(
                response
                    .headers()
                    .contains_key(header::CONTENT_SECURITY_POLICY)
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(body.contains("<main>"));
            assert!(!body.contains("hostile"));
        }
    }
}
