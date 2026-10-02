//! Concrete HTTP connection-boundary rules shared by proxy paths.
//!
//! One module for every rule about which headers belong to a *connection*
//! rather than to a message, so the HTTP path, the WebSocket path and the
//! admission validator all answer from the same list. Three copies of "which
//! headers are hop-by-hop" is how a proxy ends up stripping a header on one
//! path and forwarding it on another, which is the shape of most request
//! smuggling.
//!
//! Two distinct jobs live here, and it is worth keeping them apart:
//!
//! - **Connection hygiene** (`sanitize_*`, `append_via`) — RFC 7230 §6.1
//!   requires hop-by-hop headers not to cross a connection boundary. Applied
//!   symmetrically to requests and responses.
//! - **Ownership** ([`is_reserved_route_header`]) — the set of headers route
//!   config may not touch, in either direction. It covers HTTP framing, the
//!   `x-forwarded-` and `x-sekisho-` prefixes and the WebSocket handshake.
//!   Blocking *removal* matters as much as blocking addition: a route that
//!   could drop `X-Sekisho-User` on the way out would be an authentication
//!   bypass from the upstream's point of view.
//!
//! Prefix matching rather than an exhaustive name list, so a header added to
//! either family later is covered without anyone remembering to update this.

use axum::body::Body;
use axum::http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Version, header,
};
use base64::Engine as _;

const STATIC_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Clone)]
pub(super) struct WebSocketHandshake {
    client_key: HeaderValue,
}

impl WebSocketHandshake {
    pub(super) fn client_key(&self) -> &str {
        self.client_key
            .to_str()
            .expect("validated WebSocket key is visible ASCII")
    }
}

/// Classify a downstream request without treating malformed upgrade attempts
/// as ordinary HTTP. A request carrying any WebSocket handshake field is
/// either a complete RFC 6455 handshake or a fixed-safe 400.
pub(super) fn classify_websocket_request(
    request: &Request<Body>,
) -> Result<Option<WebSocketHandshake>, StatusCode> {
    let headers = request.headers();
    let attempted = headers.contains_key(header::UPGRADE)
        || headers.contains_key("sec-websocket-key")
        || headers.contains_key("sec-websocket-version")
        || connection_has_token(headers, "upgrade");
    if !attempted {
        return Ok(None);
    }
    if request.method() != Method::GET || request.version() != Version::HTTP_11 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !connection_has_token(headers, "upgrade")
        || !has_exact_single_token_value(headers, header::UPGRADE, "websocket")
        || !has_exact_single_token_value(headers, "sec-websocket-version", "13")
        || connection_nominates_websocket_metadata(headers)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = exact_single_value(headers, "sec-websocket-key").ok_or(StatusCode::BAD_REQUEST)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key.as_bytes())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if decoded.len() != 16 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Some(WebSocketHandshake {
        client_key: key.clone(),
    }))
}

pub(super) fn validate_upstream_switching_response(
    headers: &HeaderMap,
    handshake: &WebSocketHandshake,
) -> Result<(), StatusCode> {
    if !connection_has_token(headers, "upgrade")
        || !has_exact_single_token_value(headers, header::UPGRADE, "websocket")
        || connection_nominates_websocket_metadata(headers)
    {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let expected = websocket_accept(handshake.client_key());
    if !has_exact_single_octets(headers, "sec-websocket-accept", expected.as_bytes()) {
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(())
}

/// Remove the static hop set and every syntactically valid field named by
/// every Connection field value.
pub(super) fn sanitize_hop_by_hop(headers: &mut HeaderMap) {
    let nominated = connection_tokens(headers);
    for name in STATIC_HOP_HEADERS {
        headers.remove(*name);
    }
    for name in nominated {
        headers.remove(name);
    }
}

/// Rebuild the two hop-scoped WebSocket fields for the newly opened upstream
/// connection after removing all downstream hop authority.
pub(super) fn sanitize_websocket_request(headers: &mut HeaderMap) {
    sanitize_hop_by_hop(headers);
    headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
}

/// Validate and sanitize an upstream 101 before any tunnel is created.
pub(super) fn sanitize_switching_response(
    headers: &mut HeaderMap,
    handshake: &WebSocketHandshake,
    received_version: Version,
) -> Result<(), StatusCode> {
    validate_upstream_switching_response(headers, handshake)?;
    sanitize_hop_by_hop(headers);
    headers.remove(header::CONTENT_LENGTH);
    headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    append_via(headers, received_version);
    Ok(())
}

/// Append one syntactically valid, package-version-free Via field without
/// combining or replacing any field contributed by earlier hops. The received
/// HTTP protocol version remains part of the field as required by Via.
pub(super) fn append_via(headers: &mut HeaderMap, received_version: Version) {
    headers.append(header::VIA, via_value(received_version));
}

/// Remove every client-supplied field whose value is owned and regenerated by
/// the proxy. Prefix classification is shared with route-header admission so a
/// newly introduced identity or forwarding field cannot be blocked in config
/// yet accidentally pass through from an untrusted request.
pub(super) fn strip_client_proxy_owned_headers(headers: &mut HeaderMap) {
    let names: Vec<_> = headers
        .keys()
        .filter(|name| is_proxy_owned_header(name.as_str()))
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
}

/// Route header operations cannot change fields owned by HTTP framing,
/// Sekisho, forwarding, or the WebSocket handshake.
pub(crate) fn is_reserved_route_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    STATIC_HOP_HEADERS.contains(&lower.as_str())
        || matches!(lower.as_str(), "host" | "content-length" | "via")
        || is_proxy_owned_header_lowercase(&lower)
        || lower.starts_with("sec-websocket-")
}

/// Case-normalising wrapper. Callers holding a header name straight off the
/// wire go through here; callers that already lowercased for another check
/// call [`is_proxy_owned_header_lowercase`] directly rather than allocating a
/// second time.
fn is_proxy_owned_header(name: &str) -> bool {
    is_proxy_owned_header_lowercase(&name.to_ascii_lowercase())
}

/// The fields the proxy asserts about a request and therefore never accepts
/// from one.
///
/// Matching is by prefix, not by an enumerated list, and that is deliberate:
/// the set of `X-Sekisho-*` and `X-Forwarded-*` fields grows over releases, and
/// an enumeration would mean every new field arrives spoofable until someone
/// remembers to extend the list. A prefix closes the family once. The cost is
/// that a route cannot define its own header inside these namespaces, which is
/// the trade the reserved-header rule already makes explicit.
///
/// `forwarded` is matched exactly because RFC 7239 gives it no prefix.
fn is_proxy_owned_header_lowercase(lower: &str) -> bool {
    lower == "forwarded" || lower.starts_with("x-forwarded-") || lower.starts_with("x-sekisho-")
}

/// Convert the Policy DSL's single header-name segment to its wire spelling.
///
/// Policy identifiers accept underscores as a convenient spelling for
/// hyphens. Returning `None` for proxy-owned names makes the same closed
/// prefix authority serve both admission and runtime evaluation.
pub(crate) fn policy_request_header_name(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase().replace('_', "-");
    (!is_proxy_owned_header_lowercase(&lower)).then_some(lower)
}

#[cfg(test)]
pub(super) fn is_static_hop_header(name: &str) -> bool {
    STATIC_HOP_HEADERS.contains(&name.to_ascii_lowercase().as_str())
}

fn exact_single_value(
    headers: &HeaderMap,
    name: impl axum::http::header::AsHeaderName,
) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn has_exact_single_token_value(
    headers: &HeaderMap,
    name: impl axum::http::header::AsHeaderName,
    expected: &str,
) -> bool {
    exact_single_value(headers, name).is_some_and(|value| {
        value
            .to_str()
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case(expected))
    })
}

fn has_exact_single_octets(
    headers: &HeaderMap,
    name: impl axum::http::header::AsHeaderName,
    expected: &[u8],
) -> bool {
    exact_single_value(headers, name).is_some_and(|value| value.as_bytes() == expected)
}

fn via_value(version: Version) -> HeaderValue {
    if version == Version::HTTP_09 {
        HeaderValue::from_static("0.9 sekisho")
    } else if version == Version::HTTP_10 {
        HeaderValue::from_static("1.0 sekisho")
    } else if version == Version::HTTP_11 {
        HeaderValue::from_static("1.1 sekisho")
    } else if version == Version::HTTP_2 {
        HeaderValue::from_static("2 sekisho")
    } else if version == Version::HTTP_3 {
        HeaderValue::from_static("3 sekisho")
    } else {
        debug_assert!(false, "unsupported received HTTP version: {version:?}");
        HeaderValue::from_static("1.1 sekisho")
    }
}

fn connection_has_token(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .any(|token| trim_ascii(token).eq_ignore_ascii_case(expected.as_bytes()))
}

fn connection_tokens(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .filter_map(|token| HeaderName::from_bytes(trim_ascii(token)).ok())
        .collect()
}

fn connection_nominates_websocket_metadata(headers: &HeaderMap) -> bool {
    connection_tokens(headers)
        .iter()
        .any(|name| name.as_str().starts_with("sec-websocket-"))
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn websocket_accept(key: &str) -> String {
    let mut value = Vec::with_capacity(key.len() + 36);
    value.extend_from_slice(key.as_bytes());
    value.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &value);
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> Request<Body> {
        Request::builder()
            .method("GET")
            .version(Version::HTTP_11)
            .header(header::CONNECTION, "keep-alive, Upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn connection_tokens_from_every_field_are_removed() {
        let mut headers = HeaderMap::new();
        headers.append(header::CONNECTION, "keep-alive, x-first".parse().unwrap());
        headers.append(header::CONNECTION, "x-second".parse().unwrap());
        headers.insert("x-first", "one".parse().unwrap());
        headers.insert("x-second", "two".parse().unwrap());
        sanitize_hop_by_hop(&mut headers);
        assert!(headers.get("x-first").is_none());
        assert!(headers.get("x-second").is_none());
    }

    /// Names are matched case-insensitively (the wire may send any casing) and
    /// the strip must stay inside the reserved families — a WebSocket
    /// handshake field or an ordinary application header passing through is
    /// what keeps this from being a blunt instrument.
    #[test]
    fn client_proxy_owned_strip_covers_prefixes_without_touching_websocket_or_safe_headers() {
        for name in [
            "X-SeKiShO-Future-Claim",
            "X-FoRwArDeD-Future-Hop",
            "FoRwArDeD",
        ] {
            assert!(is_reserved_route_header(name), "route accepted {name}");
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_bytes(b"X-SeKiShO-Future-Claim").unwrap(),
            HeaderValue::from_static("forged"),
        );
        headers.insert(
            HeaderName::from_bytes(b"X-FoRwArDeD-Future-Hop").unwrap(),
            HeaderValue::from_static("forged"),
        );
        headers.insert("forwarded", HeaderValue::from_static("for=attacker"));
        headers.insert(
            "sec-websocket-key",
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert("x-safe", HeaderValue::from_static("keep"));

        strip_client_proxy_owned_headers(&mut headers);

        assert!(headers.get("x-sekisho-future-claim").is_none());
        assert!(headers.get("x-forwarded-future-hop").is_none());
        assert!(headers.get("forwarded").is_none());
        assert!(headers.get("sec-websocket-key").is_some());
        assert_eq!(headers[header::CONNECTION], "Upgrade");
        assert_eq!(headers[header::UPGRADE], "websocket");
        assert_eq!(headers["x-safe"], "keep");
    }

    #[test]
    fn policy_header_names_share_proxy_owned_prefix_classification() {
        for name in [
            "x-sekisho-user",
            "x_sekisho_user",
            "X_SEKISHO_FUTURE_CLAIM",
            "x-forwarded-for",
            "x_forwarded_future",
            "FoRwArDeD",
        ] {
            assert_eq!(policy_request_header_name(name), None, "accepted {name}");
        }
        assert_eq!(
            policy_request_header_name("X_Request_Source").as_deref(),
            Some("x-request-source")
        );
        assert_eq!(
            policy_request_header_name("x-sekisho").as_deref(),
            Some("x-sekisho")
        );
        assert_eq!(
            policy_request_header_name("x-forwarded").as_deref(),
            Some("x-forwarded")
        );
    }

    #[test]
    fn websocket_request_requires_exact_handshake_fields() {
        let handshake = classify_websocket_request(&valid_request())
            .expect("valid handshake")
            .expect("websocket attempt");
        assert_eq!(handshake.client_key(), "dGhlIHNhbXBsZSBub25jZQ==");

        for request in [
            Request::builder()
                .method("POST")
                .version(Version::HTTP_11)
                .header(header::UPGRADE, "websocket")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .method("GET")
                .version(Version::HTTP_11)
                .header(header::CONNECTION, "upgrade, sec-websocket-key")
                .header(header::UPGRADE, "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .method("GET")
                .version(Version::HTTP_11)
                .header(header::CONNECTION, "upgrade")
                .header(header::UPGRADE, "websocket, h2c")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(Body::empty())
                .unwrap(),
        ] {
            assert_eq!(
                classify_websocket_request(&request).err(),
                Some(StatusCode::BAD_REQUEST)
            );
        }
    }

    #[test]
    fn switching_response_is_validated_then_pinned_and_preserves_end_to_end_fields() {
        let handshake = classify_websocket_request(&valid_request())
            .unwrap()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, "upgrade, x-hop".parse().unwrap());
        headers.insert(header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(
            "sec-websocket-accept",
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".parse().unwrap(),
        );
        headers.insert("sec-websocket-protocol", "chat".parse().unwrap());
        headers.append(header::SET_COOKIE, "a=1".parse().unwrap());
        headers.append(header::SET_COOKIE, "b=2".parse().unwrap());
        headers.insert("x-hop", "drop".parse().unwrap());
        headers.insert(header::CONTENT_LENGTH, "7".parse().unwrap());

        sanitize_switching_response(&mut headers, &handshake, Version::HTTP_11).unwrap();
        assert_eq!(headers[header::CONNECTION], "Upgrade");
        assert_eq!(headers[header::UPGRADE], "websocket");
        assert!(headers.get("x-hop").is_none());
        assert!(headers.get(header::CONTENT_LENGTH).is_none());
        assert_eq!(headers.get_all(header::SET_COOKIE).iter().count(), 2);
        assert_eq!(headers["sec-websocket-protocol"], "chat");

        let mut case_altered_accept = HeaderMap::new();
        case_altered_accept.insert(header::CONNECTION, "upgrade".parse().unwrap());
        case_altered_accept.insert(header::UPGRADE, "WebSocket".parse().unwrap());
        case_altered_accept.insert(
            "sec-websocket-accept",
            "S3pPLMBiTxaQ9kYGzzhZRbK+xOo=".parse().unwrap(),
        );
        assert_eq!(
            sanitize_switching_response(&mut case_altered_accept, &handshake, Version::HTTP_11,),
            Err(StatusCode::BAD_GATEWAY)
        );

        let mut nominated_accept = HeaderMap::new();
        nominated_accept.insert(
            header::CONNECTION,
            "upgrade, sec-websocket-accept".parse().unwrap(),
        );
        nominated_accept.insert(header::UPGRADE, "websocket".parse().unwrap());
        nominated_accept.insert(
            "sec-websocket-accept",
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".parse().unwrap(),
        );
        assert_eq!(
            sanitize_switching_response(&mut nominated_accept, &handshake, Version::HTTP_11,),
            Err(StatusCode::BAD_GATEWAY)
        );
    }

    #[test]
    fn via_append_preserves_existing_fields_and_is_package_version_free() {
        let mut headers = HeaderMap::new();
        headers.append(header::VIA, "1.0 first".parse().unwrap());
        headers.append(header::VIA, "2 second".parse().unwrap());
        append_via(&mut headers, Version::HTTP_11);
        let values: Vec<_> = headers
            .get_all(header::VIA)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(values, ["1.0 first", "2 second", "1.1 sekisho"]);
    }

    #[test]
    fn websocket_request_drops_connection_nominated_via_before_appending_its_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, "upgrade, via".parse().unwrap());
        headers.insert(header::UPGRADE, "websocket".parse().unwrap());
        headers.append(header::VIA, "1.0 nominated".parse().unwrap());
        sanitize_websocket_request(&mut headers);
        append_via(&mut headers, Version::HTTP_11);
        let values: Vec<_> = headers
            .get_all(header::VIA)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(values, ["1.1 sekisho"]);
    }

    #[test]
    fn via_uses_the_received_protocol_version() {
        let mut headers = HeaderMap::new();
        append_via(&mut headers, Version::HTTP_2);
        assert_eq!(headers[header::VIA], "2 sekisho");
    }

    #[test]
    fn route_reserved_names_cover_proxy_and_websocket_authority() {
        for name in [
            "Connection",
            "Keep-Alive",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
            "Host",
            "Content-Length",
            "Via",
            "Forwarded",
            "X-Forwarded-For",
            "X-Sekisho-User",
            "Sec-WebSocket-Key",
        ] {
            assert!(is_reserved_route_header(name), "accepted {name}");
        }
        assert!(!is_reserved_route_header("Authorization"));
        assert!(!is_reserved_route_header("X-Custom"));
    }
}
