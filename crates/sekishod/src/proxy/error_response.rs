//! Fixed, negotiated responses for errors owned by the public proxy.
//!
//! Representation negotiation lives beside the exact wire contracts it
//! selects. No request-derived value is reflected into these responses.

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode, header};

/// Representation selected for a Sekisho-owned public proxy rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProxyErrorRepresentation {
    Json,
    Html,
}

/// The owned rejection source. Each variant keeps the exact wire form it had
/// before negotiation existed — JSON for the handler and request-target
/// rejections, plain text for the body limit, and an empty body with no
/// content type for the concurrency rejection — while sharing HTML
/// negotiation and security headers.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ProxyErrorKind {
    Handler(StatusCode),
    GlobalConcurrency,
    RequestBodyLimit,
    RequestTargetBadRequest,
    RequestTargetMethodNotAllowed,
}

impl ProxyErrorKind {
    /// The status each owned rejection answers with. Fixed per variant so a
    /// caller cannot pass a status that contradicts the body it is about to
    /// get; `Handler` is the one variant that carries its own, because the
    /// request pipeline chooses it.
    fn status(self) -> StatusCode {
        match self {
            Self::Handler(status) => status,
            Self::GlobalConcurrency => StatusCode::SERVICE_UNAVAILABLE,
            Self::RequestBodyLimit => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RequestTargetBadRequest => StatusCode::BAD_REQUEST,
            Self::RequestTargetMethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
        }
    }

    /// The exact body and content type this rejection had before negotiation
    /// existed, returned so the JSON branch can reproduce it byte for byte.
    fn legacy_representation(self) -> (&'static str, Option<&'static str>) {
        match self {
            Self::Handler(status) => {
                let body = match status {
                    StatusCode::NOT_FOUND => r#"{"error":"no matching route"}"#,
                    StatusCode::FORBIDDEN => r#"{"error":"access denied"}"#,
                    StatusCode::BAD_GATEWAY => r#"{"error":"upstream error"}"#,
                    StatusCode::SERVICE_UNAVAILABLE => r#"{"error":"service not configured"}"#,
                    StatusCode::BAD_REQUEST => r#"{"error":"bad request"}"#,
                    StatusCode::PAYLOAD_TOO_LARGE => r#"{"error":"request body too large"}"#,
                    _ => r#"{"error":"internal server error"}"#,
                };
                (body, Some("application/json"))
            }
            Self::GlobalConcurrency => ("", None),
            Self::RequestBodyLimit => ("length limit exceeded", Some("text/plain; charset=utf-8")),
            Self::RequestTargetBadRequest => {
                (r#"{"error":"bad request"}"#, Some("application/json"))
            }
            Self::RequestTargetMethodNotAllowed => (
                r#"{"error":"method not allowed"}"#,
                Some("application/json"),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// How strongly a request asked for one media type.
struct MediaPreference {
    quality: u16,
    specificity: u8,
}

/// Fold one `Accept` member into the best preference seen so far for a type.
fn update_preference(current: &mut Option<MediaPreference>, quality: u16, specificity: u8) {
    let candidate = MediaPreference {
        quality,
        specificity,
    };
    match current {
        Some(existing) if existing.specificity > specificity => {}
        Some(existing) if existing.specificity == specificity => {
            existing.quality = existing.quality.max(quality);
        }
        _ => *current = Some(candidate),
    }
}

/// Parse a `q=` value into thousandths, or `None` if it is not well formed.
fn parse_quality(value: &str) -> Option<u16> {
    let value = value.trim();
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => {
            let mut quality = 0u16;
            for byte in fraction.bytes() {
                quality = quality * 10 + u16::from(byte - b'0');
            }
            Some(quality * 10u16.pow(3 - fraction.len() as u32))
        }
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1000),
        _ => None,
    }
}

/// Select HTML only when its preference strictly outranks JSON's; ties stay
/// on the legacy JSON representation.
pub(crate) fn proxy_error_representation(headers: &HeaderMap) -> ProxyErrorRepresentation {
    let mut html = None;
    let mut json = None;

    for value in headers.get_all(header::ACCEPT) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for member in value.split(',') {
            let mut parts = member.split(';');
            let media_range = parts.next().unwrap_or_default().trim();
            if media_range.is_empty() {
                continue;
            }

            let mut quality = None;
            let mut valid = true;
            for parameter in parts {
                let Some((name, value)) = parameter.trim().split_once('=') else {
                    valid = false;
                    break;
                };
                if name.trim().eq_ignore_ascii_case("q") {
                    if quality.is_some() {
                        valid = false;
                        break;
                    }
                    quality = parse_quality(value);
                    if quality.is_none() {
                        valid = false;
                        break;
                    }
                }
            }
            if !valid {
                continue;
            }
            let quality = quality.unwrap_or(1000);

            if media_range.eq_ignore_ascii_case("text/html") {
                update_preference(&mut html, quality, 2);
            } else if media_range.eq_ignore_ascii_case("text/*") {
                update_preference(&mut html, quality, 1);
            } else if media_range.eq_ignore_ascii_case("application/json") {
                update_preference(&mut json, quality, 2);
            } else if media_range.eq_ignore_ascii_case("application/*") {
                update_preference(&mut json, quality, 1);
            } else if media_range == "*/*" {
                update_preference(&mut html, quality, 0);
                update_preference(&mut json, quality, 0);
            }
        }
    }

    let html_wins = match (html, json) {
        (Some(html), Some(json)) => html.quality > 0 && html > json,
        (Some(html), None) => html.quality > 0,
        _ => false,
    };
    if html_wins {
        ProxyErrorRepresentation::Html
    } else {
        ProxyErrorRepresentation::Json
    }
}

/// The HTML page for an owned rejection. Every interpolated value is selected
/// from a fixed status code; request data never enters the document.
fn html_error_body(status: StatusCode) -> String {
    let (title, message) = match status {
        StatusCode::BAD_REQUEST => ("Bad request", "The request could not be understood."),
        StatusCode::FORBIDDEN => ("Access denied", "You do not have access to this resource."),
        StatusCode::NOT_FOUND => ("Page not found", "The requested resource was not found."),
        StatusCode::METHOD_NOT_ALLOWED => {
            ("Method not allowed", "This request method is not allowed.")
        }
        StatusCode::PAYLOAD_TOO_LARGE => (
            "Request body too large",
            "The request body exceeds the allowed size.",
        ),
        StatusCode::BAD_GATEWAY => (
            "Upstream unavailable",
            "The upstream service could not respond.",
        ),
        StatusCode::SERVICE_UNAVAILABLE => (
            "Service unavailable",
            "The service is temporarily unavailable.",
        ),
        StatusCode::GATEWAY_TIMEOUT => (
            "Upstream timed out",
            "The upstream service did not respond in time.",
        ),
        _ => ("Request failed", "The request could not be completed."),
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title></head><body><main><h1>{title}</h1><p>{message}</p></main></body></html>"
    )
}

/// Reproduce an owned source's pre-negotiation response exactly.
pub(crate) fn legacy_proxy_error_response(kind: ProxyErrorKind) -> Response<Body> {
    let (body, content_type) = kind.legacy_representation();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = kind.status();
    if let Some(content_type) = content_type {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    }
    response
}

/// Build a negotiated fixed error response for an owned proxy rejection.
pub(crate) fn proxy_error_response(
    kind: ProxyErrorKind,
    representation: ProxyErrorRepresentation,
) -> Response<Body> {
    let status = kind.status();
    let mut response = match representation {
        ProxyErrorRepresentation::Json => legacy_proxy_error_response(kind),
        ProxyErrorRepresentation::Html => {
            let mut response = Response::new(Body::from(html_error_body(status)));
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(
                    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
                ),
            );
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            );
            response
        }
    };
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Shorthand for the rejections raised by the request pipeline.
pub(super) fn proxy_error(
    status: StatusCode,
    representation: ProxyErrorRepresentation,
) -> Response<Body> {
    proxy_error_response(ProxyErrorKind::Handler(status), representation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn representation_for(values: &[&str]) -> ProxyErrorRepresentation {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                header::ACCEPT,
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
        }
        proxy_error_representation(&headers)
    }

    #[test]
    fn proxy_error_accept_contract_is_json_safe_by_default() {
        for (values, expected) in [
            (vec![], ProxyErrorRepresentation::Json),
            (vec![""], ProxyErrorRepresentation::Json),
            (vec!["*/*"], ProxyErrorRepresentation::Json),
            (vec!["image/png"], ProxyErrorRepresentation::Json),
            (vec!["text/html"], ProxyErrorRepresentation::Html),
            (vec!["TEXT/HTML; Q=1"], ProxyErrorRepresentation::Html),
            (vec!["text/html;q=0"], ProxyErrorRepresentation::Json),
            (
                vec!["text/html;q=0, */*;q=1"],
                ProxyErrorRepresentation::Json,
            ),
            (
                vec!["text/html;q=0.8, application/json;q=0.8"],
                ProxyErrorRepresentation::Json,
            ),
            (
                vec!["text/html;q=0.8, application/*;q=0.8"],
                ProxyErrorRepresentation::Html,
            ),
            (
                vec!["text/*;q=0.8, application/json;q=0.8"],
                ProxyErrorRepresentation::Json,
            ),
            (
                vec!["text/html;q=0.8, */*;q=0.9"],
                ProxyErrorRepresentation::Json,
            ),
            (vec!["text/html;q=bogus"], ProxyErrorRepresentation::Json),
            (vec!["text/html;q=1.001"], ProxyErrorRepresentation::Json),
            (
                vec!["text/html;q=0.9;q=0.8"],
                ProxyErrorRepresentation::Json,
            ),
            (
                vec!["application/json;q=0.8", "text/html;level=1;q=0.9"],
                ProxyErrorRepresentation::Html,
            ),
            (
                vec!["text/html;q=0.5, text/html;q=0.9, application/json;q=0.8"],
                ProxyErrorRepresentation::Html,
            ),
            (
                vec!["text/html;q=0.9, application/json;q=malformed"],
                ProxyErrorRepresentation::Html,
            ),
        ] {
            assert_eq!(representation_for(&values), expected, "{values:?}");
        }
    }

    #[tokio::test]
    async fn proxy_json_wire_is_exact_except_for_negotiation_headers() {
        for (status, expected) in [
            (StatusCode::NOT_FOUND, r#"{"error":"no matching route"}"#),
            (StatusCode::FORBIDDEN, r#"{"error":"access denied"}"#),
            (StatusCode::BAD_GATEWAY, r#"{"error":"upstream error"}"#),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"service not configured"}"#,
            ),
            (StatusCode::BAD_REQUEST, r#"{"error":"bad request"}"#),
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"request body too large"}"#,
            ),
            (
                StatusCode::METHOD_NOT_ALLOWED,
                r#"{"error":"internal server error"}"#,
            ),
            (
                StatusCode::GATEWAY_TIMEOUT,
                r#"{"error":"internal server error"}"#,
            ),
        ] {
            let response = proxy_error(status, ProxyErrorRepresentation::Json);
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(response.headers()[header::VARY], "Accept");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(
                !response
                    .headers()
                    .contains_key(header::CONTENT_SECURITY_POLICY)
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], expected.as_bytes());
        }
    }

    #[tokio::test]
    async fn proxy_html_is_fixed_accessible_and_hardened_for_every_owned_status() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::METHOD_NOT_ALLOWED,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let response = proxy_error(status, ProxyErrorRepresentation::Html);
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "text/html; charset=utf-8"
            );
            assert_eq!(response.headers()[header::VARY], "Accept");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
            assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
            assert!(
                response.headers()[header::CONTENT_SECURITY_POLICY]
                    .to_str()
                    .unwrap()
                    .contains("default-src 'none'")
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(body.starts_with("<!doctype html><html lang=\"en\">"));
            assert!(body.contains("<main><h1>"));
            assert!(!body.contains("<script"));
            assert!(!body.contains("<link"));
            assert!(!body.contains("missing.example.com"));
        }
    }
}
