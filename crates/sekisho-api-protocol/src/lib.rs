//! Shared API contracts and client-side orchestration.
//!
//! The server, CLI, and WebUI share endpoint paths and hostname
//! normalization through [`api_paths`] and [`hostname_from_url`].
//! Keeping those contracts here prevents the server router and its
//! clients from drifting to different endpoint strings or hostname
//! interpretations.
//!
//! The crate also contains orchestration used only by `sekisho-cli`
//! and `sekisho-webui`. Both clients need to implement the same
//! high-level flows against the server — most notably "enable a
//! route, minting an ACME cert first if one is missing":
//!
//! - A trait [`ResourceClient`] with the minimum set of HTTP calls
//!   the orchestration needs. Each client (`sekisho-cli::ApiClient`,
//!   `sekisho-webui::SekishoClient`) implements it on its own HTTP
//!   wrapper. Error type is `String` because the two wrappers
//!   disagree on their native error type (sekisho-cli uses `String`
//!   already; sekisho-webui uses `anyhow::Error` and converts).
//!
//! - [`ensure_cert_before_enable`] is a plain free function generic
//!   over `impl ResourceClient`.
//!
//! The crate intentionally does *not* re-export the server's data
//! model. Domain types live in `sekishod::models::*`, and clients
//! parse into `serde_json::Value` at the boundary. If that becomes
//! annoying we can extract the model later, but today the overhead
//! of a separate shared crate isn't worth it.

use serde_json::Value;

pub mod api_paths;
pub mod management_rpk;
pub mod version;

/// One successfully decoded management-API collection page.
///
/// `next` is present only when the server's current
/// `{items, limit, offset, has_more}` envelope says another page exists.
/// Bare arrays and older `{items}`-only responses are terminal so the
/// encryption-key collection keeps its existing compatibility shape.
#[derive(Debug, PartialEq)]
pub struct ListPage {
    pub items: Vec<Value>,
    pub next: Option<ListPageRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListPageRequest {
    pub limit: i64,
    pub offset: i64,
}

/// Decode one response from a Sekisho collection endpoint and calculate the
/// next offset without permitting a non-progressing or wrapping client loop.
pub fn parse_list_page(value: Value, expected_offset: i64) -> Result<ListPage, String> {
    if let Value::Array(items) = value {
        return Ok(ListPage { items, next: None });
    }

    let object = value
        .as_object()
        .ok_or_else(|| "list response is neither an array nor an object".to_string())?;
    let items = object
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "list response is missing an `items` array".to_string())?;

    let Some(has_more_value) = object.get("has_more") else {
        return Ok(ListPage { items, next: None });
    };
    let has_more = has_more_value
        .as_bool()
        .ok_or_else(|| "list response `has_more` is not a boolean".to_string())?;
    let limit = object
        .get("limit")
        .and_then(Value::as_i64)
        .ok_or_else(|| "paginated list response is missing integer `limit`".to_string())?;
    let offset = object
        .get("offset")
        .and_then(Value::as_i64)
        .ok_or_else(|| "paginated list response is missing integer `offset`".to_string())?;
    if !(1..=1000).contains(&limit) {
        return Err("paginated list response `limit` is outside 1..=1000".into());
    }
    if offset != expected_offset {
        return Err(format!(
            "paginated list response offset {offset} did not match requested offset {expected_offset}"
        ));
    }
    if items.len() > limit as usize {
        return Err("paginated list response contains more items than `limit`".into());
    }
    if !has_more {
        return Ok(ListPage { items, next: None });
    }
    if items.is_empty() {
        return Err("paginated list response cannot make progress".into());
    }
    let item_count = i64::try_from(items.len())
        .map_err(|_| "paginated list item count does not fit in i64".to_string())?;
    let next_offset = offset
        .checked_add(item_count)
        .ok_or_else(|| "paginated list offset overflow".to_string())?;
    Ok(ListPage {
        items,
        next: Some(ListPageRequest {
            limit,
            offset: next_offset,
        }),
    })
}

/// Add the next-page parameters to a current collection path while retaining
/// any existing filter query.
pub fn list_page_path(path: &str, page: ListPageRequest) -> String {
    let separator = if path.contains('?') { '&' } else { '?' };
    format!(
        "{path}{separator}limit={}&offset={}",
        page.limit, page.offset
    )
}

/// Minimal HTTP surface needed by the cert-preflight flow. Clients
/// own their auth, retries, timeouts, etc.; this trait only names
/// the three GET / GET / POST calls the orchestration needs.
#[allow(async_fn_in_trait)]
pub trait ResourceClient {
    /// `GET /routes/{id}`. Returns the route JSON.
    async fn get_route(&self, id: &str) -> Result<Value, String>;
    /// `GET /certs`. Returns the complete list across every paginated
    /// response, already unwrapped from the `{items: [...]}` envelope.
    async fn list_certs(&self) -> Result<Vec<Value>, String>;
    /// `POST /certs {domain}`. Enqueues issuance and waits for the
    /// queue result. The orchestration only cares about success vs failure.
    async fn issue_cert(&self, domain: &str) -> Result<Value, String>;
}

/// Extract a hostname from a URL-like string without pulling in the
/// `url` crate. Handles `scheme://host[:port]/path`, `host:port`,
/// and the bare hostname form — enough for `route.from` values the
/// clients see.
///
/// The returned hostname is always lowercased so downstream string
/// comparisons (e.g. against `certificate.domain` which the server
/// stores lowercased via `validate_domain`) are not tricked by a
/// mixed-case `from` URL.
pub fn hostname_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = after_scheme
        .split(['/', ':'])
        .next()
        .filter(|s| !s.is_empty())?;
    Some(host.to_ascii_lowercase())
}

/// Client-side orchestration for `enable route <id>`.
///
/// The server treats `enabled` as a plain flag; the *client* owns
/// the lifecycle logic. This function fetches the route, decides
/// whether a TLS cert is needed for the route's hostname, issues
/// one via ACME if the route's `tls_downstream` is `acme` and no
/// cert exists, and leaves the caller to finish with a
/// `PATCH /routes/{id} {"enabled": true}` once this returns `Ok`.
///
/// Error cases produce a human-readable `String` the caller can
/// surface in CLI output or in an HTMX error banner. The function
/// never retries — retries belong to the caller so the UI can
/// render "trying…" state appropriately.
pub async fn ensure_cert_before_enable<C: ResourceClient>(
    client: &C,
    route_id: &str,
) -> Result<(), String> {
    let route = client
        .get_route(route_id)
        .await
        .map_err(|e| format!("could not fetch route: {e}"))?;

    let tls = route
        .get("tls_downstream")
        .and_then(|v| v.as_str())
        .unwrap_or("acme");
    if matches!(tls, "passthrough" | "none") {
        return Ok(());
    }

    let from = route
        .get("from")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "route has no `from` URL".to_string())?;
    let hostname =
        hostname_from_url(from).ok_or_else(|| format!("cannot extract hostname from `{from}`"))?;

    let certs = client
        .list_certs()
        .await
        .map_err(|e| format!("could not list certs: {e}"))?;
    // Server-side ACME issuance lowercases the domain before storing
    // (see `sekishod::api::certs::validate_domain`), but uploaded /
    // externally-minted certs could theoretically sit in mixed case.
    // Compare case-insensitively here so we never re-issue against a
    // cert that already covers the host.
    let has_cert = certs.iter().any(|c| {
        c.get("domain")
            .and_then(|d| d.as_str())
            .map(|d| d.eq_ignore_ascii_case(&hostname))
            .unwrap_or(false)
    });
    if has_cert {
        return Ok(());
    }

    match tls {
        "acme" => {
            client
                .issue_cert(&hostname)
                .await
                .map_err(|e| format!("ACME issuance failed: {e}"))?;
            Ok(())
        }
        "custom" => Err(format!(
            "no certificate for {hostname}; upload one before enabling, \
             or change tls_downstream to `acme` to have Sekisho obtain it"
        )),
        other => Err(format!("unsupported tls_downstream `{other}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_page_requires_progress_and_checked_offsets() {
        let first = parse_list_page(
            serde_json::json!({
                "items": [{"id": 1}, {"id": 2}],
                "limit": 100,
                "offset": 0,
                "has_more": true,
            }),
            0,
        )
        .unwrap();
        assert_eq!(first.items.len(), 2);
        assert_eq!(
            first.next,
            Some(ListPageRequest {
                limit: 100,
                offset: 2,
            })
        );
        assert_eq!(
            list_page_path("/sessions?user=alice", first.next.unwrap()),
            "/sessions?user=alice&limit=100&offset=2"
        );

        let no_progress = parse_list_page(
            serde_json::json!({
                "items": [],
                "limit": 100,
                "offset": 0,
                "has_more": true,
            }),
            0,
        )
        .unwrap_err();
        assert!(no_progress.contains("cannot make progress"));

        let overflow = parse_list_page(
            serde_json::json!({
                "items": [{"id": 1}],
                "limit": 1,
                "offset": i64::MAX,
                "has_more": true,
            }),
            i64::MAX,
        )
        .unwrap_err();
        assert!(overflow.contains("overflow"));
    }

    #[test]
    fn list_page_keeps_terminal_compatibility_shapes() {
        let bare = parse_list_page(serde_json::json!([{"id": 1}]), 0).unwrap();
        assert_eq!(bare.items.len(), 1);
        assert_eq!(bare.next, None);

        let items_only = parse_list_page(serde_json::json!({"items": [{"key_id": 7}]}), 0).unwrap();
        assert_eq!(items_only.items.len(), 1);
        assert_eq!(items_only.next, None);
    }

    #[test]
    fn hostname_from_url_strips_scheme_and_path() {
        assert_eq!(
            hostname_from_url("https://app.example.com/foo").as_deref(),
            Some("app.example.com"),
        );
        assert_eq!(
            hostname_from_url("https://app.example.com:8443/").as_deref(),
            Some("app.example.com"),
        );
        assert_eq!(
            hostname_from_url("app.example.com").as_deref(),
            Some("app.example.com"),
        );
        assert_eq!(hostname_from_url("").as_deref(), None);
        assert_eq!(hostname_from_url("://").as_deref(), None);
    }

    #[test]
    fn hostname_from_url_lowercases() {
        // DNS is case-insensitive; the server stores lowercased, so
        // the client must match that way to avoid spurious re-issues.
        assert_eq!(
            hostname_from_url("https://App.Example.COM/foo").as_deref(),
            Some("app.example.com"),
        );
    }

    #[tokio::test]
    async fn acme_skips_when_present_mixed_case() {
        let c = MockClient {
            route: serde_json::json!({
                "from": "https://App.Example.com",
                "tls_downstream": "acme",
            }),
            certs: vec![serde_json::json!({"domain": "app.example.com"})],
            issue_result: Err("must not be called".into()),
        };
        assert!(ensure_cert_before_enable(&c, "id").await.is_ok());
    }

    struct MockClient {
        route: Value,
        certs: Vec<Value>,
        issue_result: Result<Value, String>,
    }

    impl ResourceClient for MockClient {
        async fn get_route(&self, _id: &str) -> Result<Value, String> {
            Ok(self.route.clone())
        }
        async fn list_certs(&self) -> Result<Vec<Value>, String> {
            Ok(self.certs.clone())
        }
        async fn issue_cert(&self, _domain: &str) -> Result<Value, String> {
            self.issue_result.clone()
        }
    }

    #[tokio::test]
    async fn passthrough_skips_cert_check() {
        let c = MockClient {
            route: serde_json::json!({
                "from": "https://app.example.com",
                "tls_downstream": "passthrough",
            }),
            certs: vec![],
            issue_result: Err("must not be called".into()),
        };
        assert!(ensure_cert_before_enable(&c, "id").await.is_ok());
    }

    #[tokio::test]
    async fn acme_issues_when_missing() {
        let c = MockClient {
            route: serde_json::json!({
                "from": "https://app.example.com",
                "tls_downstream": "acme",
            }),
            certs: vec![],
            issue_result: Ok(serde_json::json!({"id": "whatever"})),
        };
        assert!(ensure_cert_before_enable(&c, "id").await.is_ok());
    }

    #[tokio::test]
    async fn acme_skips_when_present() {
        let c = MockClient {
            route: serde_json::json!({
                "from": "https://app.example.com",
                "tls_downstream": "acme",
            }),
            certs: vec![serde_json::json!({"domain": "app.example.com"})],
            issue_result: Err("must not be called".into()),
        };
        assert!(ensure_cert_before_enable(&c, "id").await.is_ok());
    }

    #[tokio::test]
    async fn acme_skips_when_matching_certificate_is_item_101() {
        let mut certs = (0..100)
            .map(|i| serde_json::json!({"domain": format!("other-{i}.example.com")}))
            .collect::<Vec<_>>();
        certs.push(serde_json::json!({"domain": "app.example.com"}));
        let c = MockClient {
            route: serde_json::json!({
                "from": "https://app.example.com",
                "tls_downstream": "acme",
            }),
            certs,
            issue_result: Err("must not be called".into()),
        };
        assert!(ensure_cert_before_enable(&c, "id").await.is_ok());
    }

    #[tokio::test]
    async fn certificate_list_error_never_starts_issuance() {
        struct FailingListClient;
        impl ResourceClient for FailingListClient {
            async fn get_route(&self, _id: &str) -> Result<Value, String> {
                Ok(serde_json::json!({
                    "from": "https://app.example.com",
                    "tls_downstream": "acme",
                }))
            }
            async fn list_certs(&self) -> Result<Vec<Value>, String> {
                Err("later page failed".into())
            }
            async fn issue_cert(&self, _domain: &str) -> Result<Value, String> {
                panic!("issuance must not run after a list error")
            }
        }

        let err = ensure_cert_before_enable(&FailingListClient, "id")
            .await
            .unwrap_err();
        assert!(err.contains("later page failed"));
    }

    #[tokio::test]
    async fn custom_without_cert_errors() {
        let c = MockClient {
            route: serde_json::json!({
                "from": "https://app.example.com",
                "tls_downstream": "custom",
            }),
            certs: vec![],
            issue_result: Err("must not be called".into()),
        };
        let err = ensure_cert_before_enable(&c, "id").await.unwrap_err();
        assert!(err.contains("upload one before enabling"));
    }
}
