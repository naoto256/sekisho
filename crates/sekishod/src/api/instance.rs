//! Singleton `/instance` resource.
//!
//! Exposes the per-instance config SQLite to admins so operators
//! can rotate node-local settings over the management API instead of
//! hand-editing systemd environment files.
//!
//! Today the resource carries two kinds of values, all stored in the
//! single `instance_config` table with a per-row `encrypted` flag:
//!
//! * **Secret** — `cluster_db_url`. Stored encrypted (the URL embeds
//!   Postgres credentials). GET responses redact it to
//!   `"**REDACTED**"` (presence-vs-null still reported); returning
//!   the value verbatim would be a credential-extraction endpoint.
//! * **Plaintext per-node settings** — `proxy_listen`, `api_listen`,
//!   `http_listen`. These are bind addresses, not secrets, and
//!   `ss -tlnp` would reveal them anyway, so they're round-tripped
//!   in the clear. The InstanceStore accessors fix the `encrypted`
//!   flag per key in code, so an operator can't toggle a field's
//!   secrecy through the API or by hand-editing the DB.
//!
//! Security posture:
//!
//! * **Authentication is the standard admin auth** applied to every
//!   other management endpoint — API key or local session.
//! * **PATCH is JSON Merge Patch.** `null` for a field clears it
//!   (= falls back to the per-node default).
//! * **Changes require a daemon restart** to take effect; the backend
//!   selection and listener binds happen once at startup. The response
//!   carries a `_restart_required: true` hint mirroring the convention
//!   used by `/config`.

use axum::Json;
use axum::extract::{Extension, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};

use super::SanitizedJson;
use crate::audit::Actor;
use crate::error::{Error, Result};
use crate::models::serde_util::deserialize_some;

/// Stand-in the API returns in place of the decrypted secret. Kept as a
/// constant so the client-side redaction detection (e.g. "show the
/// placeholder in grey") doesn't need to duplicate the literal.
const REDACTED: &str = "**REDACTED**";

/// Incoming PATCH body. Each field is `Option<Option<String>>` so we
/// can distinguish three states:
/// * missing key → leave alone.
/// * key present with `null` → clear.
/// * key present with string → set.
#[derive(Debug, Deserialize)]
pub struct InstancePatch {
    #[serde(default, deserialize_with = "deserialize_some")]
    cluster_db_url: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    proxy_listen: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    api_listen: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    http_listen: Option<Option<String>>,
    /// Per-listener source-IP ACL. Comma-separated CIDRs / bare IPs.
    /// `null` clears (= ANY); empty string also stores as ANY.
    #[serde(default, deserialize_with = "deserialize_some")]
    proxy_accept_from: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    api_accept_from: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    http_accept_from: Option<Option<String>>,
}

pub async fn get(State(store): State<crate::store::Store>) -> Result<impl IntoResponse> {
    let url = store.instance().get_cluster_db_url().await?;
    let proxy_listen = store.instance().get_proxy_listen().await?;
    let api_listen = store.instance().get_api_listen().await?;
    let http_listen = store.instance().get_http_listen().await?;
    let proxy_accept_from = store.instance().get_proxy_accept_from().await?;
    let api_accept_from = store.instance().get_api_accept_from().await?;
    let http_accept_from = store.instance().get_http_accept_from().await?;
    Ok(Json(render(
        url.as_deref(),
        &proxy_listen,
        &api_listen,
        &http_listen,
        &proxy_accept_from,
        &api_accept_from,
        &http_accept_from,
    )))
}

pub async fn update(
    State(store): State<crate::store::Store>,
    Extension(actor): Extension<Actor>,
    SanitizedJson(body): SanitizedJson<InstancePatch>,
) -> Result<impl IntoResponse> {
    // Per-field action labels for the audit event. Listing them
    // individually (instead of a single "updated") gives the operator
    // a record of *which* knobs moved without exposing the values
    // themselves — cluster_db_url in particular embeds credentials and
    // must never reach the log stream.
    let mut changed_fields: Vec<&str> = Vec::new();

    // The management listener and its ACL form one effective security
    // boundary. Validate and persist the pair in a single InstanceStore
    // transaction before applying any of the independent settings below.
    let api_listen_action = body.api_listen.as_ref().map(|value| {
        if value.is_some() {
            "api_listen_set"
        } else {
            "api_listen_cleared"
        }
    });
    let api_accept_from_action = body.api_accept_from.as_ref().map(|value| {
        if value.is_some() {
            "api_accept_from_set"
        } else {
            "api_accept_from_cleared"
        }
    });
    let management_update = store
        .instance()
        .update_management_api_binding(body.api_listen, body.api_accept_from)
        .await?;
    if management_update.listen_changed {
        changed_fields.push(api_listen_action.expect("changed listen has a patch action"));
    }
    if management_update.accept_from_changed {
        changed_fields
            .push(api_accept_from_action.expect("changed management ACL has a patch action"));
    }

    if let Some(action) = body.cluster_db_url {
        match action {
            Some(url) => {
                validate_cluster_db_url(&url)?;
                store.instance().set_cluster_db_url(&url).await?;
                changed_fields.push("cluster_db_url_set");
            }
            None => {
                store.instance().clear_cluster_db_url().await?;
                changed_fields.push("cluster_db_url_cleared");
            }
        }
    }
    if let Some(action) = body.proxy_listen {
        match action {
            Some(addr) => {
                crate::validation::validate_listen_addr(&addr)?;
                // Skip the write — and the audit entry — when the
                // submission echoes the existing value. This is the
                // common case for the WebUI form, which always
                // re-submits the current value of every listen field;
                // recording every form save as a "changed" event would
                // make the audit log misleading.
                if store.instance().get_proxy_listen().await? != addr {
                    store.instance().set_proxy_listen(&addr).await?;
                    changed_fields.push("proxy_listen_set");
                }
            }
            None => {
                if store.instance().has_value("proxy_listen").await? {
                    store.instance().clear_proxy_listen().await?;
                    changed_fields.push("proxy_listen_cleared");
                }
            }
        }
    }
    if let Some(action) = body.http_listen {
        match action {
            Some(addr) => {
                if !addr.is_empty() {
                    crate::validation::validate_listen_addr(&addr)?;
                }
                if store.instance().get_http_listen().await? != addr {
                    store.instance().set_http_listen(&addr).await?;
                    changed_fields.push("http_listen_set");
                }
            }
            None => {
                if store.instance().has_value("http_listen").await? {
                    store.instance().clear_http_listen().await?;
                    changed_fields.push("http_listen_cleared");
                }
            }
        }
    }

    // Apply accept_from changes. The validation step is the same for
    // every key — parse with `acl::AcceptFrom::parse` to surface any
    // CIDR errors as a 400 — and the canonical form is what we
    // persist so a save-then-reload sees a stable string.
    apply_accept_from_patch(&store, body.proxy_accept_from, "proxy", &mut changed_fields).await?;
    apply_accept_from_patch(&store, body.http_accept_from, "http", &mut changed_fields).await?;

    let url = store.instance().get_cluster_db_url().await?;
    let proxy_listen = store.instance().get_proxy_listen().await?;
    let api_listen = store.instance().get_api_listen().await?;
    let http_listen = store.instance().get_http_listen().await?;
    let proxy_accept_from = store.instance().get_proxy_accept_from().await?;
    let api_accept_from = store.instance().get_api_accept_from().await?;
    let http_accept_from = store.instance().get_http_accept_from().await?;
    let mut response = render(
        url.as_deref(),
        &proxy_listen,
        &api_listen,
        &http_listen,
        &proxy_accept_from,
        &api_accept_from,
        &http_accept_from,
    );
    // Mirror `/config`'s convention. Every instance-config mutation
    // requires a restart — the backend is chosen at `Store::new`
    // time and listeners are bound once at startup.
    let restart_required = !changed_fields.is_empty();
    response["_restart_required"] = json!(restart_required);
    crate::audit_mgmt!(
        actor = actor,
        event = "instance.update",
        resource = "instance",
        action = "update",
        changed_fields = ?changed_fields,
        restart_required = restart_required,
        "instance config updated"
    );
    Ok(Json(response))
}

/// Server-side sanity check. The full validation is the backend that
/// will eventually open the URL (sqlx rejects garbage), but catching
/// obvious typos here gives the operator an immediate 400 instead of a
/// quiet "next restart fails to boot" surprise.
fn validate_cluster_db_url(url: &str) -> Result<()> {
    let lower = url.to_ascii_lowercase();
    let ok = lower.starts_with("postgres://")
        || lower.starts_with("postgresql://")
        || lower.starts_with("sqlite:")
        || lower.starts_with("sqlite3:");
    if !ok {
        return Err(Error::BadRequest(
            "cluster_db_url must start with postgres://, postgresql://, or sqlite:".into(),
        ));
    }
    Ok(())
}

fn render(
    url: Option<&str>,
    proxy_listen: &str,
    api_listen: &str,
    http_listen: &str,
    proxy_accept_from: &str,
    api_accept_from: &str,
    http_accept_from: &str,
) -> Value {
    let cluster_db_url = match url {
        Some(_) => Value::String(REDACTED.into()),
        None => Value::Null,
    };
    json!({
        "cluster_db_url": cluster_db_url,
        "proxy_listen": proxy_listen,
        // api_listen is intentionally an empty-string default rather
        // than null. It pairs with the "" semantics of "localhost only"
        // — null would force clients to teach a tri-state.
        "api_listen": api_listen,
        "http_listen": http_listen,
        // accept_from fields default to "" (= ANY). Same reasoning as
        // api_listen: keep the wire shape free of nullable fields.
        "proxy_accept_from": proxy_accept_from,
        "api_accept_from": api_accept_from,
        "http_accept_from": http_accept_from,
    })
}

/// Shared apply path for the three accept_from fields. Parsing
/// surfaces a 400 with the offending entry; the canonical form is
/// what we persist so the WebUI's display value is stable.
async fn apply_accept_from_patch(
    store: &crate::store::Store,
    action: Option<Option<String>>,
    name: &'static str,
    changed: &mut Vec<&'static str>,
) -> Result<()> {
    let Some(action) = action else { return Ok(()) };
    match action {
        Some(raw) => {
            let parsed = crate::acl::AcceptFrom::parse(&raw)
                .map_err(|e| Error::BadRequest(format!("invalid {name}_accept_from: {e}")))?;
            let canonical = parsed.to_string_canonical();
            let current = match name {
                "proxy" => store.instance().get_proxy_accept_from().await?,
                "api" => store.instance().get_api_accept_from().await?,
                "http" => store.instance().get_http_accept_from().await?,
                _ => unreachable!("apply_accept_from_patch: unknown listener name"),
            };
            if current == canonical {
                return Ok(());
            }
            match name {
                "proxy" => {
                    store.instance().set_proxy_accept_from(&canonical).await?;
                    changed.push("proxy_accept_from_set");
                }
                "api" => {
                    store.instance().set_api_accept_from(&canonical).await?;
                    changed.push("api_accept_from_set");
                }
                "http" => {
                    store.instance().set_http_accept_from(&canonical).await?;
                    changed.push("http_accept_from_set");
                }
                _ => unreachable!(),
            }
        }
        None => {
            let key = match name {
                "proxy" => "proxy_accept_from",
                "api" => "api_accept_from",
                "http" => "http_accept_from",
                _ => unreachable!(),
            };
            if store.instance().has_value(key).await? {
                match name {
                    "proxy" => store.instance().clear_proxy_accept_from().await?,
                    "api" => store.instance().clear_api_accept_from().await?,
                    "http" => store.instance().clear_http_accept_from().await?,
                    _ => unreachable!(),
                }
                match name {
                    "proxy" => changed.push("proxy_accept_from_cleared"),
                    "api" => changed.push("api_accept_from_cleared"),
                    "http" => changed.push("http_accept_from_cleared"),
                    _ => unreachable!(),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_default(
        url: Option<&str>,
        proxy_listen: &str,
        api_listen: &str,
        http_listen: &str,
    ) -> Value {
        render(url, proxy_listen, api_listen, http_listen, "", "", "")
    }

    #[test]
    fn render_redacts_when_present() {
        let v = render_default(Some("postgres://u:p@h/db"), "0.0.0.0:443", "", "0.0.0.0:80");
        assert_eq!(v["cluster_db_url"], Value::String(REDACTED.into()));
    }

    #[test]
    fn render_null_when_absent() {
        let v = render_default(None, "0.0.0.0:443", "", "0.0.0.0:80");
        assert_eq!(v["cluster_db_url"], Value::Null);
    }

    #[test]
    fn render_emits_listen_addresses_in_clear() {
        // Listen addresses are not secrets — no redaction. The whole
        // point of storing them with encrypted=0 is to avoid
        // running them through the crypto path on every read.
        let v = render_default(None, "10.0.0.1:443", "10.0.0.1:9443", "10.0.0.1:80");
        assert_eq!(v["proxy_listen"], Value::String("10.0.0.1:443".into()));
        assert_eq!(v["api_listen"], Value::String("10.0.0.1:9443".into()));
        assert_eq!(v["http_listen"], Value::String("10.0.0.1:80".into()));
    }

    #[test]
    fn render_accept_from_defaults_to_empty_string() {
        // Empty list = ANY policy on the daemon side. Wire shape stays
        // empty-string rather than null so clients can do a single
        // is_empty check.
        let v = render_default(None, "0.0.0.0:443", "", "0.0.0.0:80");
        assert_eq!(v["proxy_accept_from"], Value::String("".into()));
        assert_eq!(v["api_accept_from"], Value::String("".into()));
        assert_eq!(v["http_accept_from"], Value::String("".into()));
    }

    #[test]
    fn render_emits_accept_from_canonical_form() {
        let v = render(
            None,
            "0.0.0.0:443",
            "",
            "0.0.0.0:80",
            "127.0.0.1/32,10.0.0.0/8",
            "",
            "",
        );
        assert_eq!(
            v["proxy_accept_from"],
            Value::String("127.0.0.1/32,10.0.0.0/8".into())
        );
    }

    #[test]
    fn validate_accepts_postgres_and_sqlite() {
        validate_cluster_db_url("postgres://u:p@h/db").unwrap();
        validate_cluster_db_url("POSTGRESQL://u:p@h/db").unwrap();
        validate_cluster_db_url("sqlite:/var/lib/sekisho.db").unwrap();
    }

    #[test]
    fn validate_rejects_unknown_scheme() {
        assert!(validate_cluster_db_url("mysql://u@h/db").is_err());
        assert!(validate_cluster_db_url("http://x").is_err());
        assert!(validate_cluster_db_url("not-a-url").is_err());
    }

    #[test]
    fn patch_distinguishes_missing_null_and_set() {
        // Present as null → Some(None) → "clear".
        let null_patch: InstancePatch =
            serde_json::from_value(json!({ "cluster_db_url": null })).unwrap();
        assert!(matches!(null_patch.cluster_db_url, Some(None)));

        // Missing → None → "leave alone".
        let empty_patch: InstancePatch = serde_json::from_value(json!({})).unwrap();
        assert!(empty_patch.cluster_db_url.is_none());

        // String → Some(Some(s)) → "set".
        let set_patch: InstancePatch =
            serde_json::from_value(json!({ "cluster_db_url": "postgres://u@h/db" })).unwrap();
        assert!(matches!(
            set_patch.cluster_db_url,
            Some(Some(ref s)) if s == "postgres://u@h/db"
        ));
    }

    // ═══════════════════════ roundtrip through Store ═══════════════════════
    //
    // There is no shared integration-test harness in this crate (every
    // other resource also relies on handler-logic unit tests + Store
    // tests), so we mirror that style: drive the handler's inner
    // operations through `Store::instance()` and assert the shape the
    // HTTP layer would produce. Wiring up a full `axum::Router` just
    // for this resource would introduce the first test of its kind in
    // the crate and pull in tower/hyper test utilities we otherwise
    // don't use.

    #[tokio::test]
    async fn set_then_get_reflects_redacted_presence() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [1u8; 32], None)
            .await
            .unwrap();

        // Empty instance_config → GET returns null for the url.
        let initial = store.instance().get_cluster_db_url().await.unwrap();
        assert_eq!(initial, None);
        assert_eq!(
            render_default(initial.as_deref(), "0.0.0.0:443", "", "0.0.0.0:80")["cluster_db_url"],
            Value::Null
        );

        // PATCH-equivalent: set the URL through the instance handle the
        // handler uses internally.
        validate_cluster_db_url("postgres://u:secret@h/db").unwrap();
        store
            .instance()
            .set_cluster_db_url("postgres://u:secret@h/db")
            .await
            .unwrap();

        // GET-equivalent: stored value present, response is redacted.
        let stored = store.instance().get_cluster_db_url().await.unwrap();
        let rendered = render_default(stored.as_deref(), "0.0.0.0:443", "", "0.0.0.0:80");
        assert_eq!(rendered["cluster_db_url"], Value::String(REDACTED.into()));
        assert!(
            !serde_json::to_string(&rendered).unwrap().contains("secret"),
            "plaintext leaked into rendered response"
        );
    }

    #[tokio::test]
    async fn listen_addresses_roundtrip_through_instance_store() {
        // Mirrors the path the handler walks for a `proxy_listen` PATCH:
        // validate → write through InstanceStore → read back. Keeps
        // the listen-config plumbing covered without spinning up an
        // axum router (which no other resource in this crate does).
        let store = crate::store::Store::new_for_test("sqlite::memory:", [3u8; 32], None)
            .await
            .unwrap();

        // Defaults survive a fresh install.
        assert_eq!(
            store.instance().get_proxy_listen().await.unwrap(),
            "0.0.0.0:443"
        );
        assert_eq!(
            store.instance().get_http_listen().await.unwrap(),
            "0.0.0.0:80"
        );
        assert_eq!(store.instance().get_api_listen().await.unwrap(), "");

        // Set + read back; verbatim, no encryption involved.
        crate::validation::validate_listen_addr("10.0.0.5:8443").unwrap();
        store
            .instance()
            .set_proxy_listen("10.0.0.5:8443")
            .await
            .unwrap();
        assert_eq!(
            store.instance().get_proxy_listen().await.unwrap(),
            "10.0.0.5:8443"
        );

        // Clear → falls back to the default. Mirrors a PATCH with
        // `{"proxy_listen": null}`.
        store.instance().clear_proxy_listen().await.unwrap();
        assert_eq!(
            store.instance().get_proxy_listen().await.unwrap(),
            "0.0.0.0:443"
        );
    }

    #[tokio::test]
    async fn accept_from_invalid_input_is_400() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [4u8; 32], None)
            .await
            .unwrap();
        let mut changed = Vec::new();
        let err = apply_accept_from_patch(
            &store,
            Some(Some("not-an-ip".into())),
            "proxy",
            &mut changed,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, Error::BadRequest(_)),
            "invalid CIDR should surface as 400: {err:?}"
        );
        // No mutation must have landed.
        assert_eq!(store.instance().get_proxy_accept_from().await.unwrap(), "");
        assert!(changed.is_empty());
    }

    #[tokio::test]
    async fn accept_from_canonicalises_before_storing() {
        // Bare IP widens to /32 and the stored value is the canonical
        // form. Re-applying the same canonical value is a no-op (no
        // entry in `changed`).
        let store = crate::store::Store::new_for_test("sqlite::memory:", [5u8; 32], None)
            .await
            .unwrap();
        let mut changed = Vec::new();
        apply_accept_from_patch(&store, Some(Some("10.0.0.5".into())), "api", &mut changed)
            .await
            .unwrap();
        assert_eq!(
            store.instance().get_api_accept_from().await.unwrap(),
            "10.0.0.5/32"
        );
        assert_eq!(changed, vec!["api_accept_from_set"]);

        let mut changed2 = Vec::new();
        apply_accept_from_patch(
            &store,
            Some(Some("10.0.0.5/32".into())),
            "api",
            &mut changed2,
        )
        .await
        .unwrap();
        assert!(
            changed2.is_empty(),
            "echoing the canonical form must be a no-op",
        );
    }

    #[tokio::test]
    async fn accept_from_null_clears_only_when_present() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [6u8; 32], None)
            .await
            .unwrap();

        // Clear-on-empty: must not record a "_cleared" event because
        // there was nothing to clear (audit log noise).
        let mut changed = Vec::new();
        apply_accept_from_patch(&store, Some(None), "http", &mut changed)
            .await
            .unwrap();
        assert!(changed.is_empty());

        // Set then clear → exactly one set, then exactly one cleared.
        let mut c1 = Vec::new();
        apply_accept_from_patch(&store, Some(Some("127.0.0.1".into())), "http", &mut c1)
            .await
            .unwrap();
        assert_eq!(c1, vec!["http_accept_from_set"]);

        let mut c2 = Vec::new();
        apply_accept_from_patch(&store, Some(None), "http", &mut c2)
            .await
            .unwrap();
        assert_eq!(c2, vec!["http_accept_from_cleared"]);
    }

    #[test]
    fn patch_decodes_accept_from_fields() {
        // Set, clear, and missing — same tri-state shape we already
        // verify for cluster_db_url and listen fields.
        let null_patch: InstancePatch =
            serde_json::from_value(json!({ "proxy_accept_from": null })).unwrap();
        assert!(matches!(null_patch.proxy_accept_from, Some(None)));

        let set_patch: InstancePatch =
            serde_json::from_value(json!({ "api_accept_from": "127.0.0.1/32" })).unwrap();
        assert!(matches!(
            set_patch.api_accept_from,
            Some(Some(ref s)) if s == "127.0.0.1/32"
        ));

        let empty_patch: InstancePatch = serde_json::from_value(json!({})).unwrap();
        assert!(empty_patch.proxy_accept_from.is_none());
        assert!(empty_patch.api_accept_from.is_none());
        assert!(empty_patch.http_accept_from.is_none());
    }

    #[test]
    fn patch_decodes_listen_fields_with_null_vs_set() {
        // null → Some(None) (clear); string → Some(Some(_)) (set);
        // missing → None (no-op). Same shape we already verify for
        // cluster_db_url, repeated for the listen fields so a future
        // tweak to one path can't desync the other.
        let null_patch: InstancePatch =
            serde_json::from_value(json!({ "proxy_listen": null })).unwrap();
        assert!(matches!(null_patch.proxy_listen, Some(None)));

        let set_patch: InstancePatch =
            serde_json::from_value(json!({ "api_listen": "10.0.0.1:9443" })).unwrap();
        assert!(matches!(
            set_patch.api_listen,
            Some(Some(ref s)) if s == "10.0.0.1:9443"
        ));

        let empty_patch: InstancePatch = serde_json::from_value(json!({})).unwrap();
        assert!(empty_patch.proxy_listen.is_none());
        assert!(empty_patch.api_listen.is_none());
        assert!(empty_patch.http_listen.is_none());
    }

    #[tokio::test]
    async fn clear_removes_stored_url() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [2u8; 32], None)
            .await
            .unwrap();
        store
            .instance()
            .set_cluster_db_url("sqlite:/tmp/x.db")
            .await
            .unwrap();
        assert!(
            store
                .instance()
                .get_cluster_db_url()
                .await
                .unwrap()
                .is_some()
        );

        store.instance().clear_cluster_db_url().await.unwrap();
        assert!(
            store
                .instance()
                .get_cluster_db_url()
                .await
                .unwrap()
                .is_none()
        );
    }
}
