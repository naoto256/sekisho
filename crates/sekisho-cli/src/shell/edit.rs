//! Edit-mode state machine: `EditContext` + every `set` / `unset` /
//! `commit` / scope-navigation command, plus the config-mode `cmd_edit`
//! / `cmd_create_config` entry points that construct the context.

use rustyline::Editor;
use rustyline::history::DefaultHistory;
use serde_json::{Map, Value};

use crate::api::ApiClient;
use crate::resources::{
    is_array_field, is_idp_ref_field, is_object_field, is_singleton, resource_api_path,
};

use super::completion::ShellHelper;
use super::expand_verb;
use super::help::print_edit_help;
use super::idp_ref::{annotate_idp_refs, resolve_idp_ref};
use super::json::{
    field_to_json_key, json_merge_patch, narrow_to_path, parse_value, print_json, set_nested,
};
use super::names::refresh_names;

pub(super) struct EditContext {
    pub(super) resource: String,
    pub(super) id: Option<String>,
    pub(super) name: String,
    pub(super) changes: Map<String, Value>,
    pub(super) is_new: bool,
    /// Current nested edit scope (snake_case keys walking into the resource
    /// tree). `["access"]` → `set policy x` stages `access.policy = x`.
    /// Empty = resource root. Pending `changes` always stores the patch
    /// relative to the root regardless of the current scope.
    pub(super) path: Vec<String>,
}

const EDIT_VERBS: &[&str] = &[
    "set",
    "unset",
    "edit",
    "up",
    "top",
    "show",
    "commit",
    "rollback",
    "edit-expr",
    "exit",
    "help",
    "?",
];

pub(super) fn edit_verbs() -> &'static [&'static str] {
    EDIT_VERBS
}

/// Prompt string for the current edit scope (resource + path). Empty path
/// renders `sekisho edit route/my-app> `; `["access"]` renders
/// `sekisho edit route/my-app/access> `.
pub(super) fn edit_prompt(host: &str, ctx: &EditContext) -> String {
    // Singleton resources (`sekisho` = GlobalConfig, `instance` =
    // instance-local config) have no instance name — the prompt would
    // otherwise read `edit sekisho/global>` which implies an instance
    // named "global" that doesn't exist.
    let mut p = if is_singleton(&ctx.resource) {
        format!("sekisho@{host} edit {}", ctx.resource)
    } else {
        format!("sekisho@{host} edit {}/{}", ctx.resource, ctx.name)
    };
    for seg in &ctx.path {
        p.push('/');
        p.push_str(seg);
    }
    p.push_str("> ");
    p
}

pub(super) async fn handle_edit_command(
    client: &ApiClient,
    edit_ctx: &mut Option<EditContext>,
    parts: &[&str],
    _rl: &mut Editor<ShellHelper, DefaultHistory>,
) {
    let verb = expand_verb(parts[0], EDIT_VERBS);
    match verb {
        "set" => cmd_set(client, edit_ctx, parts).await,
        "unset" => cmd_unset(edit_ctx, parts),
        "show" => cmd_show_edit(client, edit_ctx).await,
        "commit" => cmd_commit(client, edit_ctx).await,
        "edit-expr" => cmd_edit_expr(edit_ctx),
        "edit" => cmd_enter_nested(edit_ctx, parts),
        "up" => cmd_up(edit_ctx),
        "top" => cmd_top(edit_ctx),
        "rollback" => {
            if let Some(ctx) = edit_ctx.as_mut() {
                ctx.changes.clear();
                eprintln!("changes discarded");
            }
        }
        "exit" => {
            if let Some(ctx) = edit_ctx.as_ref()
                && !ctx.changes.is_empty()
            {
                eprintln!(
                    "warning: {} uncommitted changes (use 'commit' or 'rollback')",
                    ctx.changes.len()
                );
            }
            *edit_ctx = None;
        }
        "help" | "?" => print_edit_help(),
        other => eprintln!("unknown command: {other}  (type ? for help)"),
    }
}

/// `edit <field>` inside an edit context descends into that object field.
/// Only object-typed fields are valid — walking into a scalar would give
/// subsequent `set`/`show` nowhere meaningful to operate.
pub(super) fn cmd_enter_nested(edit_ctx: &mut Option<EditContext>, parts: &[&str]) {
    if parts.len() < 2 {
        eprintln!("usage: edit <field>");
        return;
    }
    let Some(ctx) = edit_ctx.as_mut() else {
        return;
    };
    // `edit a.b.c` counts as the three-step descent `a` / `b` / `c`; each
    // step is validated below.
    descend_scope(ctx, &parts[1..]);
}

/// Walk `segments` into `ctx.path`, splitting each on `.` and validating
/// every hop through the current schema scope. All-or-nothing: if any
/// segment isn't an object field, the scope is left unchanged. Shared by
/// `edit <field>` mid-session and the `edit <resource> [name] <field> …`
/// fast-path from config mode.
pub(super) fn descend_scope(ctx: &mut EditContext, segments: &[&str]) {
    let resource = ctx.resource.clone();
    let mut candidate = ctx.path.clone();
    for seg in segments {
        for sub in field_to_json_key(seg) {
            if !is_object_field(&resource, &candidate, &sub.replace('_', "-")) {
                eprintln!("'{sub}' is not an object field here");
                return;
            }
            candidate.push(sub);
        }
    }
    ctx.path = candidate;
}

/// Pop one level off the edit scope; complains at the root.
pub(super) fn cmd_up(edit_ctx: &mut Option<EditContext>) {
    if let Some(ctx) = edit_ctx.as_mut()
        && ctx.path.pop().is_none()
    {
        eprintln!("(already at top)");
    }
}

/// Return to the resource root without leaving edit mode.
pub(super) fn cmd_top(edit_ctx: &mut Option<EditContext>) {
    if let Some(ctx) = edit_ctx.as_mut() {
        ctx.path.clear();
    }
}

/// `edit-expr` — open the current `expr` field in `$EDITOR` for free-form
/// multi-line editing. Useful for policy expressions which may span many lines
/// and contain comments. The edited text replaces the staged value; commit it
/// with `commit` like any other field change.
pub(super) fn cmd_edit_expr(edit_ctx: &mut Option<EditContext>) {
    let Some(ctx) = edit_ctx.as_mut() else {
        eprintln!("not in edit mode");
        return;
    };
    // Initial content: pending change > existing field > empty.
    let initial = ctx
        .changes
        .get("expr")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("sekisho-cli-{pid}.expr"));
    if let Err(e) = std::fs::write(&path, &initial) {
        eprintln!("error: failed to create temp file: {e}");
        return;
    }

    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".into());
    let status = std::process::Command::new(&editor).arg(&path).status();
    match status {
        Ok(s) if !s.success() => {
            eprintln!("editor exited with {s}; discarding changes");
            let _ = std::fs::remove_file(&path);
            return;
        }
        Err(e) => {
            eprintln!("error: failed to launch editor `{editor}`: {e}");
            let _ = std::fs::remove_file(&path);
            return;
        }
        _ => {}
    }

    let edited = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to read edited file: {e}");
            let _ = std::fs::remove_file(&path);
            return;
        }
    };
    let _ = std::fs::remove_file(&path);

    if edited == initial {
        eprintln!("(no changes)");
        return;
    }
    ctx.changes.insert("expr".into(), Value::String(edited));
    eprintln!(
        "expr staged ({} bytes); validate on `commit`",
        ctx.changes["expr"].as_str().unwrap_or("").len()
    );
}

async fn cmd_set(client: &ApiClient, edit_ctx: &mut Option<EditContext>, parts: &[&str]) {
    if parts.len() < 3 {
        eprintln!("usage: set <field> <value> [value2 ...]");
        return;
    }
    let ctx = match edit_ctx.as_mut() {
        Some(c) => c,
        None => return,
    };

    let field = parts[1];
    let value_str = parts[2..].join(" ");
    let relative_keys = field_to_json_key(field);

    // Resolve metadata at the leaf selected by the same normalized segments
    // that will build the wire patch. This keeps `set headers.remove ...`
    // equivalent to entering `headers` before setting `remove`.
    let metadata_field = relative_keys.last().map_or(field, String::as_str);
    let metadata_parents = &relative_keys[..relative_keys.len().saturating_sub(1)];
    let mut metadata_path = ctx.path.clone();
    metadata_path.extend(metadata_parents.iter().cloned());
    let array = is_array_field(&ctx.resource, &metadata_path, metadata_field);
    // `idp_ref` fields take a UUID on the wire but we let operators
    // type the IdP name directly; a value that parses as a UUID is
    // accepted as-is for backwards compatibility with existing
    // workflows and scripts.
    let idp_ref = !array && is_idp_ref_field(&ctx.resource, &metadata_path, metadata_field);
    let value = if array {
        Value::Array(
            parts[2..]
                .iter()
                .map(|v| Value::String(v.to_string()))
                .collect(),
        )
    } else if idp_ref {
        match resolve_idp_ref(client, value_str.trim()).await {
            Ok(v) => v,
            Err(msg) => {
                eprintln!("{msg}");
                return;
            }
        }
    } else {
        parse_value(&value_str)
    };

    let mut absolute_keys: Vec<String> = ctx.path.clone();
    absolute_keys.extend(relative_keys);
    set_nested(&mut ctx.changes, &absolute_keys, value);
    // Echo the top-level staged object so operators see what's been recorded
    // (when setting under a scope, this surfaces the whole parent entry).
    let top_key = absolute_keys
        .first()
        .cloned()
        .unwrap_or_else(|| field.to_string());
    eprintln!(
        "  {field} = {}",
        serde_json::to_string(ctx.changes.get(&top_key).unwrap_or(&Value::Null))
            .unwrap_or_default()
    );
}

/// `unset <field>` — stage a `null` for `<field>` so the upcoming `commit`
/// asks the server to clear the persisted value (RFC 7396 Merge Patch
/// semantics). Fields whose Rust type requires a value — a bare `String`
/// without `#[serde(default)]`, for example — will be rejected on commit.
/// To discard pending changes without touching the server, use `rollback`.
pub(super) fn cmd_unset(edit_ctx: &mut Option<EditContext>, parts: &[&str]) {
    if parts.len() < 2 {
        eprintln!("usage: unset <field>");
        return;
    }
    let ctx = match edit_ctx.as_mut() {
        Some(c) => c,
        None => return,
    };
    let mut absolute_keys: Vec<String> = ctx.path.clone();
    absolute_keys.extend(field_to_json_key(parts[1]));
    if absolute_keys.is_empty() {
        return;
    }
    set_nested(&mut ctx.changes, &absolute_keys, Value::Null);
    eprintln!("  staged unset {}", parts[1]);
}

/// Within edit mode, `show` displays the current state of the resource being
/// edited — base value (fetched fresh from the API) overlaid with any staged
/// changes (RFC 7396 merge). For new resources (no base yet) only the staged
/// values are shown. Pending-change count is appended so the operator can tell
/// at a glance whether the displayed value matches what's persisted.
async fn cmd_show_edit(client: &ApiClient, edit_ctx: &Option<EditContext>) {
    let Some(ctx) = edit_ctx else {
        eprintln!("not in edit mode");
        return;
    };
    if ctx.is_new {
        if ctx.changes.is_empty() {
            eprintln!("(no fields set; use `set <field> <value>`)");
        } else {
            let root = Value::Object(ctx.changes.clone());
            match narrow_to_path(&root, &ctx.path) {
                Some(v) => print_json(v),
                None => eprintln!("(nothing staged at {})", ctx.path.join(".")),
            }
            eprintln!(
                "(new {} — pending: {} field(s))",
                ctx.resource,
                ctx.changes.len()
            );
        }
        return;
    }
    let path = resource_api_path(&ctx.resource);
    let url = if is_singleton(&ctx.resource) {
        path.to_string()
    } else {
        let id = ctx.id.as_deref().unwrap_or("");
        format!("{path}/{id}")
    };
    let mut base = match client.get(&url).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error fetching base: {e}");
            return;
        }
    };
    if !ctx.changes.is_empty() {
        json_merge_patch(&mut base, &Value::Object(ctx.changes.clone()));
    }
    match narrow_to_path(&base, &ctx.path) {
        Some(v) => {
            print_json(v);
            annotate_idp_refs(client, &ctx.resource, v).await;
        }
        None => eprintln!("(nothing at {})", ctx.path.join(".")),
    }
    if !ctx.changes.is_empty() {
        eprintln!("(pending: {} field(s))", ctx.changes.len());
    }
}

async fn cmd_commit(client: &ApiClient, edit_ctx: &mut Option<EditContext>) {
    let ctx = match edit_ctx.as_ref() {
        Some(c) => c,
        None => return,
    };

    if ctx.changes.is_empty() && !ctx.is_new {
        eprintln!("nothing to commit");
        return;
    }

    let body = Value::Object(ctx.changes.clone());
    let path = resource_api_path(&ctx.resource);

    let result = if ctx.is_new {
        client.post(path, &body).await
    } else if is_singleton(&ctx.resource) {
        // PATCH /config or /instance (singleton)
        client.patch(path, &body).await
    } else {
        let id = ctx.id.as_deref().unwrap_or("");
        client.patch(&format!("{path}/{id}"), &body).await
    };

    match result {
        Ok(v) => {
            eprintln!("committed:");
            print_json(&v);
            // The server signals "this took effect in the DB but needs
            // a daemon restart to observe" via `_restart_required`. The
            // /config handler sets it to an array of fields; /instance
            // sets it to a plain `true`. Surface either form so the
            // operator doesn't wonder why their change didn't kick in.
            if let Some(r) = v.get("_restart_required")
                && !r.is_null()
                && r.as_bool() != Some(false)
            {
                eprintln!("(daemon restart required for this change to take effect)");
            }
            let resource = ctx.resource.clone();
            // Pull the fresh list so completion shows the new/renamed item.
            refresh_names(client, &resource).await;
            // Keep edit context so the user can continue editing the same resource.
            if let Some(c) = edit_ctx.as_mut() {
                c.changes.clear();
                if c.is_new {
                    c.is_new = false;
                    if let Some(id) = v.get("id").and_then(|id| id.as_str()) {
                        c.id = Some(id.to_string());
                    }
                }
            }
        }
        Err(e) => eprintln!("commit failed: {e}"),
    }
}

/// `edit <resource> [name] [field …]` — config-mode entry into edit mode.
/// Fetches the named instance (or accepts the singleton's lack of name),
/// optionally descends straight into a nested scope.
pub(super) async fn cmd_edit(
    client: &ApiClient,
    edit_ctx: &mut Option<EditContext>,
    parts: &[&str],
    rl: &mut Editor<ShellHelper, DefaultHistory>,
) {
    if parts.len() < 2 {
        eprintln!("usage: edit <resource> [name] [field ...]");
        return;
    }
    let resource = parts[1];

    if is_singleton(resource) {
        // Singleton resources (`sekisho`, `instance`) — no name
        // argument required. Trailing tokens after `edit <resource>`
        // descend the field tree so `edit sekisho acme-email` or
        // `edit instance cluster-db-url` drop straight into scope.
        let mut ctx = EditContext {
            resource: resource.into(),
            id: None,
            name: "global".into(),
            changes: Map::new(),
            is_new: false,
            path: Vec::new(),
        };
        if parts.len() > 2 {
            descend_scope(&mut ctx, &parts[2..]);
        }
        let path_copy = ctx.path.clone();
        let resource_copy = ctx.resource.clone();
        *edit_ctx = Some(ctx);
        if let Some(h) = rl.helper_mut() {
            h.edit_resource = Some(resource_copy);
            h.edit_path = path_copy;
        }
        return;
    }

    if parts.len() < 3 {
        eprintln!("usage: edit <resource> <name-or-id>");
        return;
    }
    let identifier = parts[2];
    let path = resource_api_path(resource);
    if path.is_empty() {
        eprintln!("unknown resource: {resource}");
        return;
    }

    let item_path = format!("{path}/{identifier}");
    let (id, name) = match client.get(&item_path).await {
        Ok(v) => {
            let id = v
                .get("id")
                .and_then(|n| n.as_str())
                .unwrap_or(identifier)
                .to_string();
            let name = v
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or(identifier)
                .to_string();
            (id, name)
        }
        Err(_) => match client.get_list(path).await {
            Ok(items) => {
                match items
                    .iter()
                    .find(|i| i.get("name").and_then(|n| n.as_str()) == Some(identifier))
                {
                    Some(item) => {
                        let id = item
                            .get("id")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        (id, identifier.to_string())
                    }
                    None => {
                        eprintln!("not found: {identifier}");
                        return;
                    }
                }
            }
            _ => {
                eprintln!("not found: {identifier}");
                return;
            }
        },
    };

    let mut ctx = EditContext {
        resource: resource.to_string(),
        id: Some(id),
        name,
        changes: Map::new(),
        is_new: false,
        path: Vec::new(),
    };
    // `edit route foo access` drops us straight into route/foo/access —
    // anything beyond the identifier is treated as an initial descent.
    if parts.len() > 3 {
        descend_scope(&mut ctx, &parts[3..]);
    }
    let path_copy = ctx.path.clone();
    *edit_ctx = Some(ctx);
    if let Some(h) = rl.helper_mut() {
        h.edit_resource = Some(resource.to_string());
        h.edit_path = path_copy;
    }
}

pub(super) async fn cmd_create_config(
    _client: &ApiClient,
    edit_ctx: &mut Option<EditContext>,
    parts: &[&str],
    rl: &mut Editor<ShellHelper, DefaultHistory>,
) {
    if parts.len() < 3 {
        eprintln!("usage: create <route|idp> <name>");
        return;
    }
    let resource = parts[1];
    let name = parts[2];

    if resource_api_path(resource).is_empty() {
        eprintln!("unknown resource: {resource}");
        return;
    }

    let mut changes = Map::new();
    changes.insert("name".into(), Value::String(name.into()));

    *edit_ctx = Some(EditContext {
        resource: resource.to_string(),
        id: None,
        name: name.to_string(),
        changes,
        is_new: true,
        path: Vec::new(),
    });

    if let Some(h) = rl.helper_mut() {
        h.edit_resource = Some(resource.to_string());
        h.edit_path.clear();
    }
    eprintln!("creating new {resource} '{name}' — use 'set' to configure, then 'commit'");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_at(resource: &str, path: Vec<&str>) -> EditContext {
        EditContext {
            resource: resource.into(),
            id: None,
            name: "x".into(),
            changes: Map::new(),
            is_new: false,
            path: path.into_iter().map(String::from).collect(),
        }
    }

    fn test_client() -> ApiClient {
        let pin =
            "sekisho-rpk-v1:ed25519:MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .parse()
                .unwrap();
        ApiClient::new("https://127.0.0.1:1", "test-key", &pin).unwrap()
    }

    /// An array reached by dotted path from the resource root stages as an array.
    /// This failed before: the dotted name was looked up as a whole, found no
    /// match in the root scope, and the value went to the server as a string.
    #[tokio::test]
    async fn cmd_set_stages_root_dotted_array() {
        let mut ctx = Some(ctx_at("idp", vec![]));

        cmd_set(
            &test_client(),
            &mut ctx,
            &["set", "oidc_config.scopes", "openid", "email"],
        )
        .await;

        assert_eq!(
            Value::Object(ctx.unwrap().changes),
            json!({ "oidc_config": { "scopes": ["openid", "email"] } })
        );
    }

    /// The dotted form and descending with `edit` produce the same staged JSON.
    /// They are two spellings of one operation and must not diverge.
    #[tokio::test]
    async fn cmd_set_root_dotted_array_matches_nested_edit() {
        let client = test_client();
        let mut dotted = Some(ctx_at("idp", vec![]));
        let mut nested = Some(ctx_at("idp", vec!["oidc_config"]));

        cmd_set(
            &client,
            &mut dotted,
            &["set", "oidc_config.scopes", "openid", "email"],
        )
        .await;
        cmd_set(&client, &mut nested, &["set", "scopes", "openid", "email"]).await;

        assert_eq!(dotted.unwrap().changes, nested.unwrap().changes);
    }

    /// The fix generalises: arrays at the root and arrays nested under other
    /// objects both stage correctly, not just the one field that prompted it.
    #[tokio::test]
    async fn cmd_set_stages_other_nested_and_top_level_arrays() {
        let client = test_client();
        let mut headers = Some(ctx_at("route", vec![]));
        let mut upstreams = Some(ctx_at("route", vec![]));

        cmd_set(
            &client,
            &mut headers,
            &["set", "headers.remove", "cookie", "authorization"],
        )
        .await;
        cmd_set(
            &client,
            &mut upstreams,
            &["set", "to", "http://a.example", "http://b.example"],
        )
        .await;

        assert_eq!(
            Value::Object(headers.unwrap().changes),
            json!({ "headers": { "remove": ["cookie", "authorization"] } })
        );
        assert_eq!(
            Value::Object(upstreams.unwrap().changes),
            json!({ "to": ["http://a.example", "http://b.example"] })
        );
    }

    /// Scalars reached by dotted path keep their old behaviour, and a dotted path
    /// whose parent is not an object is still passed through rather than
    /// silently reshaped.
    #[tokio::test]
    async fn cmd_set_keeps_dotted_scalar_and_invalid_parent_scalar() {
        let client = test_client();
        let mut scalar = Some(ctx_at("idp", vec![]));
        let mut invalid = Some(ctx_at("idp", vec![]));

        cmd_set(
            &client,
            &mut scalar,
            &["set", "oidc_config.prompt", "login", "consent"],
        )
        .await;
        cmd_set(
            &client,
            &mut invalid,
            &["set", "oidc_config.missing.scopes", "one", "two"],
        )
        .await;

        assert_eq!(
            Value::Object(scalar.unwrap().changes),
            json!({ "oidc_config": { "prompt": "login consent" } })
        );
        assert_eq!(
            Value::Object(invalid.unwrap().changes),
            json!({ "oidc_config": { "missing": { "scopes": "one two" } } })
        );
    }

    #[test]
    fn edit_prompt_includes_path() {
        let ctx = ctx_at("route", vec!["access"]);
        assert_eq!(
            edit_prompt("jump", &ctx),
            "sekisho@jump edit route/x/access> "
        );
    }

    #[test]
    fn edit_prompt_at_root_has_no_trailing_path() {
        let ctx = ctx_at("route", vec![]);
        assert_eq!(edit_prompt("jump", &ctx), "sekisho@jump edit route/x> ");
    }

    #[test]
    fn edit_prompt_for_singleton_omits_instance_name() {
        let ctx = ctx_at("sekisho", vec![]);
        assert_eq!(edit_prompt("jump", &ctx), "sekisho@jump edit sekisho> ");
    }

    #[test]
    fn edit_prompt_for_singleton_with_nested_path() {
        let ctx = ctx_at("sekisho", vec!["acme_email"]);
        assert_eq!(
            edit_prompt("jump", &ctx),
            "sekisho@jump edit sekisho/acme_email> "
        );
    }

    #[test]
    fn cmd_enter_nested_descends_single_object() {
        // `route.access` is a real object with nested fields; descent
        // must land inside it.
        let mut ctx = Some(ctx_at("route", vec![]));
        cmd_enter_nested(&mut ctx, &["edit", "access"]);
        assert_eq!(ctx.as_ref().unwrap().path, vec!["access"]);
    }

    #[test]
    fn cmd_enter_nested_rejects_scalar_field() {
        let mut ctx = Some(ctx_at("route", vec![]));
        cmd_enter_nested(&mut ctx, &["edit", "from"]);
        assert!(ctx.as_ref().unwrap().path.is_empty());
    }

    #[test]
    fn cmd_enter_nested_rejects_partially_invalid_multi_segment() {
        let mut ctx = Some(ctx_at("route", vec![]));
        // First segment descends into `access`; second does not exist
        // at that level → entire descent is rejected.
        cmd_enter_nested(&mut ctx, &["edit", "access.nonexistent"]);
        assert!(ctx.as_ref().unwrap().path.is_empty());
    }

    #[test]
    fn descend_scope_accepts_single_object_token() {
        let mut ctx = ctx_at("route", vec![]);
        descend_scope(&mut ctx, &["access"]);
        assert_eq!(ctx.path, vec!["access"]);
    }

    #[test]
    fn descend_scope_stops_at_scalar() {
        let mut ctx = ctx_at("route", vec![]);
        descend_scope(&mut ctx, &["from", "x"]);
        assert!(ctx.path.is_empty());
    }

    #[test]
    fn cmd_unset_stages_null_at_root() {
        // `api_listen` lives on `instance` after the listen-config
        // move; `unset` against the instance singleton stages the
        // explicit-null marker so the merge-patch on the server
        // clears the row.
        let mut ctx = Some(ctx_at("instance", vec![]));
        cmd_unset(&mut ctx, &["unset", "api-listen"]);
        assert_eq!(
            Value::Object(ctx.as_ref().unwrap().changes.clone()),
            json!({ "api_listen": null })
        );
    }

    #[test]
    fn cmd_unset_stages_null_at_nested_scope() {
        let mut ctx = Some(ctx_at("route", vec!["access"]));
        cmd_unset(&mut ctx, &["unset", "policy"]);
        assert_eq!(
            Value::Object(ctx.as_ref().unwrap().changes.clone()),
            json!({ "access": { "policy": null } })
        );
    }
}
