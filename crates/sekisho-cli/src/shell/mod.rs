//! Interactive shell (REPL) for sekisho-cli.
//!
//! Submodules:
//! - [`json`]: pure value-shape helpers (merge, narrow, parse, etc.)
//! - [`names`]: resource-name registry + tab-completion cache
//! - [`render`]: result rendering (route status, sessions table)
//! - [`idp_ref`]: `idp_ref` field resolution + annotation
//! - [`help`]: per-mode help text
//! - [`completion`]: rustyline `Completer` integration
//! - [`edit`]: `EditContext` + edit-mode commands
//! - [`ops`]: operational + config-mode commands
//!
//! This file holds the main loop, the verb tables, and the dispatch
//! that routes a line into the appropriate `cmd_*` in `edit` / `ops`.

mod completion;
mod edit;
mod help;
mod idp_ref;
mod json;
mod names;
mod ops;
mod render;

use rustyline::Editor;
use rustyline::error::ReadlineError;

use crate::api::ApiClient;
use completion::ShellHelper;
use edit::{EditContext, cmd_create_config, cmd_edit, edit_prompt, handle_edit_command};
use help::{print_config_help, print_operational_help};
use names::{prefetch_all_names, resource_is_allowed, resource_names_for};
use ops::{
    cmd_activate_encryption_key, cmd_add_encryption_key, cmd_create_api_key, cmd_delete,
    cmd_export, cmd_import, cmd_retire_encryption_key, cmd_rotate_encryption_key,
    cmd_set_route_enabled, cmd_show, cmd_show_all, cmd_upload_certificate,
};

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum ShellMode {
    Operational,
    Config,
}

/// Verbs accepted in each shell mode. Shared with the completer so tab
/// completion and dispatch-time prefix expansion agree on the vocabulary.
const OPERATIONAL_VERBS: &[&str] = &[
    "show",
    "create",
    "delete",
    "enable",
    "disable",
    "upload",
    "configure",
    "export",
    "import",
    // DEK ring rotation verbs. Each takes the singular `encryption-key`
    // resource name, consistent with `show encryption-key`.
    "add",
    "activate",
    "retire",
    "rotate",
    "exit",
    "quit",
    "help",
    "?",
];
const CONFIG_VERBS: &[&str] = &[
    "show", "edit", "create", "delete", "export", "import", "exit", "help", "?",
];

/// Expand a verb prefix to the unique matching entry in `candidates`, so
/// `conf<Enter>` runs `configure` without a tab. Exact matches win over
/// prefix matches to keep short verbs (`show` vs. a hypothetical
/// `show-something`) unambiguous. Returns `input` unchanged when no match
/// or more than one match is found — the dispatcher then falls through to
/// the usual "unknown command" path.
pub(super) fn expand_verb<'a>(input: &'a str, candidates: &[&'a str]) -> &'a str {
    let mut unique: Option<&'a str> = None;
    for c in candidates {
        if *c == input {
            return c;
        }
        if c.starts_with(input) {
            if unique.is_some() {
                return input;
            }
            unique = Some(c);
        }
    }
    unique.unwrap_or(input)
}

/// Fetch the *server's* hostname (via the management API) so the prompt
/// identifies which Sekisho daemon is on the other end of the socket, not
/// whichever box happens to be running sekisho-cli. Falls back to `?` if the
/// endpoint doesn't respond — better to keep the prompt readable than to
/// abort on what's cosmetic information.
async fn fetch_server_hostname(client: &ApiClient) -> String {
    match client.get("/_internal/host").await {
        Ok(v) => v
            .get("hostname")
            .and_then(|h| h.as_str())
            .unwrap_or("?")
            .to_string(),
        Err(_) => "?".into(),
    }
}

pub async fn run(client: ApiClient) {
    // Resource registry is version-locked and compile-time — see
    // `crate::resources`. Startup only needs the instance-name prefetch
    // (what's on the server right now) for tab completion.
    prefetch_all_names(&client).await;
    let host = fetch_server_hostname(&client).await;
    let helper = ShellHelper::new();
    // Completion behavior:
    //   - List shows all candidates on TAB when ambiguous
    //   - completion_show_all_if_ambiguous(false) = the common prefix is
    //     auto-inserted; if it resolves the choice down to one, the candidate
    //     is committed without a second TAB.
    let config = rustyline::Config::builder()
        .auto_add_history(false)
        .completion_type(rustyline::CompletionType::List)
        .completion_show_all_if_ambiguous(false)
        .build();
    let mut rl = match Editor::with_config(config) {
        Ok(editor) => editor,
        Err(e) => {
            eprintln!("failed to initialize shell: {e}");
            return;
        }
    };
    rl.set_helper(Some(helper));

    let mut mode = ShellMode::Operational;
    let mut edit_ctx: Option<EditContext> = None;

    loop {
        let prompt = if let Some(ctx) = edit_ctx.as_ref() {
            edit_prompt(&host, ctx)
        } else if mode == ShellMode::Config {
            format!("sekisho@{host}# ")
        } else {
            format!("sekisho@{host}> ")
        };

        let line = match rl.readline(&prompt) {
            Ok(line) => {
                rl.add_history_entry(&line).ok();
                line
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("error: {e}");
                break;
            }
        };

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        if edit_ctx.is_some() {
            handle_edit_command(&client, &mut edit_ctx, &parts, &mut rl).await;
            // Sync the completion helper to the post-command state: if we
            // left edit mode, clear both fields; otherwise mirror the
            // possibly-updated scope path.
            if let Some(h) = rl.helper_mut() {
                match edit_ctx.as_ref() {
                    None => {
                        h.edit_resource = None;
                        h.edit_path.clear();
                    }
                    Some(ctx) => {
                        h.edit_path = ctx.path.clone();
                    }
                }
            }
        } else if mode == ShellMode::Config {
            let verb = expand_verb(parts[0], CONFIG_VERBS);
            // Expand the resource argument too, so `show conf<Enter>` runs
            // `show config`. Unknown prefixes fall through unchanged and
            // the downstream handler emits its own "unknown resource".
            let resource_args = resource_names_for(ShellMode::Config, verb);
            let mut parts = parts.clone();
            parts[0] = verb;
            if !resource_args.is_empty() && parts.len() > 1 {
                parts[1] = expand_verb(parts[1], &resource_args);
            }
            match verb {
                "show" => {
                    if parts.len() == 1 {
                        // Bare `show` in config mode dumps every config
                        // resource together (JunOS-style "show configuration",
                        // equivalent to `show sekisho`).
                        cmd_show_all(&client).await;
                    } else if resource_is_allowed(ShellMode::Config, verb, parts[1]) {
                        cmd_show(&client, &parts).await;
                    } else {
                        let names = resource_names_for(ShellMode::Config, verb).join("|");
                        eprintln!("usage: show <{names}> [name]");
                    }
                }
                "edit" => {
                    if parts.len() >= 2 && resource_is_allowed(ShellMode::Config, verb, parts[1]) {
                        cmd_edit(&client, &mut edit_ctx, &parts, &mut rl).await;
                    } else {
                        let names = resource_names_for(ShellMode::Config, verb).join("|");
                        eprintln!("usage: edit <{names}> [name] [field ...]");
                    }
                }
                "create" => {
                    if parts.len() >= 3 && resource_is_allowed(ShellMode::Config, verb, parts[1]) {
                        cmd_create_config(&client, &mut edit_ctx, &parts, &mut rl).await;
                    } else {
                        let names = resource_names_for(ShellMode::Config, verb).join("|");
                        eprintln!("usage: create <{names}> <name>");
                    }
                }
                "delete" => {
                    if parts.len() >= 3 && resource_is_allowed(ShellMode::Config, verb, parts[1]) {
                        cmd_delete(&client, &parts).await;
                    } else {
                        let names = resource_names_for(ShellMode::Config, verb).join("|");
                        eprintln!("usage: delete <{names}> <name-or-id>");
                    }
                }
                "export" => cmd_export(&client, &parts).await,
                "import" => cmd_import(&client, &parts, &mut rl).await,
                "exit" => {
                    mode = ShellMode::Operational;
                    if let Some(h) = rl.helper_mut() {
                        h.mode = ShellMode::Operational;
                    }
                }
                "help" | "?" => print_config_help(),
                other => eprintln!("unknown command: {other}  (type ? for help)"),
            }
        } else {
            // Operational mode — same arg-prefix expansion treatment as
            // config mode so `sh conf<Enter>` works for resource names
            // just like the verb itself.
            let verb = expand_verb(parts[0], OPERATIONAL_VERBS);
            let resource_args = resource_names_for(ShellMode::Operational, verb);
            let mut parts = parts.clone();
            parts[0] = verb;
            if !resource_args.is_empty() && parts.len() > 1 {
                parts[1] = expand_verb(parts[1], &resource_args);
            }
            match verb {
                "show" => {
                    if parts.len() >= 2
                        && resource_is_allowed(ShellMode::Operational, verb, parts[1])
                    {
                        cmd_show(&client, &parts).await;
                    } else {
                        let names = resource_names_for(ShellMode::Operational, verb).join("|");
                        eprintln!("usage: show <{names}> [name]");
                    }
                }
                "create" => {
                    if parts.len() >= 4
                        && resource_is_allowed(ShellMode::Operational, verb, parts[1])
                    {
                        cmd_create_api_key(&client, parts[2], &parts[3..]).await;
                    } else {
                        eprintln!(
                            "usage: create api-key <name> <management:read|management:write|management:admin> [...]"
                        );
                    }
                }
                "delete" => {
                    if parts.len() >= 3
                        && resource_is_allowed(ShellMode::Operational, verb, parts[1])
                    {
                        cmd_delete(&client, &parts).await;
                    } else {
                        let names = resource_names_for(ShellMode::Operational, verb).join("|");
                        eprintln!(
                            "usage: delete <{names}> <name-or-id>\n  (for config resources, use configure mode)"
                        );
                    }
                }
                "enable" | "disable" => {
                    let want_enabled = verb == "enable";
                    if parts.len() >= 3
                        && resource_is_allowed(ShellMode::Operational, verb, parts[1])
                    {
                        cmd_set_route_enabled(&client, parts[2], want_enabled).await;
                    } else {
                        eprintln!("usage: {verb} route <name>");
                    }
                }
                "upload" => match (parts.get(1).copied(), parts.len()) {
                    (Some(resource), n)
                        if n >= 5
                            && resource_is_allowed(ShellMode::Operational, verb, resource) =>
                    {
                        cmd_upload_certificate(&client, parts[2], parts[3], parts[4]).await;
                    }
                    _ => {
                        eprintln!("usage: upload certificate <domain> <cert.pem> <key.pem>");
                    }
                },
                "configure" => {
                    mode = ShellMode::Config;
                    if let Some(h) = rl.helper_mut() {
                        h.mode = ShellMode::Config;
                    }
                    eprintln!("entering configuration mode");
                }
                "add" => match (parts.get(1).copied(), parts.len()) {
                    (Some(resource), _)
                        if resource_is_allowed(ShellMode::Operational, verb, resource) =>
                    {
                        cmd_add_encryption_key(&client).await
                    }
                    _ => eprintln!("usage: add encryption-key"),
                },
                "activate" => match (parts.get(1).copied(), parts.len()) {
                    (Some(resource), n)
                        if n >= 3
                            && resource_is_allowed(ShellMode::Operational, verb, resource) =>
                    {
                        cmd_activate_encryption_key(&client, parts[2]).await
                    }
                    _ => eprintln!("usage: activate encryption-key <key_id>"),
                },
                "retire" => match (parts.get(1).copied(), parts.len()) {
                    (Some(resource), n)
                        if n >= 3
                            && resource_is_allowed(ShellMode::Operational, verb, resource) =>
                    {
                        cmd_retire_encryption_key(&client, parts[2]).await
                    }
                    _ => eprintln!("usage: retire encryption-key <key_id>"),
                },
                "rotate" => match (parts.get(1).copied(), parts.len()) {
                    (Some(resource), _)
                        if resource_is_allowed(ShellMode::Operational, verb, resource) =>
                    {
                        cmd_rotate_encryption_key(&client).await
                    }
                    _ => eprintln!("usage: rotate encryption-key"),
                },
                "export" => cmd_export(&client, &parts).await,
                "import" => cmd_import(&client, &parts, &mut rl).await,
                "exit" | "quit" => break,
                "help" | "?" => print_operational_help(),
                other => eprintln!("unknown command: {other}  (type ? for help)"),
            }
        }
    }

    eprintln!("bye");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{is_config_resource, resource_api_path};

    #[test]
    fn resource_api_path_known_resources() {
        assert_eq!(resource_api_path("route"), "/routes");
        assert_eq!(resource_api_path("idp"), "/idps");
        assert_eq!(resource_api_path("policy"), "/policies");
        assert_eq!(resource_api_path("api-key"), "/api_keys");
        assert_eq!(resource_api_path("sekisho"), "/config");
    }

    #[test]
    fn resource_api_path_unknown_returns_empty() {
        assert_eq!(resource_api_path("widget"), "");
    }

    #[test]
    fn is_config_resource_classifies_correctly() {
        assert!(is_config_resource("route"));
        assert!(is_config_resource("sekisho"));
        assert!(!is_config_resource("session"));
        assert!(!is_config_resource("api-key"));
    }

    #[test]
    fn expand_verb_unique_prefix() {
        assert_eq!(expand_verb("conf", OPERATIONAL_VERBS), "configure");
        // `enable` and `exit`/`export` share `e`, but `en` is unique.
        assert_eq!(expand_verb("en", OPERATIONAL_VERBS), "enable");
    }

    #[test]
    fn expand_verb_exact_match_wins() {
        // `show` is a prefix of nothing else here, but ensure exact matches
        // short-circuit even if siblings would shadow them.
        assert_eq!(expand_verb("show", OPERATIONAL_VERBS), "show");
        assert_eq!(expand_verb("edit", edit::edit_verbs()), "edit");
    }

    #[test]
    fn expand_verb_ambiguous_returns_input() {
        // "e" prefixes both `edit` and `edit-expr` and `exit` — ambiguous.
        assert_eq!(expand_verb("e", edit::edit_verbs()), "e");
    }

    #[test]
    fn expand_verb_no_match_returns_input() {
        assert_eq!(expand_verb("banana", OPERATIONAL_VERBS), "banana");
    }
}
