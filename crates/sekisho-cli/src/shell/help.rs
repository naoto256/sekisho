//! Help text for the three shell modes.
//!
//! The resource lists in each block are interpolated from
//! [`super::names::resource_names_for`] rather than typed out, so help cannot
//! advertise a verb the shell would reject or omit one it accepts. Everything
//! else — the prose, the argument shapes, the grouping — is written by hand,
//! because it explains things the resource table does not know.

use super::ShellMode;
use super::names::resource_names_for;

/// Operational-mode help: the verbs that read or switch things, plus the
/// immediate actions that have no staged form.
pub(super) fn operational_help() -> String {
    let show = resource_names_for(ShellMode::Operational, "show").join("|");
    let create = resource_names_for(ShellMode::Operational, "create").join("|");
    let delete = resource_names_for(ShellMode::Operational, "delete").join("|");
    format!(
        r#"operational commands:
  show <{show}> [name]       Show resource(s)
  create {create} <name> <management:read|management:write|management:admin> [...]
                               Create a scoped API key (immediate)
  delete <{delete}> <name-or-id>  Delete (immediate)
  enable route <name>          Enable a route (auto-acquires ACME cert if needed)
  disable route <name>         Take a route out of service (keeps config + cert)
  upload certificate <domain> <cert.pem> <key.pem>
                               Install a hand-minted certificate (for tls_downstream=custom)
  add encryption-key           Generate an inactive encryption key
  activate encryption-key <key-id>
                               Make an encryption key active
  retire encryption-key <key-id>
                               Retire an inactive encryption key
  rotate encryption-key        Re-encrypt stored data with the active key
  configure                    Enter configuration mode
  export <file.conf>           Export config to file
  import <file.conf>           Import config from file
  help / ?                     Show this help
  exit / quit                  Exit the shell

resources: {}"#,
        resource_names_for(ShellMode::Operational, "show").join(", ")
    )
}

/// The `_help()` functions build a string and the `print_*` wrappers emit it,
/// so the tests can assert on the text without capturing stderr.
pub(super) fn print_operational_help() {
    eprintln!("{}", operational_help());
}

/// Configuration-mode help. `edit` and `create` appear here and nowhere else,
/// because staging a change is what this mode is for.
pub(super) fn config_help() -> String {
    let show = resource_names_for(ShellMode::Config, "show").join("|");
    let edit = resource_names_for(ShellMode::Config, "edit").join("|");
    let create = resource_names_for(ShellMode::Config, "create").join("|");
    let delete = resource_names_for(ShellMode::Config, "delete").join("|");
    format!(
        r#"configuration mode commands:
  show <{show}> [name]    Show config resources
  edit <{edit}> [name]    Enter edit mode
  create <{create}> <name>         Create new (then set/commit)
  delete <{delete}> <name-or-id>   Delete
  export <file.conf>                Export config to file
  import <file.conf>                Import config from file
  help / ?                          Show this help
  exit                              Return to operational mode"#
    )
}

pub(super) fn print_config_help() {
    eprintln!("{}", config_help());
}

/// Edit-scope help. Static rather than generated: the commands here act on
/// whatever resource is being edited, so there is no resource list to
/// interpolate. The wording carries the distinctions that catch people out —
/// `unset` stages a null rather than deleting locally, `commit` is what
/// reaches the server, and `up`/`top` move within a nested object rather than
/// leaving the edit.
pub(super) fn edit_help() -> &'static str {
    r#"edit mode commands:
  set <field> <value>      Set a field value (scoped to current path)
  unset <field>            Clear a field (stage a null; commit asks the server to remove it)
  edit <field>             Descend into an object field (e.g. `edit access`)
  up                       Move up one level in the edit scope
  top                      Return to the resource root
  show                     Show the current scope (base + pending)
  commit                   Apply changes to the server
  rollback                 Discard all pending changes
  edit-expr                Edit pending JSON as an expression
  help / ?                 Show this help
  exit                     Leave edit mode (warns on uncommitted changes)"#
}

pub(super) fn print_edit_help() {
    eprintln!("{}", edit_help());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_resource_sets_match_capability_authority() {
        let operational = operational_help();
        assert!(
            operational.contains("delete <route|idp|certificate|api-key|session> <name-or-id>")
        );
        assert!(operational.contains("create api-key <name>"));
        assert!(!operational.contains("delete <acme-state"));
        assert!(!operational.contains("delete <encryption-key"));

        let config = config_help();
        assert!(config.contains("create <route|idp|policy> <name>"));
        assert!(config.contains("delete <route|idp|policy> <name-or-id>"));
    }

    #[test]
    fn all_mode_verbs_are_documented() {
        let operational = operational_help();
        for verb in super::super::OPERATIONAL_VERBS {
            assert!(
                operational.contains(verb),
                "missing operational verb {verb}"
            );
        }

        let config = config_help();
        for verb in super::super::CONFIG_VERBS {
            assert!(config.contains(verb), "missing config verb {verb}");
        }

        let edit = edit_help();
        for verb in super::super::edit::edit_verbs() {
            assert!(edit.contains(verb), "missing edit verb {verb}");
        }
    }
}
