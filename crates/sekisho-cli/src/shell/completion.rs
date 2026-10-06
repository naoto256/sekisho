//! Rustyline integration: tab completion, hinting, validation. All
//! synchronous trait impls — the names cache (`shell::names`) is the
//! bridge that lets us suggest server-side instance labels here
//! without blocking on an API call.

use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

use crate::resources::{descriptor, is_object_field, scope_fields};

use super::ShellMode;
use super::edit::edit_verbs;
use super::expand_verb;
use super::json::field_to_json_key;
use super::names::{cached_resource_names, resource_is_visible_in_completion, resource_names_for};
use super::{CONFIG_VERBS, OPERATIONAL_VERBS};

pub(super) struct ShellHelper {
    pub(super) edit_resource: Option<String>,
    /// Nested edit scope mirrored from `EditContext.path` so the synchronous
    /// completer can filter candidates to the current sub-tree.
    pub(super) edit_path: Vec<String>,
    pub(super) mode: ShellMode,
}

impl ShellHelper {
    pub(super) fn new() -> Self {
        Self {
            edit_resource: None,
            edit_path: Vec::new(),
            mode: ShellMode::Operational,
        }
    }
}

/// Resource names worth offering for this verb right now.
///
/// Starts from the shell's capability table and then drops anything that would
/// complete to a command the user cannot usefully run yet — a verb needing an
/// existing target with none cached, for instance. Completion may therefore
/// show less than the shell accepts, never more: typing a name that completion
/// withheld still works.
fn resource_type_candidates(mode: ShellMode, verb: &str) -> Vec<String> {
    resource_names_for(mode, verb)
        .into_iter()
        .filter(|resource| resource_is_visible_in_completion(mode, verb, resource))
        .map(str::to_string)
        .collect()
}

impl Completer for ShellHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let line = &line[..pos];
        let parts: Vec<&str> = line.split_whitespace().collect();
        let ends_with_space = line.ends_with(' ');
        let partial = if ends_with_space {
            ""
        } else {
            parts.last().copied().unwrap_or("")
        };
        let word_start = pos - partial.len();

        // Index of the word the cursor is currently typing.
        //   ""             → cursor_word=0 (top-level command)
        //   "s"            → cursor_word=0 (still typing the verb)
        //   "show "        → cursor_word=1 (typing first argument)
        //   "show ro"      → cursor_word=1
        //   "show route "  → cursor_word=2
        let cursor_word = if ends_with_space {
            parts.len()
        } else {
            parts.len().saturating_sub(1)
        };
        // Match against the canonical verb so an abbreviated prefix (e.g.
        // `sh conf<TAB>`) still picks the right arg-candidate branch below.
        // The completer only rewrites the partial under the cursor, so the
        // verb the user typed stays as-is in the buffer.
        let verb = if cursor_word == 0 {
            None
        } else {
            parts.first().copied().map(|raw| {
                let verbs: &[&str] = if self.edit_resource.is_some() {
                    edit_verbs()
                } else if self.mode == ShellMode::Config {
                    CONFIG_VERBS
                } else {
                    OPERATIONAL_VERBS
                };
                expand_verb(raw, verbs)
            })
        };
        let arg1 = if cursor_word >= 2 {
            parts.get(1).copied()
        } else {
            None
        };

        let mut candidates: Vec<String> = if let Some(resource) = self.edit_resource.as_deref() {
            // Inside edit context — candidates are scoped to the current
            // `edit_path` position in the resource tree.
            match cursor_word {
                0 => edit_verbs().iter().map(|s| s.to_string()).collect(),
                1 if matches!(verb, Some("set")) => {
                    // `set` wants a scalar the user can put a value into.
                    scope_fields(resource, &self.edit_path)
                        .into_iter()
                        .filter(|f| f.editable)
                        .map(|f| f.name.replace('_', "-"))
                        .collect()
                }
                1 if matches!(verb, Some("unset")) => {
                    // `unset` writes a null; valid on anything with an
                    // editable leaf somewhere in it (clearing the scalar
                    // directly, or blanking a whole sub-object).
                    scope_fields(resource, &self.edit_path)
                        .into_iter()
                        .filter(|f| f.has_editable_descendant())
                        .map(|f| f.name.replace('_', "-"))
                        .collect()
                }
                1 if matches!(verb, Some("edit")) => {
                    // `edit` descends — needs an object with something
                    // editable underneath, else the user just hits a
                    // dead end.
                    scope_fields(resource, &self.edit_path)
                        .into_iter()
                        .filter(|f| !f.children.is_empty() && f.has_editable_descendant())
                        .map(|f| f.name.replace('_', "-"))
                        .collect()
                }
                _ => Vec::new(),
            }
        } else if self.mode == ShellMode::Config {
            // Config mode
            match cursor_word {
                0 => CONFIG_VERBS.iter().map(|s| s.to_string()).collect(),
                1 => verb
                    .map(|verb| resource_type_candidates(ShellMode::Config, verb))
                    .unwrap_or_default(),
                _ => {
                    // 2+ tokens: instance-name completion at position 2,
                    // then scope descent for `edit`. Walks the tokens
                    // between the resource (or resource+instance) and the
                    // cursor position through the schema tree, so every
                    // deeper level offers the object fields at that scope.
                    if let (Some("edit"), Some(res)) = (verb, arg1) {
                        let Some(desc) = descriptor(res) else {
                            return Ok((word_start, Vec::new()));
                        };
                        let scope_start = if desc.directly_editable { 2 } else { 3 };
                        if !desc.directly_editable && cursor_word == 2 {
                            cached_resource_names(res)
                        } else if cursor_word >= scope_start {
                            let already: Vec<&str> = parts
                                .iter()
                                .skip(scope_start)
                                .take(cursor_word - scope_start)
                                .copied()
                                .collect();
                            let mut path: Vec<String> = Vec::new();
                            let mut stopped = false;
                            for tok in already {
                                for seg in field_to_json_key(tok) {
                                    if !is_object_field(res, &path, &seg.replace('_', "-")) {
                                        stopped = true;
                                        break;
                                    }
                                    path.push(seg);
                                }
                                if stopped {
                                    break;
                                }
                            }
                            if stopped {
                                Vec::new()
                            } else {
                                scope_fields(res, &path)
                                    .into_iter()
                                    .filter(|f| {
                                        !f.children.is_empty() && f.has_editable_descendant()
                                    })
                                    .map(|f| f.name.replace('_', "-"))
                                    .collect()
                            }
                        } else {
                            Vec::new()
                        }
                    } else if cursor_word == 2 {
                        // show/delete on a list resource: suggest instance names.
                        match (verb, arg1) {
                            (Some("show") | Some("delete"), Some(res))
                                if descriptor(res).is_some_and(|d| !d.directly_editable) =>
                            {
                                cached_resource_names(res)
                            }
                            _ => Vec::new(),
                        }
                    } else {
                        Vec::new()
                    }
                }
            }
        } else {
            // Operational mode
            match cursor_word {
                0 => OPERATIONAL_VERBS.iter().map(|s| s.to_string()).collect(),
                1 => verb
                    .map(|verb| resource_type_candidates(ShellMode::Operational, verb))
                    .unwrap_or_default(),
                2 => match (verb, arg1) {
                    (Some("show") | Some("delete"), Some(res))
                        if descriptor(res).is_some_and(|d| !d.directly_editable) =>
                    {
                        cached_resource_names(res)
                    }
                    (Some("enable") | Some("disable"), Some("route")) => {
                        cached_resource_names("route")
                    }
                    _ => Vec::new(),
                },
                _ => Vec::new(),
            }
        };

        candidates.retain(|c| c.starts_with(partial));
        candidates.sort();
        candidates.dedup();

        // Single-candidate completion commits the word outright, so append a
        // trailing space — the cursor then sits at the next argument's slot,
        // which is almost always what the user wants next.
        let unique = candidates.len() == 1;
        let matches: Vec<Pair> = candidates
            .into_iter()
            .map(|c| {
                let replacement = if unique { format!("{c} ") } else { c.clone() };
                Pair {
                    display: c,
                    replacement,
                }
            })
            .collect();

        Ok((word_start, matches))
    }
}

impl Hinter for ShellHelper {
    type Hint = String;
}
impl Highlighter for ShellHelper {}
impl Validator for ShellHelper {}
impl Helper for ShellHelper {}

#[cfg(test)]
mod tests {
    use super::super::names::store_resource_names;
    use super::*;
    use std::sync::Mutex;

    static COMPLETION_CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn complete_displays(helper: &ShellHelper, line: &str) -> Vec<String> {
        let history = rustyline::history::DefaultHistory::new();
        let ctx = rustyline::Context::new(&history);
        helper
            .complete(line, line.len(), &ctx)
            .unwrap()
            .1
            .into_iter()
            .map(|pair| pair.display)
            .collect()
    }

    /// Completion offers exactly what the shell accepts in operational mode —
    /// derived from the capability table, never a second hand-written list.
    #[test]
    fn operational_resource_completion_uses_capability_authority() {
        let helper = ShellHelper::new();
        assert_eq!(complete_displays(&helper, "create "), ["api-key"]);
        assert_eq!(complete_displays(&helper, "upload "), ["certificate"]);
        for verb in ["enable ", "disable "] {
            assert_eq!(complete_displays(&helper, verb), ["route"]);
        }
        for verb in ["add ", "activate ", "retire ", "rotate "] {
            assert_eq!(complete_displays(&helper, verb), ["encryption-key"]);
        }
    }

    /// The same for configuration mode, where the verb set differs.
    #[test]
    fn config_resource_completion_uses_capability_authority() {
        let mut helper = ShellHelper::new();
        helper.mode = ShellMode::Config;
        assert_eq!(
            complete_displays(&helper, "show "),
            ["config", "idp", "instance", "policy", "route", "sekisho"]
        );
        assert_eq!(
            complete_displays(&helper, "create "),
            ["idp", "policy", "route"]
        );
    }

    /// Completion derives from the registered verbs, so pin the resulting
    /// user-visible suggestions against reviving export or import.
    #[test]
    fn export_and_import_are_not_completed() {
        let operational = ShellHelper::new();
        let operational_verbs = complete_displays(&operational, "");
        assert!(!operational_verbs.iter().any(|verb| verb == "export"));
        assert!(!operational_verbs.iter().any(|verb| verb == "import"));

        let mut config = ShellHelper::new();
        config.mode = ShellMode::Config;
        let config_verbs = complete_displays(&config, "");
        assert!(!config_verbs.iter().any(|verb| verb == "export"));
        assert!(!config_verbs.iter().any(|verb| verb == "import"));
    }

    /// Instance-name completion follows the cache, and singletons complete
    /// without one because they have no name to look up.
    #[test]
    fn target_completion_reflects_cache_and_singleton_availability() {
        let _guard = COMPLETION_CACHE_TEST_LOCK.lock().unwrap();
        for resource in [
            "route",
            "idp",
            "policy",
            "certificate",
            "api-key",
            "session",
            "acme-state",
            "encryption-key",
        ] {
            store_resource_names(resource, Vec::new());
        }

        let operational = ShellHelper::new();
        assert!(complete_displays(&operational, "delete ").is_empty());

        let mut config = ShellHelper::new();
        config.mode = ShellMode::Config;
        assert!(complete_displays(&config, "delete ").is_empty());
        assert_eq!(complete_displays(&config, "edit "), ["instance", "sekisho"]);

        for resource in [
            "route",
            "idp",
            "policy",
            "certificate",
            "api-key",
            "session",
            "acme-state",
            "encryption-key",
        ] {
            store_resource_names(resource, vec!["present".into()]);
        }

        assert_eq!(
            complete_displays(&operational, "delete "),
            ["api-key", "certificate", "idp", "route", "session"]
        );
        assert_eq!(
            complete_displays(&config, "delete "),
            ["idp", "policy", "route"]
        );
        assert_eq!(
            complete_displays(&config, "edit "),
            ["idp", "instance", "policy", "route", "sekisho"]
        );
    }

    // ── Completer (abbreviated verb at arg position) ───────────
    //
    // Regression for the case where `sh conf<TAB>` produced no candidates
    // because the completer's `match` saw verb=="sh" and fell through. The
    // completer now expands the verb prefix internally for lookup while
    // leaving the typed verb in the buffer untouched (so the result is
    // `sh config `, not `show config `).
    #[test]
    fn complete_abbreviated_verb_expands_arg() {
        let helper = ShellHelper::new();
        let history = rustyline::history::DefaultHistory::new();
        let ctx = rustyline::Context::new(&history);
        let line = "sh conf";
        let (start, pairs) = helper.complete(line, line.len(), &ctx).unwrap();
        // `conf` starts at position 3 ("sh ".len()), and the unique match
        // appends a trailing space.
        assert_eq!(start, 3);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].display, "config");
        assert_eq!(pairs[0].replacement, "config ");
    }
}
