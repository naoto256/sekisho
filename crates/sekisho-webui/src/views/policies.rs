//! Policy views — DSL expression + optional description.

use maud::{Markup, html};
use serde_json::Value;

use super::{extract_id, render_cell};

pub fn list(items: &[Value]) -> Markup {
    html! {
        hgroup {
            h2 { "Policies" }
            p class="muted" {
                "Named authorization expressions. Referenced from routes as "
                code { "policy.<name>" } "."
            }
        }
        p class="toolbar" {
            a href="/policies/new" role="button" class="primary" { "Create policy" }
        }
        table class="resource-list striped" {
            thead { tr { th { "Name" } th { "Expression" } th class="actions" { "Actions" } } }
            tbody {
                @for item in items {
                    tr {
                        td {
                            @if let Some(id) = extract_id(item) {
                                a href=(format!("/policies/{id}")) { (render_cell(item, "name")) }
                            } @else {
                                (render_cell(item, "name"))
                            }
                        }
                        td { code class="expr" { (render_cell(item, "expr")) } }
                        td class="actions" {
                            @if let Some(id) = extract_id(item) {
                                button
                                    class="destructive"
                                    hx-delete=(format!("/policies/{id}"))
                                    hx-confirm="Delete this policy?"
                                    hx-target="closest tr"
                                    hx-swap="outerHTML"
                                    { "Delete" }
                            }
                        }
                    }
                }
                @if items.is_empty() {
                    tr { td colspan="3" class="muted center" { "No policies yet." } }
                }
            }
        }
    }
}

pub fn new_form() -> Markup {
    form_body(None)
}

pub fn edit_form(item: &Value) -> Markup {
    form_body(Some(item))
}

fn form_body(item: Option<&Value>) -> Markup {
    let name = item
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // Server's `Policy` struct stores the expression under `expr`; the
    // prior UI field `expression` silently dropped on the wire.
    let expr = item
        .and_then(|v| v.get("expr"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let action = match item.and_then(extract_id) {
        Some(id) => format!("/policies/{id}"),
        None => "/policies".into(),
    };
    let creating = item.is_none();
    html! {
        hgroup {
            h2 { @if creating { "Create policy" } @else { "Edit policy " code { (name) } } }
        }
        form method="post" action=(action) class="stack" {
            label { "Name" input type="text" name="name" value=(name) required; }
            label {
                "Expression"
                textarea name="expr" rows="4" class="mono" placeholder="claim.groups in [\"admins\"] and client.ip in [\"10.0.0.0/8\"]" { (expr) }
                small class="muted" {
                    "Policy DSL — boolean expression over "
                    code { "claim" } ", " code { "client" } ", " code { "request" } ", "
                    code { "time" } ", " code { "date" } "."
                }
            }
            div class="toolbar" {
                button type="submit" class="primary" { @if creating { "Create" } @else { "Save" } }
                a href="/policies" role="button" class="secondary outline" { "Cancel" }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{edit_form, new_form};

    fn assert_exact_policy_namespaces(html: &str) {
        for namespace in ["claim", "client", "request", "time", "date"] {
            assert!(
                html.contains(&format!("<code>{namespace}</code>")),
                "missing policy namespace {namespace}"
            );
        }
        assert!(!html.contains("<code>session</code>"));
    }

    /// Both forms advertise the same namespaces the evaluator implements, so the
    /// UI cannot suggest a namespace a policy would then fail to parse.
    #[test]
    fn new_and_edit_forms_show_the_exact_policy_namespace_set() {
        assert_exact_policy_namespaces(&new_form().into_string());
        assert_exact_policy_namespaces(
            &edit_form(&json!({"id": "policy-1", "name": "admins", "expr": "true"})).into_string(),
        );
    }
}
