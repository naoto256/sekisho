//! Evaluator for parsed Policy expressions.
//!
//! Resolves field paths against the runtime context (session + request) and
//! folds the AST to a boolean. The evaluator is async because `policy.<name>`
//! triggers a `Store` lookup; a `visited` set bounds recursion in the
//! presence of cycles.
//!
//! Referenced-policy lookup errors and operand-shape mismatches return
//! `false`. A referenced-policy parse error logs at `warn` and returns
//! `false`. Regex compile errors log at `debug` and both regex operators
//! return `false`.

use super::ast::{Expr, FieldPath, Op, Operand, Value};
use super::parse_cached;
use crate::models::session::Session;
use crate::store::Store;
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::pin::Pin;

/// Runtime context for evaluation: session + request meta. Build with
/// `EvalContext::default()` and fill the fields you have; missing fields
/// resolve to an empty value list, against which all comparisons return
/// false.
#[derive(Default)]
pub struct EvalContext<'a> {
    pub session: Option<&'a Session>,
    pub client_ip: Option<IpAddr>,
    pub client_port: Option<u16>,
    pub request_method: Option<&'a str>,
    pub request_path: Option<&'a str>,
    pub request_host: Option<&'a str>,
    /// Lower-cased header name → value. Optional so callers (and tests) can
    /// skip building a map when not relevant.
    pub request_headers: Option<&'a HashMap<String, String>>,
}

/// Evaluate `expr` against `ctx`. Returns true iff the policy permits access.
/// `store` is consulted only for `policy.<name>` references.
pub async fn evaluate(expr: &Expr, ctx: &EvalContext<'_>, store: &Store) -> bool {
    let mut visited = HashSet::new();
    eval_inner(expr, ctx, store, &mut visited).await
}

// ── core dispatch ────────────────────────────────────────────────────────

// Recursive `Or` / `And` evaluation and the `PolicyRef` path back into
// `eval_inner` need an indirection with a known-sized return type. Boxing
// the future supplies that compile-time shape for the async recursion.
fn eval_inner<'a>(
    expr: &'a Expr,
    ctx: &'a EvalContext<'a>,
    store: &'a Store,
    visited: &'a mut HashSet<String>,
) -> Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
    Box::pin(async move {
        match expr {
            Expr::Or(a, b) => {
                eval_inner(a, ctx, store, visited).await || eval_inner(b, ctx, store, visited).await
            }
            Expr::And(a, b) => {
                eval_inner(a, ctx, store, visited).await && eval_inner(b, ctx, store, visited).await
            }
            Expr::PolicyRef(name) => eval_policy_ref(name, ctx, store, visited).await,
            Expr::Cmp(field, op, operand) => eval_cmp(field, *op, operand, ctx),
        }
    })
}

async fn eval_policy_ref(
    name: &str,
    ctx: &EvalContext<'_>,
    store: &Store,
    visited: &mut HashSet<String>,
) -> bool {
    if !visited.insert(name.to_string()) {
        tracing::debug!(policy = name, "policy reference cycle detected");
        return false;
    }
    let result = match store.get_policy_by_name(name).await {
        Ok(policy) => match parse_cached(&policy.expr) {
            Ok(parsed) => eval_inner(&parsed, ctx, store, visited).await,
            Err(e) => {
                tracing::warn!(policy = name, error = %e, "referenced policy failed to parse");
                false
            }
        },
        Err(e) => {
            tracing::debug!(policy = name, error = %e, "referenced policy not found");
            false
        }
    };
    visited.remove(name);
    result
}

// ── comparison ───────────────────────────────────────────────────────────

fn eval_cmp(field: &FieldPath, op: Op, operand: &Operand, ctx: &EvalContext<'_>) -> bool {
    let resolved = resolve_field(field, ctx);
    if resolved.is_empty() {
        return false;
    }
    match (op, operand) {
        (Op::In, Operand::List(values)) => values.iter().any(|v| any_matches(&resolved, Op::Eq, v)),
        (Op::NotIn, Operand::List(values)) => {
            !values.iter().any(|v| any_matches(&resolved, Op::Eq, v))
        }
        // The parser pairs `In`/`NotIn` with a List and other operators
        // with a Value. A manually-constructed AST that violates either
        // pairing returns false without logging or producing an error.
        (Op::In | Op::NotIn, _) | (_, Operand::List(_)) => false,
        (op, Operand::Value(v)) => any_matches(&resolved, op, v),
    }
}

/// True if any element of `resolved` satisfies `op` against `expected`.
/// Multi-valued fields (e.g. `claim.groups`) match if at least one value does.
fn any_matches(resolved: &[String], op: Op, expected: &Value) -> bool {
    resolved.iter().any(|r| value_matches(r, op, expected))
}

/// Compare a single resolved string against a literal value with the given
/// operator. CIDR is auto-detected on string literals containing `/` when the
/// resolved string parses as an IP address.
fn value_matches(resolved: &str, op: Op, expected: &Value) -> bool {
    if let Some(result) = try_cidr_match(resolved, op, expected) {
        return result;
    }
    match (op, expected) {
        (Op::Eq, Value::String(s)) => resolved.eq_ignore_ascii_case(s),
        (Op::Ne, Value::String(s)) => !resolved.eq_ignore_ascii_case(s),
        (Op::RegexMatch, Value::String(s)) => matches!(regex_is_match(s, resolved), Some(true)),
        (Op::RegexNotMatch, Value::String(s)) => {
            matches!(regex_is_match(s, resolved), Some(false))
        }
        (op, Value::Number(n)) => match resolved.parse::<i64>() {
            Ok(r) => num_compare(op, r, *n),
            Err(_) => false,
        },
        (Op::Eq, Value::Bool(b)) => resolved.parse::<bool>().map(|r| r == *b).unwrap_or(false),
        (Op::Ne, Value::Bool(b)) => resolved.parse::<bool>().map(|r| r != *b).unwrap_or(false),
        _ => false,
    }
}

/// CIDR check: if `expected` is a quoted CIDR string and `resolved` parses as
/// an IP address, perform `IpNet::contains`. Returns `None` when the inputs
/// don't look like a CIDR comparison so the caller falls through to ordinary
/// string semantics.
fn try_cidr_match(resolved: &str, op: Op, expected: &Value) -> Option<bool> {
    let s = match expected {
        Value::String(s) if s.contains('/') => s,
        _ => return None,
    };
    let net: IpNet = s.parse().ok()?;
    let ip: IpAddr = resolved.parse().ok()?;
    let inside = net.contains(&ip);
    Some(match op {
        Op::Eq => inside,
        Op::Ne => !inside,
        _ => false,
    })
}

/// Cache of compiled regex patterns seen in policy expressions.
///
/// Keys are regex literals from parsed policy expressions, not request
/// fields. Each distinct successfully compiled pattern observed over the
/// process lifetime remains in the map. Compile failures return no result and
/// are not inserted, so a later evaluation attempts compilation again.
static POLICY_REGEX_CACHE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<regex::Regex>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn regex_is_match(pattern: &str, haystack: &str) -> Option<bool> {
    // Fast path: look the pattern up under a short-lived lock and clone the
    // `Arc` out so `is_match` runs outside the critical section.
    {
        let cache = POLICY_REGEX_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(re) = cache.get(pattern) {
            return Some(re.is_match(haystack));
        }
    }

    match regex::Regex::new(pattern) {
        Ok(re) => {
            let re = std::sync::Arc::new(re);
            {
                let mut cache = POLICY_REGEX_CACHE.lock().unwrap_or_else(|e| e.into_inner());
                cache.entry(pattern.to_string()).or_insert(re.clone());
            }
            Some(re.is_match(haystack))
        }
        Err(e) => {
            tracing::debug!(pattern, error = %e, "regex failed to compile");
            None
        }
    }
}

fn num_compare(op: Op, lhs: i64, rhs: i64) -> bool {
    match op {
        Op::Eq => lhs == rhs,
        Op::Ne => lhs != rhs,
        Op::Lt => lhs < rhs,
        Op::Le => lhs <= rhs,
        Op::Gt => lhs > rhs,
        Op::Ge => lhs >= rhs,
        _ => false,
    }
}

// ── field resolution ─────────────────────────────────────────────────────

/// Resolve a dotted field path to zero or more string values from the
/// context. Multi-valued fields (`claim.groups`) return all values;
/// single-valued fields return a 1-element vec; missing fields return empty.
fn resolve_field(field: &FieldPath, ctx: &EvalContext<'_>) -> Vec<String> {
    let segs: Vec<&str> = field.segments.iter().map(String::as_str).collect();
    match segs.as_slice() {
        ["claim", rest @ ..] => resolve_claim(rest, ctx),
        ["client", rest @ ..] => resolve_client(rest, ctx),
        ["request", rest @ ..] => resolve_request(rest, ctx),
        ["time", rest @ ..] => resolve_time(rest),
        ["date", rest @ ..] => resolve_date(rest),
        _ => Vec::new(),
    }
}

fn resolve_client(rest: &[&str], ctx: &EvalContext<'_>) -> Vec<String> {
    match rest {
        ["ip"] => ctx
            .client_ip
            .map(|ip| vec![ip.to_string()])
            .unwrap_or_default(),
        ["port"] => ctx
            .client_port
            .map(|p| vec![p.to_string()])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn resolve_request(rest: &[&str], ctx: &EvalContext<'_>) -> Vec<String> {
    match rest {
        ["method"] => ctx
            .request_method
            .map(|m| vec![m.to_string()])
            .unwrap_or_default(),
        ["path"] => ctx
            .request_path
            .map(|p| vec![p.to_string()])
            .unwrap_or_default(),
        ["host"] => ctx
            .request_host
            .map(|h| vec![h.to_string()])
            .unwrap_or_default(),
        ["header", name] => {
            // The lexer accepts both `_` and `-` inside field identifiers.
            // Request-header resolution lowercases the DSL segment and
            // maps underscores to wire-name hyphens, so `user_agent` and
            // `user-agent` both look up `user-agent`.
            let Some(key) = crate::proxy::header_boundary::policy_request_header_name(name) else {
                return Vec::new();
            };
            ctx.request_headers
                .and_then(|h| h.get(&key))
                .map(|v| vec![v.clone()])
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

fn resolve_time(rest: &[&str]) -> Vec<String> {
    let now = chrono::Local::now();
    match rest {
        ["now"] => vec![now.format("%H:%M:%S").to_string()],
        ["hour"] => vec![now.format("%H").to_string()],
        ["minute"] => vec![now.format("%M").to_string()],
        _ => Vec::new(),
    }
}

fn resolve_date(rest: &[&str]) -> Vec<String> {
    let now = chrono::Local::now();
    match rest {
        ["today"] => vec![now.format("%Y-%m-%d").to_string()],
        ["weekday"] => vec![now.format("%a").to_string()],
        _ => Vec::new(),
    }
}

fn resolve_claim(rest: &[&str], ctx: &EvalContext<'_>) -> Vec<String> {
    let Some(session) = ctx.session else {
        return Vec::new();
    };
    match rest {
        // Built-in aliases derived from session fields.
        ["username"] => vec![session.user_id.clone()],
        ["groups"] => session.groups.clone(),
        ["domain"] => session
            .user_id
            .split('@')
            .nth(1)
            .map(|d| vec![d.to_ascii_lowercase()])
            .unwrap_or_default(),
        // `email` is a common alias: many IdPs send a dedicated `email`
        // claim, but the user_id is often the email too. Try both.
        ["email"] => session
            .claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(|v| vec![v.to_string()])
            .or_else(|| {
                session
                    .user_id
                    .contains('@')
                    .then(|| vec![session.user_id.clone()])
            })
            .unwrap_or_default(),
        // Generic claim lookup: walk JSON paths, flatten arrays at the leaf.
        _ => walk_claim_path(&session.claims, rest),
    }
}

/// Walk a dotted path inside `session.claims` and return the leaf flattened
/// to strings (object → empty, array → all elements stringified).
fn walk_claim_path(claims: &HashMap<String, serde_json::Value>, path: &[&str]) -> Vec<String> {
    let mut current =
        serde_json::Value::Object(claims.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
    for seg in path {
        current = match current {
            serde_json::Value::Object(ref m) => {
                m.get(*seg).cloned().unwrap_or(serde_json::Value::Null)
            }
            _ => return Vec::new(),
        };
        if current.is_null() {
            return Vec::new();
        }
    }
    json_to_strings(&current)
}

fn json_to_strings(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::Null => Vec::new(),
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Number(n) => vec![n.to_string()],
        serde_json::Value::Bool(b) => vec![b.to_string()],
        serde_json::Value::Array(a) => a.iter().flat_map(json_to_strings).collect(),
        serde_json::Value::Object(_) => Vec::new(),
    }
}
