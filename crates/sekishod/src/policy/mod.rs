//! Policy expression DSL.
//!
//! `Policy` is a named, reusable boolean expression evaluated against a session
//! and request context. The expression is a string (stored verbatim in the DB)
//! parsed into an AST and evaluated on each request.
//!
//! Field names are dot-separated paths inside one of these namespaces:
//!
//! | namespace   | source                                          |
//! |-------------|-------------------------------------------------|
//! | `claim.*`   | IdP-issued attribute (username, groups, ...)    |
//! | `client.*`  | network layer (IP, port, future mTLS cert)      |
//! | `request.*` | HTTP layer (method, path, host, headers)        |
//! | `time.*`    | request time (now, hour, minute)                |
//! | `date.*`    | request date (today, weekday)                   |
//!
//! Operators: `==` `!=` `<` `<=` `>` `>=` `~=` `!~` `in` `not in`.
//! Logical: `and` `or`, parentheses, `#` line comments. See `mdBook` chapter
//! "Policy Expression Language" for full grammar and examples.

pub mod ast;
pub mod evaluator;
pub mod lexer;
pub mod parser;

#[cfg(test)]
#[path = "cache_test.rs"]
mod cache_test;
#[cfg(test)]
#[path = "evaluator_test.rs"]
mod evaluator_test;
#[cfg(test)]
#[path = "lexer_test.rs"]
mod lexer_test;
#[cfg(test)]
#[path = "parser_test.rs"]
mod parser_test;

pub use evaluator::{EvalContext, evaluate};
pub use parser::parse;

/// Parse cache for policy expressions.
///
/// `evaluate_route_access` runs on every proxied request, and the same route's
/// `access.policy` string is re-tokenized + re-parsed each time. The parser
/// is cheap per call but unique expressions are bounded by the registered
/// route / Policy set — hundreds at most in realistic deployments — so we
/// can trade a few kilobytes of memory for avoiding the parse round trip
/// entirely on the hot path.
///
/// Key: the raw expression string. Value: `Arc<Expr>` so callers can hand a
/// `&Expr` to `evaluate` without copying the AST. Parse failures are not
/// cached so that fixing a broken expression takes effect immediately.
static EXPR_CACHE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<ast::Expr>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Parse `expr_str` into an `Arc<Expr>`, reusing a previously parsed AST if
/// the same string has been seen before. Errors mirror [`parse`] verbatim
/// and are intentionally never cached.
pub fn parse_cached(expr_str: &str) -> Result<std::sync::Arc<ast::Expr>, parser::ParseError> {
    {
        let cache = EXPR_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ast) = cache.get(expr_str) {
            return Ok(ast.clone());
        }
    }

    let ast = std::sync::Arc::new(parse(expr_str)?);
    let mut cache = EXPR_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    Ok(cache.entry(expr_str.to_string()).or_insert(ast).clone())
}
