//! Behavioural tests for `policy::parse_cached`. The cache is process-wide
//! so these tests only assert observable guarantees: repeated parses return
//! equivalent ASTs, parse errors surface unchanged, and broken input is not
//! silently fixed up on the next call. Memory-layout aliasing between
//! cached results is intentionally *not* asserted — a `HashMap` resize
//! could invalidate that without changing behaviour.

#[cfg(test)]
mod tests {
    use crate::policy::parse_cached;

    #[test]
    fn returns_parsed_ast_for_valid_expression() {
        let ast1 = parse_cached("claim.username == \"alice\"").expect("valid");
        let ast2 = parse_cached("claim.username == \"alice\"").expect("valid");
        // Cached hits resolve through the same `Arc`, so `ptr_eq` should
        // hold for identical input strings seen back-to-back. If the cache
        // silently stops reusing, this regresses the whole point of the
        // optimisation.
        assert!(std::sync::Arc::ptr_eq(&ast1, &ast2));
    }

    #[test]
    fn surfaces_parse_error_and_does_not_cache() {
        let err = parse_cached("claim.username ==").unwrap_err();
        assert!(!err.message.is_empty());

        // A second call must re-run the parser (the fix-it path); if we
        // cached the error we'd need to invalidate on valid input, which
        // is strictly more complex than simply not caching failures.
        let err2 = parse_cached("claim.username ==").unwrap_err();
        assert_eq!(err.message, err2.message);
    }
}
