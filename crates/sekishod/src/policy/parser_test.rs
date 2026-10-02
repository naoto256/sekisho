//! Grammar tests for the policy DSL.
//!
//! Precedence is the point. `and` binding tighter than `or`, and parentheses
//! overriding it, decide what a multi-clause policy actually means — an
//! operator who reads a rule one way while the evaluator reads it another gets
//! access control they did not write. The remaining cases pin the surface
//! syntax that the CLI and docs promise: `in` lists, `policy.<name>`
//! references, and regex operators.

#[cfg(test)]
mod tests {
    use super::super::ast::{Expr, Op, Operand, Value};
    use super::super::parser::parse;

    #[test]
    fn simple_eq() {
        let expr = parse(r#"claim.username == "alice""#).unwrap();
        match expr {
            Expr::Cmp(field, Op::Eq, Operand::Value(Value::String(s))) => {
                assert_eq!(field.as_string(), "claim.username");
                assert_eq!(s, "alice");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn and_or_precedence() {
        // a and b or c  ==  (a and b) or c
        let e = parse(r#"a == "x" and b == "y" or c == "z""#).unwrap();
        // top-level should be Or
        assert!(matches!(e, Expr::Or(_, _)));
    }

    #[test]
    fn parens_override_precedence() {
        // a or (b and c) — top-level is Or, right side is And
        let e = parse(r#"a == "x" or (b == "y" and c == "z")"#).unwrap();
        match e {
            Expr::Or(_, right) => assert!(matches!(*right, Expr::And(_, _))),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn in_list() {
        let e = parse(r#"claim.groups in ["A", "B"]"#).unwrap();
        match e {
            Expr::Cmp(_, Op::In, Operand::List(vs)) => assert_eq!(vs.len(), 2),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn not_in_list() {
        let e = parse(r#"claim.groups not in ["A"]"#).unwrap();
        assert!(matches!(e, Expr::Cmp(_, Op::NotIn, Operand::List(_))));
    }

    #[test]
    fn policy_ref_dot_syntax() {
        let e = parse("policy.soc-from-office").unwrap();
        match e {
            Expr::PolicyRef(name) => assert_eq!(name, "soc-from-office"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn policy_ref_in_boolean_combination() {
        // Boolean atoms — no comparison operator needed.
        let e = parse("policy.a or policy.b").unwrap();
        match e {
            Expr::Or(l, r) => {
                assert!(matches!(*l, Expr::PolicyRef(ref n) if n == "a"));
                assert!(matches!(*r, Expr::PolicyRef(ref n) if n == "b"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn regex_ops() {
        let e = parse(r#"request.path ~= "^/admin""#).unwrap();
        assert!(matches!(e, Expr::Cmp(_, Op::RegexMatch, _)));
        let e = parse(r#"request.path !~ "^/admin""#).unwrap();
        assert!(matches!(e, Expr::Cmp(_, Op::RegexNotMatch, _)));
    }

    #[test]
    fn multiline_with_comments() {
        let src = r#"
            # top comment
            (claim.groups in [
                "A",   # first group
                "B"
            ])
            and client.ip in ["192.168.0.0/24"]
        "#;
        let e = parse(src).unwrap();
        assert!(matches!(e, Expr::And(_, _)));
    }

    #[test]
    fn bare_identifier_is_field() {
        // Single-segment field name (no dot) is allowed by the grammar.
        let e = parse(r#"groups in ["A"]"#).unwrap();
        match e {
            Expr::Cmp(field, _, _) => assert_eq!(field.as_string(), "groups"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn syntax_error_has_position() {
        let err = parse(r#"a == "x" annd b == "y""#).unwrap_err();
        // After parsing `a == "x"`, the parser expects `and`/`or` or end.
        // `annd` is parsed as a fresh Ident, which yields "expected end of expression"
        // at line 1, somewhere around col 10.
        assert_eq!(err.line, 1);
        assert!(err.col > 8);
    }

    #[test]
    fn proxy_owned_request_headers_are_rejected_after_dsl_normalization() {
        for field in [
            "request.header.x-sekisho-user",
            "request.header.x_sekisho_user",
            "request.header.X_SEKISHO_FUTURE",
            "request.header.x-forwarded-for",
            "request.header.forwarded",
        ] {
            let error = parse(&format!(r#"{field} == "forged""#)).unwrap_err();
            assert_eq!(error.line, 1, "{field}");
            assert_eq!(error.col, 1, "{field}");
            assert!(error.message.contains("proxy-owned header"), "{error}");
        }
    }

    #[test]
    fn ordinary_claim_and_non_resolving_multisegment_fields_remain_parseable() {
        for source in [
            r#"request.header.x_request_source == "cron""#,
            r#"request.header.x-sekisho == "application-owned""#,
            r#"claim.x-sekisho-user == "issuer-owned""#,
            r#"request.header.x.sekisho == "non-resolving""#,
        ] {
            parse(source).unwrap_or_else(|error| panic!("{source}: {error}"));
        }
    }
}
