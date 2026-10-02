//! Token-level tests for the policy DSL.
//!
//! Mostly about what the lexer *rejects*. The DSL decides access, so an input
//! the operator wrote one way and the lexer read another is an authorization
//! bug — hence cases like a single `=` being an error rather than being
//! charitably read as `==`.

#[cfg(test)]
mod tests {
    use super::super::lexer::{TokenKind, tokenize};

    fn kinds(input: &str) -> Vec<TokenKind> {
        tokenize(input)
            .unwrap()
            .into_iter()
            .map(|t| t.kind)
            .collect()
    }

    #[test]
    fn simple_eq() {
        let k = kinds(r#"claim.username == "alice""#);
        assert_eq!(
            k,
            vec![
                TokenKind::Ident("claim".into()),
                TokenKind::Dot,
                TokenKind::Ident("username".into()),
                TokenKind::EqEq,
                TokenKind::String("alice".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn comments_and_whitespace() {
        let k = kinds("# top\nclaim.x == \"y\"\n# end");
        assert!(k.contains(&TokenKind::Ident("claim".into())));
        assert!(k.contains(&TokenKind::String("y".into())));
    }

    #[test]
    fn list_with_numbers_and_bools() {
        let k = kinds("[1, 2, true, false]");
        assert_eq!(
            k,
            vec![
                TokenKind::LBracket,
                TokenKind::Number(1),
                TokenKind::Comma,
                TokenKind::Number(2),
                TokenKind::Comma,
                TokenKind::Bool(true),
                TokenKind::Comma,
                TokenKind::Bool(false),
                TokenKind::RBracket,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn keywords_and_operators() {
        let k = kinds("a in [b] and c not in [d] or e ~= f and g !~ h");
        assert!(k.contains(&TokenKind::In));
        assert!(k.contains(&TokenKind::And));
        assert!(k.contains(&TokenKind::Or));
        assert!(k.contains(&TokenKind::Not));
        assert!(k.contains(&TokenKind::TildeEq));
        assert!(k.contains(&TokenKind::BangTilde));
    }

    #[test]
    fn ge_le_gt_lt() {
        let k = kinds("a >= 1 and b <= 2 and c > 3 and d < 4");
        assert!(k.contains(&TokenKind::Ge));
        assert!(k.contains(&TokenKind::Le));
        assert!(k.contains(&TokenKind::Gt));
        assert!(k.contains(&TokenKind::Lt));
    }

    #[test]
    fn string_escapes() {
        let k = kinds(r#""line1\nline2 with \"quote\"""#);
        assert_eq!(
            k[0],
            TokenKind::String("line1\nline2 with \"quote\"".into())
        );
    }

    #[test]
    fn single_eq_is_error() {
        assert!(tokenize("a = 1").is_err());
    }

    #[test]
    fn unterminated_string_is_error() {
        assert!(tokenize(r#"a == "abc"#).is_err());
    }

    #[test]
    fn identifier_accepts_uppercase_and_mixed_case() {
        // Names like `DL_SOC` are natural for policy/group identifiers and
        // must tokenize to a single Ident — not bail at the leading uppercase.
        let k = kinds("policy.DL_SOC");
        assert_eq!(
            k,
            vec![
                TokenKind::Ident("policy".into()),
                TokenKind::Dot,
                TokenKind::Ident("DL_SOC".into()),
                TokenKind::Eof,
            ]
        );
        let k = kinds("MixedCase");
        assert_eq!(k[0], TokenKind::Ident("MixedCase".into()));
    }

    #[test]
    fn identifier_accepts_hyphen_in_middle() {
        // `soc-team` is a valid resource name and must round-trip through
        // the lexer too (leading character still has to be alphabetic).
        let k = kinds("policy.soc-team");
        assert_eq!(
            k,
            vec![
                TokenKind::Ident("policy".into()),
                TokenKind::Dot,
                TokenKind::Ident("soc-team".into()),
                TokenKind::Eof,
            ]
        );
    }
}
