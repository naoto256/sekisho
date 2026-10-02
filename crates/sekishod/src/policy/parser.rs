//! Recursive-descent parser for the Policy expression language.
//!
//! Grammar (informal):
//!
//!   expr        := or_expr
//!   or_expr     := and_expr ('or' and_expr)*
//!   and_expr    := atom ('and' atom)*
//!   atom        := '(' expr ')' | policy_ref | comparison
//!   policy_ref  := 'policy' '.' IDENT     -- only when not followed by an op
//!   comparison  := field op_or_in
//!   op_or_in    := cmp_op value
//!                | 'in' list
//!                | 'not' 'in' list
//!   cmp_op      := '==' | '!=' | '<' | '<=' | '>' | '>=' | '~=' | '!~'
//!   field       := IDENT ('.' IDENT)*
//!   value       := STRING | NUMBER | BOOL
//!   list        := '[' (value (',' value)*)? ']'
//!
//! Precedence: `or` binds looser than `and`. Use parentheses for the rest.

use super::ast::{Expr, FieldPath, Op, Operand, Value};
use super::lexer::{LexError, Token, TokenKind, tokenize};

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub line: usize,
    pub col: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "parse error at line {}, col {}: {}",
            self.line, self.col, self.message
        )
    }
}
impl std::error::Error for ParseError {}

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        Self {
            line: e.line,
            col: e.col,
            message: e.message,
        }
    }
}

pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let tokens = tokenize(input)?;
    let mut p = Parser { tokens, pos: 0 };
    let expr = p.parse_or()?;
    p.expect_eof()?;
    Ok(expr)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn peek_kind_at(&self, offset: usize) -> Option<&TokenKind> {
        self.tokens.get(self.pos + offset).map(|t| &t.kind)
    }

    fn bump(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        self.pos += 1;
        t
    }

    fn expect_eof(&self) -> Result<(), ParseError> {
        if matches!(self.peek().kind, TokenKind::Eof) {
            Ok(())
        } else {
            Err(self.error_here(format!(
                "expected end of expression, got {:?}",
                self.peek().kind
            )))
        }
    }

    fn error_here(&self, msg: String) -> ParseError {
        ParseError {
            line: self.peek().line,
            col: self.peek().col,
            message: msg,
        }
    }

    // ── precedence climbing ─────────────────────────────────────────────

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek().kind, TokenKind::Or) {
            self.bump();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_atom()?;
        while matches!(self.peek().kind, TokenKind::And) {
            self.bump();
            let right = self.parse_atom()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_atom(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek().kind, TokenKind::LParen) {
            return self.parse_paren();
        }
        if let Some(name) = self.try_take_policy_ref() {
            return Ok(Expr::PolicyRef(name));
        }
        self.parse_comparison()
    }

    fn parse_paren(&mut self) -> Result<Expr, ParseError> {
        self.bump(); // (
        let expr = self.parse_or()?;
        if !matches!(self.peek().kind, TokenKind::RParen) {
            return Err(self.error_here(format!("expected `)`, got {:?}", self.peek().kind)));
        }
        self.bump(); // )
        Ok(expr)
    }

    /// `policy.<name>` is a boolean atom only when *not* followed by a
    /// comparison operator. With `policy.foo == "bar"` the `policy.foo` path
    /// goes through normal field-comparison resolution (and resolves to
    /// nothing → false). Returns `None` and consumes nothing if the lookahead
    /// fails.
    fn try_take_policy_ref(&mut self) -> Option<String> {
        let head_is_policy = matches!(
            self.peek_kind_at(0),
            Some(TokenKind::Ident(s)) if s == "policy"
        );
        let dot = matches!(self.peek_kind_at(1), Some(TokenKind::Dot));
        let name = matches!(self.peek_kind_at(2), Some(TokenKind::Ident(_)));
        let next_is_op = matches!(
            self.peek_kind_at(3),
            Some(
                TokenKind::EqEq
                    | TokenKind::NotEq
                    | TokenKind::Lt
                    | TokenKind::Le
                    | TokenKind::Gt
                    | TokenKind::Ge
                    | TokenKind::TildeEq
                    | TokenKind::BangTilde
                    | TokenKind::In
                    | TokenKind::Not
            )
        );
        if !(head_is_policy && dot && name && !next_is_op) {
            return None;
        }
        self.bump(); // policy
        self.bump(); // .
        let name_tok = self.bump();
        match name_tok.kind {
            TokenKind::Ident(n) => Some(n),
            _ => unreachable!("guarded by lookahead above"),
        }
    }

    fn parse_field(&mut self) -> Result<FieldPath, ParseError> {
        let start = self.peek().clone();
        let mut segs = Vec::new();
        segs.push(self.expect_ident("expected field name (identifier)")?);
        while matches!(self.peek().kind, TokenKind::Dot) {
            self.bump();
            segs.push(self.expect_ident("expected identifier after `.`")?);
        }
        if let [namespace, kind, name] = segs.as_slice()
            && namespace == "request"
            && kind == "header"
            && crate::proxy::header_boundary::policy_request_header_name(name).is_none()
        {
            return Err(ParseError {
                line: start.line,
                col: start.col,
                message: format!("request.header may not reference proxy-owned header `{name}`"),
            });
        }
        Ok(FieldPath::new(segs))
    }

    fn expect_ident(&mut self, what: &str) -> Result<String, ParseError> {
        match self.peek().kind.clone() {
            TokenKind::Ident(s) => {
                self.bump();
                Ok(s)
            }
            other => Err(self.error_here(format!("{what}, got {other:?}"))),
        }
    }

    fn parse_comparison(&mut self) -> Result<Expr, ParseError> {
        let field = self.parse_field()?;
        let op = self.parse_op()?;
        let operand = match op {
            Op::In | Op::NotIn => Operand::List(self.parse_list()?),
            _ => Operand::Value(self.parse_value()?),
        };
        Ok(Expr::Cmp(field, op, operand))
    }

    fn parse_op(&mut self) -> Result<Op, ParseError> {
        let token = self.bump();
        match token.kind {
            TokenKind::EqEq => Ok(Op::Eq),
            TokenKind::NotEq => Ok(Op::Ne),
            TokenKind::Lt => Ok(Op::Lt),
            TokenKind::Le => Ok(Op::Le),
            TokenKind::Gt => Ok(Op::Gt),
            TokenKind::Ge => Ok(Op::Ge),
            TokenKind::TildeEq => Ok(Op::RegexMatch),
            TokenKind::BangTilde => Ok(Op::RegexNotMatch),
            TokenKind::In => Ok(Op::In),
            TokenKind::Not => {
                // `not in` is the only legal `not` placement at this position.
                if !matches!(self.peek().kind, TokenKind::In) {
                    return Err(self.error_here(format!(
                        "expected `in` after `not`, got {:?}",
                        self.peek().kind
                    )));
                }
                self.bump();
                Ok(Op::NotIn)
            }
            other => Err(ParseError {
                line: token.line,
                col: token.col,
                message: format!("expected comparison operator after field, got {other:?}"),
            }),
        }
    }

    fn parse_value(&mut self) -> Result<Value, ParseError> {
        let t = self.bump();
        match t.kind {
            TokenKind::String(s) => Ok(Value::String(s)),
            TokenKind::Number(n) => Ok(Value::Number(n)),
            TokenKind::Bool(b) => Ok(Value::Bool(b)),
            other => Err(ParseError {
                line: t.line,
                col: t.col,
                message: format!("expected value (string/number/bool), got {other:?}"),
            }),
        }
    }

    fn parse_list(&mut self) -> Result<Vec<Value>, ParseError> {
        if !matches!(self.peek().kind, TokenKind::LBracket) {
            return Err(self.error_here(format!(
                "expected `[` to start list, got {:?}",
                self.peek().kind
            )));
        }
        self.bump(); // [
        let mut items = Vec::new();
        if matches!(self.peek().kind, TokenKind::RBracket) {
            self.bump();
            return Ok(items);
        }
        loop {
            items.push(self.parse_value()?);
            match self.peek().kind {
                TokenKind::Comma => {
                    self.bump();
                }
                TokenKind::RBracket => {
                    self.bump();
                    return Ok(items);
                }
                _ => {
                    return Err(self.error_here(format!(
                        "expected `,` or `]` in list, got {:?}",
                        self.peek().kind
                    )));
                }
            }
        }
    }
}
