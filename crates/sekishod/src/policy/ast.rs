//! AST for the Policy expression language.
//!
//! The grammar is small enough that the AST can be a single `Expr` enum with
//! boxed alternatives for recursion. Type-level invariants between `Op` and
//! `Operand` (e.g. `Op::In` only pairs with `Operand::List`) are enforced by
//! the parser, not by the type — collapsing them into separate variants would
//! force the evaluator to re-shape every match without buying real safety.

/// A parsed policy expression. `Expr::Cmp` covers comparisons (`==`, `<`,
/// `~=`, `in`, ...); `Expr::PolicyRef` is the boolean atom `policy.<name>`.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// `lhs or rhs` — short-circuit OR.
    Or(Box<Expr>, Box<Expr>),
    /// `lhs and rhs` — short-circuit AND.
    And(Box<Expr>, Box<Expr>),
    /// `field op operand` — leaf comparison.
    Cmp(FieldPath, Op, Operand),
    /// `policy.<name>` — recursive reference resolved by the evaluator.
    PolicyRef(String),
}

/// Dotted field path e.g. `claim.username`, `client.ip`,
/// `request.header.user_agent`. The first segment is the namespace
/// (`claim` / `client` / `request` / `time` / `date`) and the remainder
/// names the attribute within it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldPath {
    pub segments: Vec<String>,
}

impl FieldPath {
    pub fn new(segments: Vec<String>) -> Self {
        Self { segments }
    }

    /// Render back to source form (`claim.username` etc.). Used by error
    /// messages and tests.
    #[allow(dead_code)]
    pub fn as_string(&self) -> String {
        self.segments.join(".")
    }
}

/// Comparison operators. Pairing rules enforced by the parser:
///   - `In` / `NotIn` always carry `Operand::List`
///   - `RegexMatch` / `RegexNotMatch` always carry `Operand::Value(String)`
///   - all others carry `Operand::Value(_)`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    NotIn,
    RegexMatch,
    RegexNotMatch,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Value(Value),
    List(Vec<Value>),
}

/// A literal value. CIDR auto-detection happens at eval time on
/// `Value::String` (any string with `/` that parses as `IpNet` is treated as
/// a CIDR for IP-typed left operands).
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Number(i64),
    Bool(bool),
}
