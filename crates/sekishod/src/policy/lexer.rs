//! Tokenizer for the Policy expression language.
//!
//! Produces a flat `Vec<Token>` with line/column info on every token so the
//! parser can emit "line 4, col 17" errors. Whitespace and `#` line comments
//! are skipped here; everything else becomes a `TokenKind`.

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // Literals
    Ident(String),
    String(String),
    Number(i64),
    Bool(bool),
    // Punctuation
    Dot,
    Comma,
    LParen,
    RParen,
    LBracket,
    RBracket,
    // Operators
    EqEq,      // ==
    NotEq,     // !=
    Lt,        // <
    Le,        // <=
    Gt,        // >
    Ge,        // >=
    TildeEq,   // ~=
    BangTilde, // !~
    // Keywords
    And,
    Or,
    In,
    Not,
    // End of input
    Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LexError {
    pub line: usize,
    pub col: usize,
    pub message: String,
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "lex error at line {}, col {}: {}",
            self.line, self.col, self.message
        )
    }
}
impl std::error::Error for LexError {}

pub fn tokenize(input: &str) -> Result<Vec<Token>, LexError> {
    Lexer::new(input).tokenize()
}

struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.chars().peekable(),
            line: 1,
            col: 1,
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.chars.peek().copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.next()?;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    fn err(&self, line: usize, col: usize, message: impl Into<String>) -> LexError {
        LexError {
            line,
            col,
            message: message.into(),
        }
    }

    fn tokenize(mut self) -> Result<Vec<Token>, LexError> {
        let mut tokens = Vec::new();
        while let Some(c) = self.peek() {
            let line = self.line;
            let col = self.col;

            // Skip whitespace and `#` line comments.
            if c.is_whitespace() {
                self.bump();
                continue;
            }
            if c == '#' {
                while matches!(self.peek(), Some(cc) if cc != '\n') {
                    self.bump();
                }
                continue;
            }

            // Single- and double-character punctuation / operators.
            if let Some(kind) = self.try_punct()? {
                tokens.push(Token { kind, line, col });
                continue;
            }

            // Literals and identifiers.
            let kind = match c {
                '"' => self.read_string(line, col)?,
                d if d.is_ascii_digit() => self.read_number(line, col)?,
                a if a.is_ascii_alphabetic() || a == '_' => self.read_ident(),
                _ => {
                    return Err(self.err(line, col, format!("unexpected character `{c}`")));
                }
            };
            tokens.push(Token { kind, line, col });
        }
        tokens.push(Token {
            kind: TokenKind::Eof,
            line: self.line,
            col: self.col,
        });
        Ok(tokens)
    }

    /// Recognize all single-/double-character punctuation tokens. Returns
    /// `Ok(None)` if the next character isn't punctuation (caller falls
    /// through to literals/identifiers).
    fn try_punct(&mut self) -> Result<Option<TokenKind>, LexError> {
        let c = self.peek().expect("only called after peek");
        let line = self.line;
        let col = self.col;
        let kind = match c {
            '(' => {
                self.bump();
                TokenKind::LParen
            }
            ')' => {
                self.bump();
                TokenKind::RParen
            }
            '[' => {
                self.bump();
                TokenKind::LBracket
            }
            ']' => {
                self.bump();
                TokenKind::RBracket
            }
            ',' => {
                self.bump();
                TokenKind::Comma
            }
            '.' => {
                self.bump();
                TokenKind::Dot
            }
            '=' => {
                self.bump();
                if self.peek() == Some('=') {
                    self.bump();
                    TokenKind::EqEq
                } else {
                    return Err(self.err(
                        line,
                        col,
                        "expected `==` (single `=` is not an operator)",
                    ));
                }
            }
            '!' => {
                self.bump();
                match self.peek() {
                    Some('=') => {
                        self.bump();
                        TokenKind::NotEq
                    }
                    Some('~') => {
                        self.bump();
                        TokenKind::BangTilde
                    }
                    _ => return Err(self.err(line, col, "expected `!=` or `!~` after `!`")),
                }
            }
            '<' => {
                self.bump();
                if self.peek() == Some('=') {
                    self.bump();
                    TokenKind::Le
                } else {
                    TokenKind::Lt
                }
            }
            '>' => {
                self.bump();
                if self.peek() == Some('=') {
                    self.bump();
                    TokenKind::Ge
                } else {
                    TokenKind::Gt
                }
            }
            '~' => {
                self.bump();
                if self.peek() == Some('=') {
                    self.bump();
                    TokenKind::TildeEq
                } else {
                    return Err(self.err(
                        line,
                        col,
                        "expected `~=` (single `~` is not an operator)",
                    ));
                }
            }
            _ => return Ok(None),
        };
        Ok(Some(kind))
    }

    fn read_string(&mut self, start_line: usize, start_col: usize) -> Result<TokenKind, LexError> {
        self.bump(); // opening "
        let mut s = String::new();
        loop {
            match self.peek() {
                Some('"') => {
                    self.bump();
                    return Ok(TokenKind::String(s));
                }
                Some('\\') => {
                    let esc_line = self.line;
                    let esc_col = self.col;
                    self.bump();
                    let escaped = match self.peek() {
                        Some('n') => '\n',
                        Some('t') => '\t',
                        Some('\\') => '\\',
                        Some('"') => '"',
                        Some(other) => {
                            return Err(self.err(
                                esc_line,
                                esc_col,
                                format!("unknown string escape `\\{other}`"),
                            ));
                        }
                        None => {
                            return Err(self.err(esc_line, esc_col, "unterminated string escape"));
                        }
                    };
                    self.bump();
                    s.push(escaped);
                }
                Some(_) => s.push(self.bump().unwrap()),
                None => {
                    return Err(self.err(start_line, start_col, "unterminated string literal"));
                }
            }
        }
    }

    fn read_number(&mut self, line: usize, col: usize) -> Result<TokenKind, LexError> {
        let mut buf = String::new();
        while matches!(self.peek(), Some(cc) if cc.is_ascii_digit()) {
            buf.push(self.bump().unwrap());
        }
        let n: i64 = buf
            .parse()
            .map_err(|e| self.err(line, col, format!("invalid number `{buf}`: {e}")))?;
        Ok(TokenKind::Number(n))
    }

    /// Identifier: lowercase letter or underscore start, then alnum / `_` /
    /// `-`. Hyphen is allowed because policy and claim names are commonly
    /// kebab-case (`soc-team`, `email-verified`); the DSL has no numeric
    /// subtraction so `-` is unambiguous between idents.
    fn read_ident(&mut self) -> TokenKind {
        let mut buf = String::new();
        while matches!(self.peek(), Some(cc) if cc.is_ascii_alphanumeric() || cc == '_' || cc == '-')
        {
            buf.push(self.bump().unwrap());
        }
        match buf.as_str() {
            "and" => TokenKind::And,
            "or" => TokenKind::Or,
            "in" => TokenKind::In,
            "not" => TokenKind::Not,
            "true" => TokenKind::Bool(true),
            "false" => TokenKind::Bool(false),
            _ => TokenKind::Ident(buf),
        }
    }
}
