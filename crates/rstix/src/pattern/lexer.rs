//! STIX pattern lexer (STIX Specification §9.4 whitespace, §9.2 constants).

use crate::core::StixTimestamp;
use crate::pattern::error::PatternError;

/// Maximum pattern string length (DoS guard).
pub const MAX_PATTERN_BYTES: usize = 64 * 1024;

/// Maximum AST nesting depth during parse.
pub const MAX_AST_DEPTH: usize = 64;

/// Maximum comparisons within one observation expression.
pub const MAX_COMPARISONS_PER_OBSERVATION: usize = 256;

/// Maximum observation expressions in one pattern (Level 2/3 combinations).
pub const MAX_OBSERVATIONS: usize = 256;

/// Lexer token with source span.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SpannedToken {
    /// Token kind.
    pub token: Token,
    /// Inclusive start byte index.
    pub start: usize,
    /// Exclusive end byte index.
    pub end: usize,
}

/// Token kinds for STIX patterning (Levels 1–3).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Token {
    /// Single-quoted string literal.
    StringLit(String),
    /// Integer literal.
    IntLit(i64),
    /// Floating-point literal.
    FloatLit(f64),
    /// Boolean literal.
    BoolLit(bool),
    /// Timestamp literal (`t'…'`).
    TimestampLit(StixTimestamp),
    /// Hex byte literal (`h'…'`).
    HexLit(Vec<u8>),
    /// Base64 byte literal (`b'…'`).
    BinaryLit(Vec<u8>),
    /// `=`
    Eq,
    /// `!=`
    NotEq,
    /// `>`
    Gt,
    /// `<`
    Lt,
    /// `>=`
    Gte,
    /// `<=`
    Lte,
    /// `IN`
    In,
    /// `LIKE`
    Like,
    /// `MATCHES`
    Matches,
    /// `ISSUBSET`
    IsSubset,
    /// `ISSUPERSET`
    IsSuperset,
    /// `EXISTS`
    Exists,
    /// `NOT`
    Not,
    /// `AND`
    And,
    /// `OR`
    Or,
    /// `FOLLOWEDBY`
    FollowedBy,
    /// `WITHIN`
    Within,
    /// `REPEATS`
    Repeats,
    /// `START`
    Start,
    /// `STOP`
    Stop,
    /// `TIMES` (REPEATS suffix)
    Times,
    /// `SECONDS`
    Seconds,
    /// `MINUTES`
    Minutes,
    /// `HOURS`
    Hours,
    /// `DAYS`
    Days,
    /// `MONTHS`
    Months,
    /// `YEARS`
    Years,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `:`
    Colon,
    /// `.`
    Dot,
    /// `,`
    Comma,
    /// `*`
    Star,
    /// Identifier or hyphenated object type / property name.
    Identifier(String),
    /// End of input.
    Eof,
}

struct Lexer<'a> {
    source: &'a str,
    chars: std::str::CharIndices<'a>,
    peek: Option<(usize, char)>,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str) -> Self {
        let mut chars = source.char_indices();
        let peek = chars.next();
        Self {
            source,
            chars,
            peek,
        }
    }

    fn bump(&mut self) -> Option<(usize, char)> {
        let current = self.peek;
        self.peek = self.chars.next();
        current
    }

    fn peek_char(&self) -> Option<char> {
        self.peek.map(|(_, c)| c)
    }

    fn peek_offset(&self) -> usize {
        self.peek.map(|(i, _)| i).unwrap_or(self.source.len())
    }

    fn tokenize(mut self) -> Result<Vec<SpannedToken>, PatternError> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace();
            let start = self.peek_offset();
            if self.peek.is_none() {
                tokens.push(SpannedToken {
                    token: Token::Eof,
                    start,
                    end: start,
                });
                break;
            }
            let token = self.next_token(start)?;
            let end = self.peek_offset();
            tokens.push(SpannedToken { token, start, end });
        }
        Ok(tokens)
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek_char() {
            if is_pattern_whitespace(c) {
                self.bump();
            } else {
                break;
            }
        }
    }

    fn next_token(&mut self, start: usize) -> Result<Token, PatternError> {
        let (_, c) = self.bump().expect("peek guarded");
        match c {
            '[' => Ok(Token::LBracket),
            ']' => Ok(Token::RBracket),
            '(' => Ok(Token::LParen),
            ')' => Ok(Token::RParen),
            ':' => Ok(Token::Colon),
            '.' => Ok(Token::Dot),
            ',' => Ok(Token::Comma),
            '*' => Ok(Token::Star),
            '=' => Ok(Token::Eq),
            '>' => {
                if self.peek_char() == Some('=') {
                    self.bump();
                    Ok(Token::Gte)
                } else {
                    Ok(Token::Gt)
                }
            }
            '<' => {
                if self.peek_char() == Some('=') {
                    self.bump();
                    Ok(Token::Lte)
                } else {
                    Ok(Token::Lt)
                }
            }
            '!' => {
                if self.peek_char() == Some('=') {
                    self.bump();
                    Ok(Token::NotEq)
                } else {
                    Err(lex_error(start, "expected '!=' after '!'"))
                }
            }
            '\'' => self.read_quoted(start),
            'h' if self.peek_char() == Some('\'') => {
                self.bump();
                self.read_prefixed_bytes(start, 'h')
            }
            'b' if self.peek_char() == Some('\'') => {
                self.bump();
                self.read_prefixed_bytes(start, 'b')
            }
            't' if self.peek_char() == Some('\'') => {
                self.bump();
                self.read_timestamp(start)
            }
            '-' | '0'..='9' => self.read_number(start, c),
            _ if is_ident_start(c) => self.read_identifier_or_keyword(start, c),
            _ => Err(lex_error(start, format!("unexpected character {c:?}"))),
        }
    }

    fn read_quoted(&mut self, start: usize) -> Result<Token, PatternError> {
        let mut value = String::new();
        loop {
            match self.bump() {
                None => return Err(lex_error(start, "unterminated string literal")),
                Some((_, '\'')) => break,
                Some((_, '\\')) => match self.bump() {
                    None => return Err(lex_error(start, "unterminated escape in string")),
                    Some((_, ch)) if ch == '\'' || ch == '\\' => value.push(ch),
                    Some((pos, ch)) => {
                        return Err(lex_error(pos, format!("invalid escape \\{ch}")));
                    }
                },
                Some((_, ch)) => value.push(ch),
            }
        }
        Ok(Token::StringLit(value))
    }

    fn read_prefixed_bytes(&mut self, start: usize, prefix: char) -> Result<Token, PatternError> {
        let mut raw = String::new();
        loop {
            match self.bump() {
                None => return Err(lex_error(start, "unterminated literal")),
                Some((_, '\'')) => break,
                Some((_, ch)) => raw.push(ch),
            }
        }
        match prefix {
            'h' => decode_hex(&raw)
                .map(Token::HexLit)
                .map_err(|msg| lex_error(start, msg)),
            'b' => decode_base64(&raw)
                .map(Token::BinaryLit)
                .map_err(|msg| lex_error(start, msg)),
            _ => unreachable!(),
        }
    }

    fn read_timestamp(&mut self, start: usize) -> Result<Token, PatternError> {
        let mut raw = String::new();
        loop {
            match self.bump() {
                None => return Err(lex_error(start, "unterminated timestamp literal")),
                Some((_, '\'')) => break,
                Some((_, ch)) => raw.push(ch),
            }
        }
        StixTimestamp::parse(&raw)
            .map(Token::TimestampLit)
            .map_err(|e| lex_error(start, format!("invalid timestamp: {e}")))
    }

    fn read_number(&mut self, start: usize, first: char) -> Result<Token, PatternError> {
        let mut text = String::new();
        text.push(first);
        let mut saw_dot = first == '.';
        while let Some(c) = self.peek_char() {
            if c.is_ascii_digit() {
                text.push(c);
                self.bump();
            } else if c == '.' && !saw_dot {
                saw_dot = true;
                text.push(c);
                self.bump();
            } else {
                break;
            }
        }
        if saw_dot {
            text.parse::<f64>()
                .map(Token::FloatLit)
                .map_err(|_| lex_error(start, format!("invalid float {text}")))
        } else {
            text.parse::<i64>()
                .map(Token::IntLit)
                .map_err(|_| lex_error(start, format!("invalid integer {text}")))
        }
    }

    fn read_identifier_or_keyword(
        &mut self,
        _start: usize,
        first: char,
    ) -> Result<Token, PatternError> {
        let mut text = String::new();
        text.push(first);
        while let Some(c) = self.peek_char() {
            if is_ident_continue(c) {
                text.push(c);
                self.bump();
            } else {
                break;
            }
        }
        Ok(match text.as_str() {
            "true" => Token::BoolLit(true),
            "false" => Token::BoolLit(false),
            "AND" => Token::And,
            "OR" => Token::Or,
            "NOT" => Token::Not,
            "FOLLOWEDBY" => Token::FollowedBy,
            "WITHIN" => Token::Within,
            "REPEATS" => Token::Repeats,
            "START" => Token::Start,
            "STOP" => Token::Stop,
            "TIMES" => Token::Times,
            "SECONDS" => Token::Seconds,
            "MINUTES" => Token::Minutes,
            "HOURS" => Token::Hours,
            "DAYS" => Token::Days,
            "MONTHS" => Token::Months,
            "YEARS" => Token::Years,
            "IN" => Token::In,
            "LIKE" => Token::Like,
            "MATCHES" => Token::Matches,
            "ISSUBSET" => Token::IsSubset,
            "ISSUPERSET" => Token::IsSuperset,
            "EXISTS" => Token::Exists,
            _ => Token::Identifier(text),
        })
    }
}

/// Tokenize a STIX pattern string (crate-private).
pub(crate) fn lex(source: &str) -> Result<Vec<SpannedToken>, PatternError> {
    if source.len() > MAX_PATTERN_BYTES {
        return Err(PatternError::InputTooLarge {
            max: MAX_PATTERN_BYTES,
        });
    }
    Lexer::new(source).tokenize()
}

fn lex_error(pos: usize, msg: impl Into<String>) -> PatternError {
    PatternError::LexError {
        pos,
        msg: msg.into(),
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// STIX pattern whitespace (Unicode WSpace=Y subset per §9.4).
fn is_pattern_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0020}'
            | '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0085}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{3000}'
            | '\u{FEFF}'
    ) || ('\u{2000}'..='\u{200A}').contains(&c)
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, String> {
    // Walk bytes, not char indices: multi-byte UTF-8 in a hex literal must
    // return an error, never panic on a mid-character slice (fuzz finding).
    let bytes = raw.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("hex literal must have an even number of digits".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let hi = hex_nibble(chunk[0]).ok_or_else(|| format!("invalid hex digit in {raw:?}"))?;
        let lo = hex_nibble(chunk[1]).ok_or_else(|| format!("invalid hex digit in {raw:?}"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_base64(raw: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .map_err(|e| format!("invalid base64: {e}"))
}

#[cfg(test)]
mod security {
    use super::*;

    fn token_kinds(source: &str) -> Vec<Token> {
        lex(source).unwrap().into_iter().map(|t| t.token).collect()
    }

    #[test]
    fn lex_simple_observation() {
        let kinds = token_kinds("[ipv4-addr:value = '203.0.113.4']");
        assert_eq!(
            kinds,
            vec![
                Token::LBracket,
                Token::Identifier("ipv4-addr".into()),
                Token::Colon,
                Token::Identifier("value".into()),
                Token::Eq,
                Token::StringLit("203.0.113.4".into()),
                Token::RBracket,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn lex_quoted_property_and_keywords() {
        let kinds = token_kinds("[file:hashes.'SHA-256' = h'ffc3']");
        assert_eq!(
            kinds,
            vec![
                Token::LBracket,
                Token::Identifier("file".into()),
                Token::Colon,
                Token::Identifier("hashes".into()),
                Token::Dot,
                Token::StringLit("SHA-256".into()),
                Token::Eq,
                Token::HexLit(vec![0xff, 0xc3]),
                Token::RBracket,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn lex_rejects_unterminated_string() {
        let err = lex("[x = 'oops]").unwrap_err();
        assert!(matches!(err, PatternError::LexError { .. }));
    }

    #[test]
    fn lex_rejects_non_ascii_hex_without_panic() {
        // Regression: slicing hex by byte indices panicked on multi-byte UTF-8
        // (libFuzzer crash-bbdb035e4d7fb4447623bb8927a85ef9804d60c5).
        let err = lex("h'ɞ'").unwrap_err();
        assert!(matches!(err, PatternError::LexError { .. }));
        assert!(decode_hex("ɞ").is_err());
        assert!(decode_hex("^ɞ").is_err());
        let crash =
            "[lfi h'^ɞȚ^[gfile:hashes.'SHA-256' = 'bf0b31fcf8a3feeaf7092761e18c859ee52a9c']";
        assert!(crate::Pattern::parse(crash).is_err());
    }

    #[test]
    fn lex_enforces_max_size() {
        let huge = "a".repeat(MAX_PATTERN_BYTES + 1);
        assert!(matches!(
            lex(&huge).unwrap_err(),
            PatternError::InputTooLarge { .. }
        ));
    }
}
