//! Elastic Lucene reverse frontend.
//!
//! Parses the Lucene / Elasticsearch `query_string` subset used by detection
//! authors into the HIR: `field:value` (with `*`/`?` wildcards), quoted
//! phrases, `field:/regex/`, `field:[a TO b]` / `{a TO b}` ranges,
//! `field:>=N` comparisons, `field:(a OR b)` value groups, `_exists_:field`,
//! bare keyword terms, and the `AND`/`OR`/`NOT` (plus `&&`/`||`/`!` and
//! `+`/`-`) boolean operators with parentheses.
//!
//! Adjacent terms with no explicit operator are ANDed
//! ([`QueryDialect::implicit_and`]), matching a `default_operator: AND` posture,
//! which is the common intent for detection queries.
//!
//! Constructs with no Sigma equivalent are rejected with a structured
//! [`ConvertError::UnsupportedConstruct`]: boosting (`^`), fuzzy and proximity
//! (`~`), and non-numeric ranges.

use rsigma_ir::{IrMatcher, IrNumber, IrPattern, IrPatternPart, NumericLiteral};

use crate::error::{ConvertError, Result};

use super::{
    Frontend, QueryDialect, QueryExpr, QueryLeaf, ReverseCtx, infer_str_matcher, parse_pattern,
};

/// The Lucene boolean dialect.
pub const LUCENE_DIALECT: QueryDialect = QueryDialect {
    name: "lucene",
    and_tokens: &["AND", "&&"],
    or_tokens: &["OR", "||"],
    not_tokens: &["NOT", "!"],
    implicit_and: true,
};

/// Reverse frontend for Elastic Lucene query strings.
#[derive(Debug, Default, Clone, Copy)]
pub struct LuceneFrontend;

impl Frontend for LuceneFrontend {
    fn name(&self) -> &str {
        LUCENE_DIALECT.name
    }

    fn dialect(&self) -> &QueryDialect {
        &LUCENE_DIALECT
    }

    fn parse_atom(&self, atom: &str, ctx: &ReverseCtx) -> Result<QueryExpr<QueryLeaf>> {
        if let Some((field, value)) = split_field(atom) {
            if field == "_exists_" {
                return Ok(leaf(field_leaf(unquote(value), IrMatcher::Exists(true))));
            }
            if is_field_name(field) {
                return parse_field(field, value.trim(), ctx);
            }
        }
        Ok(leaf(QueryLeaf::Keyword(keyword_matcher(atom)?)))
    }
}

// =============================================================================
// Field predicate parsing
// =============================================================================

fn parse_field(field: &str, value: &str, ctx: &ReverseCtx) -> Result<QueryExpr<QueryLeaf>> {
    if let Some(inner) = strip_pair(value, '(', ')') {
        return parse_value_group(field, inner, ctx);
    }
    if value.starts_with('[') || value.starts_with('{') {
        return parse_range(field, value);
    }
    if let Some(pattern) = strip_pair(value, '/', '/') {
        return Ok(leaf(field_leaf(
            field.to_string(),
            IrMatcher::Regex {
                pattern: regex_unescape(pattern),
                case_insensitive: false,
                multiline: false,
                dotall: false,
                cased: false,
            },
        )));
    }
    if let Some(matcher) = parse_comparison(value)? {
        return Ok(leaf(field_leaf(field.to_string(), matcher)));
    }
    Ok(leaf(field_leaf(field.to_string(), scalar_matcher(value)?)))
}

/// Parse a `field:(a OR b ...)` value group by reusing the shared boolean parser
/// over the bare values, all bound to `field`.
fn parse_value_group(field: &str, inner: &str, _ctx: &ReverseCtx) -> Result<QueryExpr<QueryLeaf>> {
    let tokens = super::tokenize(&LUCENE_DIALECT, inner)?;
    let tree = super::parse_boolean(&LUCENE_DIALECT, tokens, 1)?;
    tree.expand(&mut |atom: String| {
        Ok(QueryExpr::Leaf(field_leaf(
            field.to_string(),
            scalar_matcher(&atom)?,
        )))
    })
}

/// Parse a `[a TO b]` (inclusive) or `{a TO b}` (exclusive) numeric range.
fn parse_range(field: &str, value: &str) -> Result<QueryExpr<QueryLeaf>> {
    let open = value.chars().next().unwrap_or('[');
    let close = value.chars().last().unwrap_or(']');
    let inner = &value[1..value.len().saturating_sub(1)];

    let (low, high) = split_range(inner).ok_or_else(|| {
        ConvertError::QueryParse(format!("range must be '[low TO high]', got '{value}'"))
    })?;

    let inclusive_low = open == '[';
    let inclusive_high = close == ']';

    let mut bounds = Vec::new();
    if low != "*" {
        let n = range_number(low)?;
        bounds.push(if inclusive_low {
            IrMatcher::NumericGte(n)
        } else {
            IrMatcher::NumericGt(n)
        });
    }
    if high != "*" {
        let n = range_number(high)?;
        bounds.push(if inclusive_high {
            IrMatcher::NumericLte(n)
        } else {
            IrMatcher::NumericLt(n)
        });
    }

    match bounds.len() {
        0 => Ok(leaf(field_leaf(field.to_string(), IrMatcher::Exists(true)))),
        1 => Ok(leaf(field_leaf(field.to_string(), bounds.pop().unwrap()))),
        _ => Ok(QueryExpr::And(
            bounds
                .into_iter()
                .map(|m| leaf(field_leaf(field.to_string(), m)))
                .collect(),
        )),
    }
}

fn split_range(inner: &str) -> Option<(&str, &str)> {
    for sep in [" TO ", " to "] {
        if let Some(idx) = inner.find(sep) {
            let low = inner[..idx].trim();
            let high = inner[idx + sep.len()..].trim();
            return Some((low, high));
        }
    }
    None
}

fn range_number(s: &str) -> Result<IrNumber> {
    NumericLiteral::parse(s)
        .map(IrNumber::Literal)
        .ok_or_else(|| {
            ConvertError::UnsupportedConstruct(format!(
                "non-numeric range bound '{s}' has no Sigma equivalent"
            ))
        })
}

fn parse_comparison(value: &str) -> Result<Option<IrMatcher>> {
    let (ctor, rest): (fn(IrNumber) -> IrMatcher, &str) = if let Some(r) = value.strip_prefix(">=")
    {
        (IrMatcher::NumericGte, r)
    } else if let Some(r) = value.strip_prefix("<=") {
        (IrMatcher::NumericLte, r)
    } else if let Some(r) = value.strip_prefix('>') {
        (IrMatcher::NumericGt, r)
    } else if let Some(r) = value.strip_prefix('<') {
        (IrMatcher::NumericLt, r)
    } else {
        return Ok(None);
    };
    let n = NumericLiteral::parse(rest.trim()).ok_or_else(|| {
        ConvertError::UnsupportedConstruct(format!("non-numeric comparison bound '{rest}'"))
    })?;
    Ok(Some(ctor(IrNumber::Literal(n))))
}

/// Interpret a single scalar value (not a range, group, regex, or comparison).
fn scalar_matcher(value: &str) -> Result<IrMatcher> {
    if let Some(inner) = quoted_inner(value) {
        return Ok(IrMatcher::Str {
            op: rsigma_ir::IrStrOp::Exact,
            pattern: plain_pattern(&inner),
            case_insensitive: true,
        });
    }

    reject_boost_fuzzy(value)?;

    match value {
        "true" => return Ok(IrMatcher::BoolEq(true)),
        "false" => return Ok(IrMatcher::BoolEq(false)),
        _ => {}
    }

    if !has_unescaped_wildcard(value)
        && let Some(n) = NumericLiteral::parse(value)
    {
        return Ok(IrMatcher::NumericEq(IrNumber::Literal(n)));
    }

    Ok(infer_str_matcher(&lucene_value_to_sigma(value), true))
}

fn keyword_matcher(term: &str) -> Result<IrMatcher> {
    if let Some(inner) = quoted_inner(term) {
        return Ok(IrMatcher::Str {
            op: rsigma_ir::IrStrOp::Contains,
            pattern: plain_pattern(&inner),
            case_insensitive: true,
        });
    }
    reject_boost_fuzzy(term)?;
    Ok(IrMatcher::Str {
        op: rsigma_ir::IrStrOp::Contains,
        pattern: parse_pattern(&lucene_value_to_sigma(term)),
        case_insensitive: true,
    })
}

// =============================================================================
// Helpers
// =============================================================================

fn leaf(l: QueryLeaf) -> QueryExpr<QueryLeaf> {
    QueryExpr::Leaf(l)
}

fn field_leaf(field: String, matcher: IrMatcher) -> QueryLeaf {
    QueryLeaf::Field { field, matcher }
}

fn plain_pattern(s: &str) -> IrPattern {
    IrPattern {
        parts: if s.is_empty() {
            Vec::new()
        } else {
            vec![IrPatternPart::Literal(s.to_string())]
        },
    }
}

/// Split an atom at its first top-level `:` (not inside quotes or brackets).
fn split_field(atom: &str) -> Option<(&str, &str)> {
    let chars: Vec<(usize, char)> = atom.char_indices().collect();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    for (byte_idx, c) in &chars {
        match quote {
            Some(q) => {
                if *c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(*c),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ':' if depth == 0 => {
                    return Some((&atom[..*byte_idx], &atom[byte_idx + 1..]));
                }
                _ => {}
            },
        }
    }
    None
}

fn is_field_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '@' => {}
        _ => return false,
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '@'))
}

fn strip_pair(value: &str, open: char, close: char) -> Option<&str> {
    let mut chars = value.chars();
    if chars.next()? != open {
        return None;
    }
    if value.chars().count() < 2 || !value.ends_with(close) {
        return None;
    }
    let start = open.len_utf8();
    let end = value.len() - close.len_utf8();
    Some(&value[start..end])
}

fn quoted_inner(value: &str) -> Option<String> {
    for q in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(q) && value.ends_with(q) {
            let inner = &value[1..value.len() - 1];
            // A quoted phrase is a literal: unescape Lucene backslash escapes
            // (`\\` -> `\`, `\"` -> `"`, ...) so the phrase is the intended text.
            let mut out = String::with_capacity(inner.len());
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if let Some(next) = chars.next() {
                        out.push(next);
                    }
                } else {
                    out.push(c);
                }
            }
            return Some(out);
        }
    }
    None
}

fn unquote(value: &str) -> String {
    quoted_inner(value).unwrap_or_else(|| value.to_string())
}

fn has_unescaped_wildcard(value: &str) -> bool {
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '*' | '?' => return true,
            _ => {}
        }
    }
    false
}

fn reject_boost_fuzzy(value: &str) -> Result<()> {
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '^' => {
                return Err(ConvertError::UnsupportedConstruct(
                    "term boosting (^) has no Sigma equivalent".into(),
                ));
            }
            '~' => {
                return Err(ConvertError::UnsupportedConstruct(
                    "fuzzy/proximity (~) has no Sigma equivalent".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Convert a Lucene value into a Sigma value string: keep `\*`/`\?`/`\\`
/// escapes (so wildcards stay literal), and drop backslashes escaping other
/// Lucene specials (so `\:` becomes a literal `:`).
fn lucene_value_to_sigma(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let chars: Vec<char> = value.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            let next = chars[i + 1];
            match next {
                '*' | '?' | '\\' => {
                    out.push('\\');
                    out.push(next);
                }
                _ => out.push(next),
            }
            i += 2;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn regex_unescape(pattern: &str) -> String {
    pattern.replace("\\/", "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reverse::ReverseCtx;

    fn rule_yaml(query: &str) -> String {
        let frontend = LuceneFrontend;
        let ctx = ReverseCtx {
            title: Some("Test".into()),
            product: Some("windows".into()),
            ..Default::default()
        };
        let ir = frontend.parse_query(query, &ctx).expect("parses");
        let rule = rsigma_ir::raise_rule(&ir, &rsigma_ir::RaiseOptions::default()).expect("raises");
        rsigma_parser::emit_rule_yaml(&rule)
    }

    #[test]
    fn simple_field_equality() {
        let out = rule_yaml("EventID:4688");
        assert!(out.contains("EventID: 4688"), "{out}");
    }

    #[test]
    fn wildcards_become_modifiers() {
        let out = rule_yaml("Image:*\\\\cmd.exe");
        assert!(out.contains("Image|endswith:"), "{out}");
    }

    #[test]
    fn regex_maps_to_re_modifier() {
        let out = rule_yaml("CommandLine:/a.*b/");
        assert!(out.contains("CommandLine|re: 'a.*b'"), "{out}");
    }

    #[test]
    fn inclusive_range_becomes_gte_lte() {
        let out = rule_yaml("Port:[1024 TO 65535]");
        assert!(out.contains("Port|gte: 1024"), "{out}");
        assert!(out.contains("Port|lte: 65535"), "{out}");
    }

    #[test]
    fn comparison_shorthand() {
        let out = rule_yaml("Port:>=1024");
        assert!(out.contains("Port|gte: 1024"), "{out}");
    }

    #[test]
    fn value_group_becomes_value_list() {
        let out = rule_yaml("Image:(\"a.exe\" OR \"b.exe\")");
        assert!(out.contains("Image:"), "{out}");
        assert!(out.contains("- a.exe"), "{out}");
        assert!(out.contains("- b.exe"), "{out}");
    }

    #[test]
    fn exists_maps_to_exists_modifier() {
        let out = rule_yaml("_exists_:CommandLine");
        assert!(out.contains("CommandLine|exists: true"), "{out}");
    }

    #[test]
    fn keyword_term_becomes_keywords_selection() {
        let out = rule_yaml("mimikatz");
        assert!(out.contains("keywords:"), "{out}");
        assert!(out.contains("- mimikatz"), "{out}");
    }

    #[test]
    fn boosting_is_rejected() {
        let frontend = LuceneFrontend;
        let err = frontend
            .parse_query("field:value^2", &ReverseCtx::default())
            .unwrap_err();
        assert!(matches!(err, ConvertError::UnsupportedConstruct(_)));
    }

    #[test]
    fn fuzzy_is_rejected() {
        let frontend = LuceneFrontend;
        let err = frontend
            .parse_query("roam~", &ReverseCtx::default())
            .unwrap_err();
        assert!(matches!(err, ConvertError::UnsupportedConstruct(_)));
    }
}
