//! Semantic checks on parsed detections.
//!
//! The parser runs these checks on every detection it builds, so `rule parse`,
//! lint, the LSP, evaluation, and conversion reject the same invalid rules, as
//! pySigma does when it loads a rule. IR lowering repeats the item checks for
//! detections that are built or rewritten after parsing.

use std::fmt;
use std::net::IpAddr;

use crate::ast::{ConditionExpr, Detection, DetectionItem, Modifier, Quantifier, SelectorPattern};
use crate::emit::modifier_str;
use crate::error::{Result, SigmaParserError};
use crate::value::SigmaValue;

use Modifier::*;

const STRING_OPERATORS: [Modifier; 3] = [Contains, StartsWith, EndsWith];
const NUMERIC_COMPARISONS: [Modifier; 4] = [Gt, Gte, Lt, Lte];
const TIMESTAMP_PARTS: [Modifier; 6] = [Minute, Hour, Day, Week, Month, Year];
const UTF16_ENCODINGS: [Modifier; 3] = [Wide, Utf16, Utf16be];
const VALUE_TRANSFORMS: [Modifier; 7] =
    [Base64, Base64Offset, Wide, Utf16, Utf16be, WindAsh, Expand];
const REGEX_FLAGS: [Modifier; 3] = [IgnoreCase, Multiline, DotAll];
const STRING_ONLY: [Modifier; 14] = [
    Contains,
    StartsWith,
    EndsWith,
    Base64,
    Base64Offset,
    Wide,
    Utf16,
    Utf16be,
    WindAsh,
    Re,
    Cidr,
    Expand,
    FieldRef,
    Cased,
];

/// Check that a modifier chain sets at most one operator and combines only
/// modifiers that compose.
///
/// Returns a description of the first conflict found.
///
/// # Examples
///
/// ```
/// use rsigma_parser::Modifier;
/// use rsigma_parser::validate::check_modifiers;
///
/// assert!(check_modifiers(&[Modifier::Contains, Modifier::All]).is_ok());
/// assert!(check_modifiers(&[Modifier::Contains, Modifier::Re]).is_err());
/// assert!(check_modifiers(&[Modifier::IgnoreCase]).is_err());
/// ```
pub fn check_modifiers(modifiers: &[Modifier]) -> std::result::Result<(), String> {
    let has = |m: Modifier| modifiers.contains(&m);
    let present = |set: &[Modifier]| -> Vec<&'static str> {
        set.iter()
            .copied()
            .filter(|m| has(*m))
            .map(modifier_str)
            .collect()
    };
    let numeric = NUMERIC_COMPARISONS.iter().any(|m| has(*m));
    let timestamp = TIMESTAMP_PARTS.iter().any(|m| has(*m));
    // `fieldref` may combine with exactly one of contains/startswith/endswith.
    let fieldref_conflicts = has(Re)
        || has(Cidr)
        || has(Exists)
        || numeric
        || timestamp
        || present(&STRING_OPERATORS).len() > 1;

    let mut operators = present(&[Contains, StartsWith, EndsWith, Re, Cidr, Exists]);
    if has(FieldRef) && fieldref_conflicts {
        operators.push("fieldref");
    }
    operators.extend(present(&NUMERIC_COMPARISONS));
    operators.extend(
        modifiers
            .iter()
            .filter(|m| TIMESTAMP_PARTS.contains(m))
            .map(|m| modifier_str(*m)),
    );
    if has(Cased) && (has(Re) || has(Cidr) || has(Exists) || numeric || timestamp) {
        operators.push("cased");
    }
    if has(FieldRef)
        && !fieldref_conflicts
        && let Some(name) = string_operator_before_fieldref(modifiers)
    {
        return Err(format!("|{name} must follow |fieldref"));
    }
    if operators.len() > 1 {
        return Err(format!(
            "at most one operator may be set per field; got |{}",
            operators.join(", |")
        ));
    }

    let encodings = present(&UTF16_ENCODINGS);
    if encodings.len() > 1 {
        return Err(format!(
            "|wide, |utf16, and |utf16be are mutually exclusive UTF-16 encodings; got |{}",
            encodings.join(", |")
        ));
    }
    if has(Base64) && has(Base64Offset) {
        return Err(
            "|base64 and |base64offset are mutually exclusive base64 strategies; pick one".into(),
        );
    }

    let non_string_operator =
        has(Re) || has(Cidr) || has(Exists) || has(FieldRef) || numeric || timestamp;
    let transforms = present(&VALUE_TRANSFORMS);
    if non_string_operator && !transforms.is_empty() {
        return Err(format!(
            "value transformations |{} only apply to string match operators (default eq, \
             contains, startswith, endswith) and cannot be combined with the operator that \
             is also set on this field",
            transforms.join(", |")
        ));
    }

    let flags = present(&REGEX_FLAGS);
    if !has(Re) && !flags.is_empty() {
        return Err(format!(
            "regex flag modifiers |{} have no effect without |re; case sensitivity for \
             substring or equality matching is controlled by |cased (or its absence, which \
             keeps the default case-insensitive behavior)",
            flags.join(", |")
        ));
    }
    if let Some(re_at) = modifiers.iter().position(|m| *m == Re)
        && modifiers[..re_at].iter().any(|m| REGEX_FLAGS.contains(m))
    {
        return Err("regex flag modifiers |i, |m, and |s must follow |re".into());
    }

    Ok(())
}

/// A string operator before `|fieldref` would wildcard the referenced field
/// name in pySigma, which rejects it.
fn string_operator_before_fieldref(modifiers: &[Modifier]) -> Option<&'static str> {
    let fieldref_at = modifiers.iter().position(|m| *m == FieldRef)?;
    modifiers[..fieldref_at]
        .iter()
        .find(|m| STRING_OPERATORS.contains(m))
        .map(|m| modifier_str(*m))
}

/// Check that a `|cidr` value is `address/prefix` with no host bits set, as
/// pySigma requires.
///
/// # Examples
///
/// ```
/// use rsigma_parser::validate::check_cidr;
///
/// assert!(check_cidr("10.0.0.0/8").is_ok());
/// assert!(check_cidr("10.0.0.1/8").is_err());
/// assert!(check_cidr("fe80::/10").is_ok());
/// ```
pub fn check_cidr(cidr: &str) -> std::result::Result<(), String> {
    let invalid = |reason: &str| format!("invalid CIDR expression '{cidr}': {reason}");
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| invalid("expected address/prefix"))?;
    let addr: IpAddr = addr.parse().map_err(|_| invalid("invalid IP address"))?;
    let (bits, width) = match addr {
        IpAddr::V4(a) => (u128::from(u32::from(a)), 32),
        IpAddr::V6(a) => (u128::from(a), 128),
    };
    let prefix: u32 = prefix
        .parse()
        .ok()
        .filter(|p| *p <= width)
        .ok_or_else(|| invalid("invalid prefix length"))?;
    let host_mask = u128::MAX.checked_shr(128 - width + prefix).unwrap_or(0);
    if bits & host_mask != 0 {
        return Err(invalid("host bits set"));
    }
    Ok(())
}

/// Check that a `|re` value is a valid regular expression.
///
/// Lookaround and backreferences are accepted, as in pySigma and the PCRE
/// dialect that Sigma regular expressions follow, although the evaluator
/// rejects them when it compiles the rule.
///
/// # Examples
///
/// ```
/// use rsigma_parser::validate::check_regex;
///
/// assert!(check_regex(r"^cmd\.exe$").is_ok());
/// assert!(check_regex(r"(?<!\\)cmd").is_ok());
/// assert!(check_regex("a(b").is_err());
/// ```
pub fn check_regex(pattern: &str) -> std::result::Result<(), String> {
    if regex_syntax::Parser::new().parse(pattern).is_ok() {
        return Ok(());
    }
    fancy_regex::Regex::new(pattern)
        .map(drop)
        .map_err(|e| e.to_string())
}

/// The boolean an `|exists` value stands for.
pub fn exists_flag(value: &SigmaValue) -> Option<bool> {
    match value {
        SigmaValue::Bool(b) => Some(*b),
        SigmaValue::String(_)
        | SigmaValue::Integer(_)
        | SigmaValue::Float(_)
        | SigmaValue::Null => None,
    }
}

/// Check one detection item: its modifier chain, and every value against the
/// type its modifiers require.
pub fn check_detection_item(item: &DetectionItem) -> Result<()> {
    let modifiers = &item.field.modifiers;
    let has = |m: Modifier| modifiers.contains(&m);
    let subject = match &item.field.name {
        Some(name) => format!("field '{name}'"),
        None => "keyword".to_string(),
    };
    let invalid = |msg: String| SigmaParserError::InvalidValue(format!("{subject}: {msg}"));

    check_modifiers(modifiers)
        .map_err(|e| SigmaParserError::InvalidModifiers(format!("{subject}: {e}")))?;

    if has(Exists) {
        if item.field.name.is_none() {
            return Err(invalid("|exists must be applied to a field".into()));
        }
        return match item.values.as_slice() {
            [SigmaValue::Bool(_)] => Ok(()),
            _ => Err(invalid(
                "|exists takes a single boolean value, true or false".into(),
            )),
        };
    }
    if has(All) && item.values.is_empty() {
        return Err(SigmaParserError::InvalidModifiers(format!(
            "{subject}: |all requires at least one value"
        )));
    }
    if item.values.is_empty() && item.field.name.is_none() {
        return Err(invalid(
            "an empty value list must be bound to a field".into(),
        ));
    }

    let numeric = NUMERIC_COMPARISONS
        .iter()
        .chain(&TIMESTAMP_PARTS)
        .copied()
        .find(|m| has(*m));
    let string_only = STRING_ONLY.iter().copied().find(|m| has(*m));
    let base64 = has(Base64) || has(Base64Offset);
    let utf16 = UTF16_ENCODINGS.iter().any(|m| has(*m));

    for value in &item.values {
        if let Some(m) = numeric {
            if !is_numeric(value) {
                return Err(invalid(format!(
                    "|{} requires a numeric value, got {}",
                    modifier_str(m),
                    describe(value)
                )));
            }
            continue;
        }
        let Some(m) = string_only else { continue };
        let SigmaValue::String(s) = value else {
            return Err(invalid(format!(
                "|{} requires a string value, got {}",
                modifier_str(m),
                describe(value)
            )));
        };
        if has(Re) {
            check_regex(&s.original)
                .map_err(|e| invalid(format!("invalid regular expression: {e}")))?;
        }
        if has(Cidr) {
            check_cidr(&s.as_plain().unwrap_or_else(|| s.original.clone())).map_err(invalid)?;
        }
        if has(FieldRef) && s.contains_wildcards() {
            return Err(invalid(
                "a field reference must not contain wildcards".into(),
            ));
        }
        if base64 && s.contains_wildcards() {
            return Err(invalid(
                "|base64 and |base64offset do not support wildcards; escape * and ? as \\* and \\? to match them literally".into(),
            ));
        }
        if utf16 && !base64 && !s.original.is_ascii() {
            return Err(invalid(
                "|wide, |utf16, and |utf16be without |base64 or |base64offset require an ASCII value".into(),
            ));
        }
    }
    Ok(())
}

fn is_numeric(value: &SigmaValue) -> bool {
    matches!(value, SigmaValue::Integer(_) | SigmaValue::Float(_))
}

fn describe(value: &SigmaValue) -> String {
    match value {
        SigmaValue::String(s) => format!("'{s}'"),
        other => other.to_string(),
    }
}

/// Check a named detection for empty selections, `null` keywords, and
/// field-less items that can never match the event, and the conditions of any
/// extended array blocks inside it.
pub(crate) fn check_detection(name: &str, detection: &Detection) -> Result<()> {
    check_detection_in(name, detection, false)
}

/// Check a detection whose field-less items match the event when
/// `array_member` is false, and an array member inside an array body.
fn check_detection_in(name: &str, detection: &Detection, array_member: bool) -> Result<()> {
    let invalid = |msg: &str| SigmaParserError::InvalidDetection(format!("'{name}' {msg}"));
    match detection {
        Detection::AllOf(items) if items.is_empty() => Err(invalid("is empty")),
        Detection::AllOf(_) if array_member => Ok(()),
        Detection::AllOf(items) => items
            .iter()
            .filter(|item| item.field.name.is_none())
            .try_for_each(check_event_keyword),
        Detection::AnyOf(subs) | Detection::And(subs) => {
            if subs.is_empty() {
                return Err(invalid("is empty"));
            }
            subs.iter()
                .try_for_each(|d| check_detection_in(name, d, array_member))
        }
        Detection::Keywords(values) => {
            if values.is_empty() {
                return Err(invalid("is empty"));
            }
            if values.iter().any(|v| matches!(v, SigmaValue::Null)) {
                return Err(invalid(
                    "uses null as a keyword; keywords match text anywhere in the event",
                ));
            }
            Ok(())
        }
        Detection::ArrayMatch { body, .. } => check_detection_in(name, body, true),
        Detection::Conditional { named, condition } => {
            for (sub_name, sub) in named {
                check_detection_in(sub_name, sub, array_member)?;
            }
            let names: Vec<&str> = named.keys().map(String::as_str).collect();
            check_condition(condition, &names)
        }
    }
}

/// Check a field-less item that matches the whole event. A keyword is matched
/// against the text of the event's values, so a modifier that compares a
/// typed value, or a null check, never matches it.
fn check_event_keyword(item: &DetectionItem) -> Result<()> {
    let has = |m: Modifier| item.field.modifiers.contains(&m);
    let invalid = |msg: String| SigmaParserError::InvalidValue(format!("keyword: {msg}"));
    if let Some(m) = [Cidr, FieldRef]
        .into_iter()
        .chain(NUMERIC_COMPARISONS)
        .chain(TIMESTAMP_PARTS)
        .find(|m| has(*m))
    {
        return Err(invalid(format!(
            "|{} must be applied to a field",
            modifier_str(m)
        )));
    }
    if item.values.iter().any(|v| matches!(v, SigmaValue::Null)) {
        return Err(invalid(
            "null is not a keyword; a null check must be bound to a field".into(),
        ));
    }
    Ok(())
}

/// Check that every identifier in a condition names a detection and every
/// selector matches at least one.
pub(crate) fn check_condition(expr: &ConditionExpr, names: &[&str]) -> Result<()> {
    match unresolved_references(expr, names).first() {
        None => Ok(()),
        Some(unresolved) => Err(SigmaParserError::InvalidDetection(unresolved.to_string())),
    }
}

/// A condition reference that resolves to no detection.
pub(crate) enum Unresolved<'a> {
    /// An identifier that names no detection.
    Identifier(&'a str),
    /// A selector whose pattern matches no detection.
    Selector {
        quantifier: &'a Quantifier,
        pattern: &'a SelectorPattern,
    },
}

impl fmt::Display for Unresolved<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unresolved::Identifier(id) => {
                write!(
                    f,
                    "condition references unknown detection identifier '{id}'"
                )
            }
            Unresolved::Selector {
                quantifier,
                pattern,
            } => write!(
                f,
                "selector '{quantifier} of {pattern}' matches no detection identifier"
            ),
        }
    }
}

/// Every unresolved reference in a condition, in the order it appears.
pub(crate) fn unresolved_references<'a>(
    expr: &'a ConditionExpr,
    names: &[&str],
) -> Vec<Unresolved<'a>> {
    let mut out = Vec::new();
    collect_unresolved(expr, names, &mut out);
    out
}

fn collect_unresolved<'a>(expr: &'a ConditionExpr, names: &[&str], out: &mut Vec<Unresolved<'a>>) {
    match expr {
        ConditionExpr::And(exprs) | ConditionExpr::Or(exprs) => {
            exprs.iter().for_each(|e| collect_unresolved(e, names, out))
        }
        ConditionExpr::Not(inner) => collect_unresolved(inner, names, out),
        ConditionExpr::Identifier(id) => {
            if !names.contains(&id.as_str()) {
                out.push(Unresolved::Identifier(id));
            }
        }
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            if !names.iter().any(|n| pattern.matches_detection_name(n)) {
                out.push(Unresolved::Selector {
                    quantifier,
                    pattern,
                });
            }
        }
    }
}
