use std::borrow::Cow;
use std::net::IpAddr;

use chrono::{Datelike, Timelike};
use ipnet::IpNet;

use super::{ExpandPart, TimePart};
use crate::event::{Event, EventValue};

/// Lowercase a `&str` with minimal allocation, falling back to full Unicode case
/// folding only when the input contains non-ASCII bytes.
///
/// Three-tier fast path:
/// 1. Pure ASCII with no uppercase letters: returns `Cow::Borrowed(s)` (zero allocation).
/// 2. Pure ASCII with some uppercase: allocates once and folds via `make_ascii_lowercase`.
/// 3. Contains non-ASCII: falls through to `s.to_lowercase()` (full Unicode).
///
/// **Correctness note**: the first branch must require BOTH `s.is_ascii()` AND
/// no ASCII-uppercase bytes. A naive `s.bytes().all(|b| !b.is_ascii_uppercase())`
/// alone returns `true` for non-ASCII input (whose continuation bytes are not
/// in `0x41..=0x5A`), which would silently skip Unicode case folding.
pub fn ascii_lowercase_cow(s: &str) -> Cow<'_, str> {
    if s.is_ascii() && s.bytes().all(|b| !b.is_ascii_uppercase()) {
        return Cow::Borrowed(s);
    }
    if s.is_ascii() {
        let mut buf = s.to_owned();
        buf.make_ascii_lowercase();
        return Cow::Owned(buf);
    }
    Cow::Owned(s.to_lowercase())
}

/// Try to extract a string representation from an [`EventValue`] and apply a predicate.
///
/// Handles `Str` directly and coerces numbers/bools to string for comparison.
pub(super) fn match_str_value(value: &EventValue, pred: impl Fn(&str) -> bool) -> bool {
    match_str_value_ref(value, &pred)
}

fn match_str_value_ref(value: &EventValue, pred: &dyn Fn(&str) -> bool) -> bool {
    match value {
        EventValue::Str(s) => pred(s),
        EventValue::Int(n) => pred(&n.to_string()),
        EventValue::Float(f) => pred(&f.to_string()),
        EventValue::Bool(b) => pred(if *b { "true" } else { "false" }),
        EventValue::Array(arr) => arr.iter().any(|v| match_str_value_ref(v, pred)),
        _ => false,
    }
}

/// Try to extract a numeric value and apply a predicate.
///
/// Handles numeric values directly and tries to parse strings as numbers.
pub(super) fn match_numeric_value(value: &EventValue, pred: impl Fn(f64) -> bool) -> bool {
    match_numeric_value_ref(value, &pred)
}

fn match_numeric_value_ref(value: &EventValue, pred: &dyn Fn(f64) -> bool) -> bool {
    match value {
        EventValue::Int(n) => pred(*n as f64),
        EventValue::Float(f) => pred(*f),
        EventValue::Str(s) => s.parse::<f64>().is_ok_and(pred),
        EventValue::Array(arr) => arr.iter().any(|v| match_numeric_value_ref(v, pred)),
        _ => false,
    }
}

/// Convert a [`SigmaString`](rsigma_parser::SigmaString) to a regex pattern string.
///
/// Wildcards are converted: `*` → `.*`, `?` → `.`
/// Plain text is regex-escaped.
pub fn sigma_string_to_regex(
    parts: &[rsigma_parser::value::StringPart],
    case_insensitive: bool,
) -> String {
    use rsigma_parser::value::{SpecialChar, StringPart};

    let mut pattern = String::new();
    if case_insensitive {
        pattern.push_str("(?i)");
    }
    pattern.push('^');
    for part in parts {
        match part {
            StringPart::Plain(text) => {
                pattern.push_str(&regex::escape(text));
            }
            StringPart::Special(SpecialChar::WildcardMulti) => {
                pattern.push_str(".*");
            }
            StringPart::Special(SpecialChar::WildcardSingle) => {
                pattern.push('.');
            }
        }
    }
    pattern.push('$');
    pattern
}

/// Resolve all placeholders in an expand template from the event.
pub(super) fn expand_template(template: &[ExpandPart], event: &impl Event) -> String {
    let mut result = String::new();
    for part in template {
        match part {
            ExpandPart::Literal(s) => result.push_str(s),
            ExpandPart::Placeholder(field) => {
                if let Some(val) = event.get_field(field)
                    && let Some(s) = val.as_str()
                {
                    result.push_str(&s);
                }
            }
        }
    }
    result
}

/// Parse an expand template string like `C:\Users\%user%\AppData` into parts.
pub fn parse_expand_template(s: &str) -> Vec<ExpandPart> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_placeholder = false;
    let mut placeholder = String::new();

    for ch in s.chars() {
        if ch == '%' {
            if in_placeholder {
                if !placeholder.is_empty() {
                    parts.push(ExpandPart::Placeholder(placeholder.clone()));
                    placeholder.clear();
                }
                in_placeholder = false;
            } else {
                if !current.is_empty() {
                    parts.push(ExpandPart::Literal(current.clone()));
                    current.clear();
                }
                in_placeholder = true;
            }
        } else if in_placeholder {
            placeholder.push(ch);
        } else {
            current.push(ch);
        }
    }

    if in_placeholder && !placeholder.is_empty() {
        current.push('%');
        current.push_str(&placeholder);
    }
    if !current.is_empty() {
        parts.push(ExpandPart::Literal(current));
    }

    parts
}

/// Extract a time component from an [`EventValue`] (timestamp string or number).
pub(super) fn extract_timestamp_part(value: &EventValue, part: TimePart) -> Option<i64> {
    match value {
        EventValue::Str(s) => parse_timestamp_str(s, part),
        EventValue::Int(n) => {
            let secs = if *n > 1_000_000_000_000 { n / 1000 } else { *n };
            let dt = chrono::DateTime::from_timestamp(secs, 0)?;
            Some(extract_part_from_datetime(&dt, part))
        }
        EventValue::Float(f) => {
            let secs = *f as i64;
            let secs = if secs > 1_000_000_000_000 {
                secs / 1000
            } else {
                secs
            };
            let dt = chrono::DateTime::from_timestamp(secs, 0)?;
            Some(extract_part_from_datetime(&dt, part))
        }
        _ => None,
    }
}

fn parse_timestamp_str(ts_str: &str, part: TimePart) -> Option<i64> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts_str) {
        return Some(extract_part_from_datetime(&dt.to_utc(), part));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S") {
        let dt = naive.and_utc();
        return Some(extract_part_from_datetime(&dt, part));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S") {
        let dt = naive.and_utc();
        return Some(extract_part_from_datetime(&dt, part));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S%.f") {
        let dt = naive.and_utc();
        return Some(extract_part_from_datetime(&dt, part));
    }
    None
}

/// Extract a specific time component from a UTC DateTime.
fn extract_part_from_datetime(dt: &chrono::DateTime<chrono::Utc>, part: TimePart) -> i64 {
    match part {
        TimePart::Minute => dt.minute() as i64,
        TimePart::Hour => dt.hour() as i64,
        TimePart::Day => dt.day() as i64,
        TimePart::Week => dt.iso_week().week() as i64,
        TimePart::Month => dt.month() as i64,
        TimePart::Year => dt.year() as i64,
    }
}

/// CIDR network match helper for IP addresses.
pub(super) fn match_cidr(value: &EventValue, net: &IpNet) -> bool {
    match_str_value(value, |s| {
        s.parse::<IpAddr>().is_ok_and(|ip| net.contains(&ip))
    })
}

// =============================================================================
// Property-based tests
// =============================================================================

#[cfg(test)]
mod proptests {
    use super::super::CompiledMatcher;
    use super::*;
    use crate::event::{EventValue, JsonEvent};
    use proptest::prelude::*;
    use rsigma_parser::value::{SpecialChar, StringPart};
    use serde_json::json;

    fn arb_string_parts() -> impl Strategy<Value = Vec<StringPart>> {
        prop::collection::vec(
            prop_oneof![
                "[[:print:]]{0,20}".prop_map(StringPart::Plain),
                Just(StringPart::Special(SpecialChar::WildcardMulti)),
                Just(StringPart::Special(SpecialChar::WildcardSingle)),
            ],
            0..8,
        )
    }

    proptest! {
        #[test]
        fn wildcard_regex_always_valid(parts in arb_string_parts(), ci in any::<bool>()) {
            let pattern = sigma_string_to_regex(&parts, ci);
            prop_assert!(regex::Regex::new(&pattern).is_ok(),
                "sigma_string_to_regex produced invalid regex: {}", pattern);
        }
    }

    proptest! {
        #[test]
        fn plain_text_matches_itself(text in "[[:print:]]{1,30}") {
            let parts = vec![StringPart::Plain(text.clone())];
            let pattern = sigma_string_to_regex(&parts, false);
            let re = regex::Regex::new(&pattern).unwrap();
            prop_assert!(re.is_match(&text),
                "plain text should match itself: text={:?}, pattern={}", text, pattern);
        }
    }

    proptest! {
        #[test]
        fn plain_text_rejects_different_string(
            text in "[a-zA-Z0-9]{1,10}",
            other in "[a-zA-Z0-9]{1,10}",
        ) {
            prop_assume!(text != other);
            let parts = vec![StringPart::Plain(text.clone())];
            let pattern = sigma_string_to_regex(&parts, false);
            let re = regex::Regex::new(&pattern).unwrap();
            prop_assert!(!re.is_match(&other),
                "plain {:?} should not match {:?}", text, other);
        }
    }

    proptest! {
        #[test]
        fn exact_ci_symmetric(s in "[[:alpha:]]{1,20}") {
            let m = CompiledMatcher::Exact {
                value: s.to_lowercase(),
                case_insensitive: true,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let upper = EventValue::Str(s.to_uppercase().into());
            let lower = EventValue::Str(s.to_lowercase().into());
            prop_assert!(m.matches(&upper, &event),
                "CI exact should match uppercase: {:?}", s.to_uppercase());
            prop_assert!(m.matches(&lower, &event),
                "CI exact should match lowercase: {:?}", s.to_lowercase());
        }
    }

    proptest! {
        #[test]
        fn contains_agrees_with_stdlib(
            haystack in "[[:print:]]{0,30}",
            needle in "[[:print:]]{1,10}",
        ) {
            let expected = haystack.contains(&needle);
            let m = CompiledMatcher::Contains {
                value: needle.clone(),
                case_insensitive: false,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "Contains({:?}) on {:?}", needle, haystack);
        }
    }

    proptest! {
        #[test]
        fn startswith_agrees_with_stdlib(
            haystack in "[[:print:]]{0,30}",
            prefix in "[[:print:]]{1,10}",
        ) {
            let expected = haystack.starts_with(&prefix);
            let m = CompiledMatcher::StartsWith {
                value: prefix.clone(),
                case_insensitive: false,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "StartsWith({:?}) on {:?}", prefix, haystack);
        }
    }

    proptest! {
        #[test]
        fn endswith_agrees_with_stdlib(
            haystack in "[[:print:]]{0,30}",
            suffix in "[[:print:]]{1,10}",
        ) {
            let expected = haystack.ends_with(&suffix);
            let m = CompiledMatcher::EndsWith {
                value: suffix.clone(),
                case_insensitive: false,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "EndsWith({:?}) on {:?}", suffix, haystack);
        }
    }

    proptest! {
        #[test]
        fn ci_contains_agrees_with_lowercased(
            haystack in "[[:alpha:]]{0,20}",
            needle in "[[:alpha:]]{1,8}",
        ) {
            let expected = haystack.to_lowercase().contains(&needle.to_lowercase());
            let m = CompiledMatcher::Contains {
                value: needle.to_lowercase(),
                case_insensitive: true,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "CI Contains({:?}) on {:?}", needle, haystack);
        }

        #[test]
        fn ci_startswith_agrees_with_lowercased(
            haystack in "[[:alpha:]]{0,20}",
            prefix in "[[:alpha:]]{1,8}",
        ) {
            let expected = haystack.to_lowercase().starts_with(&prefix.to_lowercase());
            let m = CompiledMatcher::StartsWith {
                value: prefix.to_lowercase(),
                case_insensitive: true,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "CI StartsWith({:?}) on {:?}", prefix, haystack);
        }

        #[test]
        fn ci_endswith_agrees_with_lowercased(
            haystack in "[[:alpha:]]{0,20}",
            suffix in "[[:alpha:]]{1,8}",
        ) {
            let expected = haystack.to_lowercase().ends_with(&suffix.to_lowercase());
            let m = CompiledMatcher::EndsWith {
                value: suffix.to_lowercase(),
                case_insensitive: true,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "CI EndsWith({:?}) on {:?}", suffix, haystack);
        }
    }

    proptest! {
        #[test]
        fn wildcard_star_matches_anything(s in "[[:print:]]{0,30}") {
            let parts = vec![StringPart::Special(SpecialChar::WildcardMulti)];
            let pattern = sigma_string_to_regex(&parts, false);
            let re = regex::Regex::new(&pattern).unwrap();
            prop_assert!(re.is_match(&s), "* should match any string: {:?}", s);
        }

        #[test]
        fn wildcard_question_matches_single_char(c in proptest::char::range('!', '~')) {
            let parts = vec![StringPart::Special(SpecialChar::WildcardSingle)];
            let pattern = sigma_string_to_regex(&parts, false);
            let re = regex::Regex::new(&pattern).unwrap();
            let s = c.to_string();
            prop_assert!(re.is_match(&s), "? should match single char: {:?}", s);
        }
    }

    // =========================================================================
    // ascii_lowercase_cow correctness
    // =========================================================================

    proptest! {
        #[test]
        fn ascii_lowercase_cow_correct(s in ".{0,40}") {
            let expected = s.to_lowercase();
            let cow = ascii_lowercase_cow(&s);
            prop_assert_eq!(
                cow.as_ref(),
                expected.as_str(),
                "ascii_lowercase_cow disagrees with std to_lowercase on {:?}",
                s
            );
        }

        #[test]
        fn ascii_lowercase_cow_borrows_when_already_lower_ascii(s in "[a-z0-9 _.,/-]{0,40}") {
            let cow = ascii_lowercase_cow(&s);
            // Pure ASCII with no uppercase must hit the zero-alloc branch.
            prop_assert!(matches!(cow, std::borrow::Cow::Borrowed(_)));
        }
    }

    #[test]
    fn ascii_lowercase_cow_handles_unicode_uppercase() {
        // Regression: a non-ASCII string with no ASCII-uppercase bytes must NOT
        // be returned as Borrowed without lowercasing the non-ASCII chars.
        let inputs = ["Ärzte", "ΣΊΓΜΑ", "Über", "España", "ÉCOLE"];
        for input in inputs {
            let cow = ascii_lowercase_cow(input);
            assert_eq!(
                cow.as_ref(),
                input.to_lowercase(),
                "ascii_lowercase_cow failed Unicode lowering for {input:?}"
            );
        }
    }

    // =========================================================================
    // AhoCorasickSet equivalence with AnyOf(Contains)
    // =========================================================================

    proptest! {
        #[test]
        fn ac_agrees_with_anyof_contains(
            needles in prop::collection::vec("[a-z0-9._/]{1,12}", 8..=20),
            haystack in "[[:print:]]{0,80}",
        ) {
            // Build both forms from the same needles. They MUST produce identical
            // results on every haystack.
            let ci_contains: Vec<CompiledMatcher> = needles.iter().map(|n| {
                CompiledMatcher::Contains {
                    value: n.to_lowercase(),
                    case_insensitive: true,
                }
            }).collect();

            let unoptimized = CompiledMatcher::AnyOf(ci_contains.clone());
            let optimized = crate::compiler::optimize_any_of_for_test(ci_contains);

            let event_json = json!({});
            let event = JsonEvent::borrow(&event_json);
            let value = EventValue::Str(haystack.clone().into());

            prop_assert_eq!(
                optimized.matches(&value, &event),
                unoptimized.matches(&value, &event),
                "AC vs AnyOf(Contains) disagree on haystack {:?}", haystack
            );
        }
    }
}
