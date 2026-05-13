use regex::RegexSet;

use super::helpers::{
    ascii_lowercase_cow, expand_template, extract_timestamp_part, match_cidr, match_numeric_value,
    match_str_value,
};
use super::{CompiledMatcher, GroupMode};
use crate::event::{Event, EventValue};

/// Reduce a [`RegexSet`] match against `s` according to `mode`.
///
/// `Any` short-circuits via [`RegexSet::is_match`]; `All` requires every
/// pattern in the set to fire, so we materialize the matched-pattern bitset
/// and check its population against the set length.
#[inline]
fn regex_set_matches(set: &RegexSet, mode: GroupMode, s: &str) -> bool {
    match mode {
        GroupMode::Any => set.is_match(s),
        GroupMode::All => {
            let hits = set.matches(s);
            hits.iter().count() == set.len()
        }
    }
}

impl CompiledMatcher {
    /// Check if this matcher matches an [`EventValue`] from an event.
    ///
    /// The `event` parameter is needed for `FieldRef` to access other fields.
    #[inline]
    pub fn matches(&self, value: &EventValue, event: &impl Event) -> bool {
        match self {
            // -- String matchers --
            CompiledMatcher::Exact {
                value: expected,
                case_insensitive,
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    s.to_lowercase() == *expected
                } else {
                    s == expected
                }
            }),

            CompiledMatcher::Contains {
                value: needle,
                case_insensitive,
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    s.to_lowercase().contains(needle.as_str())
                } else {
                    s.contains(needle.as_str())
                }
            }),

            CompiledMatcher::StartsWith {
                value: prefix,
                case_insensitive,
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    s.to_lowercase().starts_with(prefix.as_str())
                } else {
                    s.starts_with(prefix.as_str())
                }
            }),

            CompiledMatcher::EndsWith {
                value: suffix,
                case_insensitive,
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    s.to_lowercase().ends_with(suffix.as_str())
                } else {
                    s.ends_with(suffix.as_str())
                }
            }),

            CompiledMatcher::Regex(re) => match_str_value(value, |s| re.is_match(s)),

            CompiledMatcher::AhoCorasickSet {
                automaton,
                case_insensitive,
                ..
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    automaton.is_match(ascii_lowercase_cow(s).as_ref())
                } else {
                    automaton.is_match(s)
                }
            }),

            CompiledMatcher::RegexSetMatch { set, mode } => {
                match_str_value(value, |s| regex_set_matches(set, *mode, s))
            }

            // -- Network --
            CompiledMatcher::Cidr(net) => match_cidr(value, net),

            // -- Numeric --
            CompiledMatcher::NumericEq(n) => {
                match_numeric_value(value, |v| (v - n).abs() < f64::EPSILON)
            }
            CompiledMatcher::NumericGt(n) => match_numeric_value(value, |v| v > *n),
            CompiledMatcher::NumericGte(n) => match_numeric_value(value, |v| v >= *n),
            CompiledMatcher::NumericLt(n) => match_numeric_value(value, |v| v < *n),
            CompiledMatcher::NumericLte(n) => match_numeric_value(value, |v| v <= *n),

            // -- Special --
            CompiledMatcher::Exists(expect) => {
                let exists = !value.is_null();
                exists == *expect
            }

            CompiledMatcher::FieldRef {
                field: ref_field,
                case_insensitive,
            } => {
                if let Some(ref_value) = event.get_field(ref_field) {
                    if *case_insensitive {
                        match (value.as_str(), ref_value.as_str()) {
                            (Some(a), Some(b)) => a.to_lowercase() == b.to_lowercase(),
                            _ => value == &ref_value,
                        }
                    } else {
                        value == &ref_value
                    }
                } else {
                    false
                }
            }

            CompiledMatcher::Null => value.is_null(),

            CompiledMatcher::BoolEq(expected) => match value {
                EventValue::Bool(b) => b == expected,
                EventValue::Str(s) => match s.to_lowercase().as_str() {
                    "true" | "1" | "yes" => *expected,
                    "false" | "0" | "no" => !*expected,
                    _ => false,
                },
                _ => false,
            },

            // -- Expand --
            CompiledMatcher::Expand {
                template,
                case_insensitive,
            } => {
                let expanded = expand_template(template, event);
                match_str_value(value, |s| {
                    if *case_insensitive {
                        s.to_lowercase() == expanded.to_lowercase()
                    } else {
                        s == expanded
                    }
                })
            }

            // -- Timestamp --
            CompiledMatcher::TimestampPart { part, inner } => {
                match extract_timestamp_part(value, *part) {
                    Some(n) => {
                        let num_val = EventValue::Int(n);
                        inner.matches(&num_val, event)
                    }
                    None => false,
                }
            }

            // -- Negation --
            CompiledMatcher::Not(inner) => !inner.matches(value, event),

            // -- Composite --
            CompiledMatcher::AnyOf(matchers) => matchers.iter().any(|m| m.matches(value, event)),
            CompiledMatcher::AllOf(matchers) => matchers.iter().all(|m| m.matches(value, event)),

            CompiledMatcher::CaseInsensitiveGroup { children, mode } => {
                match_str_value(value, |s| {
                    let lowered = ascii_lowercase_cow(s);
                    match mode {
                        GroupMode::Any => children
                            .iter()
                            .any(|c| c.matches_pre_lowered(lowered.as_ref())),
                        GroupMode::All => children
                            .iter()
                            .all(|c| c.matches_pre_lowered(lowered.as_ref())),
                    }
                })
            }
        }
    }

    /// Match a haystack that has already been Unicode-lowercased.
    ///
    /// **Precondition**: `lowered_str` was produced by `ascii_lowercase_cow`
    /// (or an equivalent full-Unicode lowercaser) AND every child of the
    /// surrounding [`CompiledMatcher::CaseInsensitiveGroup`] is pre-lowerable
    /// (see `compiler::optimizer::is_pre_lowerable`).
    ///
    /// This method is internal to the crate. Optimizer bugs that violate the
    /// precondition trip a `debug_assert!`; in release the conservative
    /// fallback (`false`) avoids producing a false positive but may miss a
    /// match.
    ///
    /// No `event` parameter: pre-lowerable matchers are pure string predicates
    /// that never reference cross-event state. If a future event-aware matcher
    /// becomes pre-lowerable, the signature gains `event` then.
    pub(crate) fn matches_pre_lowered(&self, lowered_str: &str) -> bool {
        match self {
            CompiledMatcher::Contains {
                value,
                case_insensitive: true,
            } => lowered_str.contains(value.as_str()),
            CompiledMatcher::StartsWith {
                value,
                case_insensitive: true,
            } => lowered_str.starts_with(value.as_str()),
            CompiledMatcher::EndsWith {
                value,
                case_insensitive: true,
            } => lowered_str.ends_with(value.as_str()),
            CompiledMatcher::Exact {
                value,
                case_insensitive: true,
            } => lowered_str == value,
            CompiledMatcher::Regex(re) => re.is_match(lowered_str),
            CompiledMatcher::AhoCorasickSet {
                automaton,
                case_insensitive: true,
                ..
            } => automaton.is_match(lowered_str),
            CompiledMatcher::RegexSetMatch { set, mode } => {
                regex_set_matches(set, *mode, lowered_str)
            }

            CompiledMatcher::Not(inner) => !inner.matches_pre_lowered(lowered_str),
            CompiledMatcher::AnyOf(ms) => ms.iter().any(|m| m.matches_pre_lowered(lowered_str)),
            CompiledMatcher::AllOf(ms) => ms.iter().all(|m| m.matches_pre_lowered(lowered_str)),
            CompiledMatcher::CaseInsensitiveGroup { children, mode } => match mode {
                GroupMode::Any => children.iter().any(|c| c.matches_pre_lowered(lowered_str)),
                GroupMode::All => children.iter().all(|c| c.matches_pre_lowered(lowered_str)),
            },

            other => {
                debug_assert!(
                    false,
                    "matches_pre_lowered called with non-pre-lowerable matcher: {other:?}"
                );
                false
            }
        }
    }

    /// Check if this matcher matches a plain `&str` value.
    ///
    /// Handles the string-matching subset of `CompiledMatcher`. Matchers that
    /// require a full `EventValue` (numeric comparisons, field refs, etc.)
    /// return `false` — those are never used in keyword detection.
    pub(super) fn matches_str(&self, s: &str) -> bool {
        match self {
            CompiledMatcher::Exact {
                value: expected,
                case_insensitive,
            } => {
                if *case_insensitive {
                    s.to_lowercase() == *expected
                } else {
                    s == expected
                }
            }
            CompiledMatcher::Contains {
                value: needle,
                case_insensitive,
            } => {
                if *case_insensitive {
                    s.to_lowercase().contains(needle.as_str())
                } else {
                    s.contains(needle.as_str())
                }
            }
            CompiledMatcher::StartsWith {
                value: prefix,
                case_insensitive,
            } => {
                if *case_insensitive {
                    s.to_lowercase().starts_with(prefix.as_str())
                } else {
                    s.starts_with(prefix.as_str())
                }
            }
            CompiledMatcher::EndsWith {
                value: suffix,
                case_insensitive,
            } => {
                if *case_insensitive {
                    s.to_lowercase().ends_with(suffix.as_str())
                } else {
                    s.ends_with(suffix.as_str())
                }
            }
            CompiledMatcher::Regex(re) => re.is_match(s),
            CompiledMatcher::AhoCorasickSet {
                automaton,
                case_insensitive,
                ..
            } => {
                if *case_insensitive {
                    automaton.is_match(ascii_lowercase_cow(s).as_ref())
                } else {
                    automaton.is_match(s)
                }
            }
            CompiledMatcher::RegexSetMatch { set, mode } => regex_set_matches(set, *mode, s),
            CompiledMatcher::Not(inner) => !inner.matches_str(s),
            CompiledMatcher::AnyOf(matchers) => matchers.iter().any(|m| m.matches_str(s)),
            CompiledMatcher::AllOf(matchers) => matchers.iter().all(|m| m.matches_str(s)),
            CompiledMatcher::CaseInsensitiveGroup { children, mode } => {
                let lowered = ascii_lowercase_cow(s);
                match mode {
                    GroupMode::Any => children
                        .iter()
                        .any(|c| c.matches_pre_lowered(lowered.as_ref())),
                    GroupMode::All => children
                        .iter()
                        .all(|c| c.matches_pre_lowered(lowered.as_ref())),
                }
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::JsonEvent;
    use crate::matcher::helpers::parse_expand_template;
    use crate::matcher::{ExpandPart, TimePart};
    use ipnet::IpNet;
    use regex::Regex;
    use serde_json::json;

    fn empty_event() -> serde_json::Value {
        json!({})
    }

    #[test]
    fn test_exact_case_insensitive() {
        let m = CompiledMatcher::Exact {
            value: "whoami".into(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("whoami".into()), &event));
        assert!(m.matches(&EventValue::Str("WHOAMI".into()), &event));
        assert!(m.matches(&EventValue::Str("Whoami".into()), &event));
        assert!(!m.matches(&EventValue::Str("other".into()), &event));
    }

    #[test]
    fn test_exact_case_sensitive() {
        let m = CompiledMatcher::Exact {
            value: "whoami".into(),
            case_insensitive: false,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("whoami".into()), &event));
        assert!(!m.matches(&EventValue::Str("WHOAMI".into()), &event));
    }

    #[test]
    fn test_contains() {
        let m = CompiledMatcher::Contains {
            value: "admin".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("superadminuser".into()), &event));
        assert!(m.matches(&EventValue::Str("ADMIN".into()), &event));
        assert!(!m.matches(&EventValue::Str("user".into()), &event));
    }

    #[test]
    fn test_starts_with() {
        let m = CompiledMatcher::StartsWith {
            value: "cmd".into(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("cmd.exe".into()), &event));
        assert!(m.matches(&EventValue::Str("CMD.EXE".into()), &event));
        assert!(!m.matches(&EventValue::Str("xcmd".into()), &event));
    }

    #[test]
    fn test_ends_with() {
        let m = CompiledMatcher::EndsWith {
            value: ".exe".into(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("cmd.exe".into()), &event));
        assert!(m.matches(&EventValue::Str("CMD.EXE".into()), &event));
        assert!(!m.matches(&EventValue::Str("cmd.bat".into()), &event));
    }

    #[test]
    fn test_regex() {
        let re = Regex::new("(?i)^test.*value$").unwrap();
        let m = CompiledMatcher::Regex(re);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("testXYZvalue".into()), &event));
        assert!(m.matches(&EventValue::Str("TESTvalue".into()), &event));
        assert!(!m.matches(&EventValue::Str("notamatch".into()), &event));
    }

    #[test]
    fn test_cidr() {
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        let m = CompiledMatcher::Cidr(net);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("10.1.2.3".into()), &event));
        assert!(!m.matches(&EventValue::Str("192.168.1.1".into()), &event));
    }

    #[test]
    fn test_numeric() {
        let m = CompiledMatcher::NumericGte(100.0);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Int(100), &event));
        assert!(m.matches(&EventValue::Int(200), &event));
        assert!(!m.matches(&EventValue::Int(50), &event));
        assert!(m.matches(&EventValue::Str("150".into()), &event));
    }

    #[test]
    fn test_null() {
        let m = CompiledMatcher::Null;
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Null, &event));
        assert!(!m.matches(&EventValue::Str("".into()), &event));
    }

    #[test]
    fn test_bool() {
        let m = CompiledMatcher::BoolEq(true);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Bool(true), &event));
        assert!(!m.matches(&EventValue::Bool(false), &event));
        assert!(m.matches(&EventValue::Str("true".into()), &event));
    }

    #[test]
    fn test_field_ref() {
        let e = json!({"src": "10.0.0.1", "dst": "10.0.0.1"});
        let event = JsonEvent::borrow(&e);
        let m = CompiledMatcher::FieldRef {
            field: "dst".into(),
            case_insensitive: true,
        };
        assert!(m.matches(&EventValue::Str("10.0.0.1".into()), &event));
    }

    #[test]
    fn test_any_of() {
        let m = CompiledMatcher::AnyOf(vec![
            CompiledMatcher::Exact {
                value: "a".into(),
                case_insensitive: false,
            },
            CompiledMatcher::Exact {
                value: "b".into(),
                case_insensitive: false,
            },
        ]);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("a".into()), &event));
        assert!(m.matches(&EventValue::Str("b".into()), &event));
        assert!(!m.matches(&EventValue::Str("c".into()), &event));
    }

    #[test]
    fn test_all_of() {
        let m = CompiledMatcher::AllOf(vec![
            CompiledMatcher::Contains {
                value: "admin".into(),
                case_insensitive: false,
            },
            CompiledMatcher::Contains {
                value: "user".into(),
                case_insensitive: false,
            },
        ]);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("adminuser".into()), &event));
        assert!(!m.matches(&EventValue::Str("admin".into()), &event));
    }

    #[test]
    fn test_array_value_matching() {
        let m = CompiledMatcher::Exact {
            value: "target".into(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        let arr = EventValue::Array(vec![
            EventValue::Str("other".into()),
            EventValue::Str("target".into()),
            EventValue::Str("more".into()),
        ]);
        assert!(m.matches(&arr, &event));
        let arr2 = EventValue::Array(vec![
            EventValue::Str("other".into()),
            EventValue::Str("nope".into()),
        ]);
        assert!(!m.matches(&arr2, &event));
    }

    #[test]
    fn test_number_coercion_to_string() {
        let m = CompiledMatcher::Exact {
            value: "42".into(),
            case_insensitive: false,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Int(42), &event));
    }

    // =========================================================================
    // Unicode case folding tests
    // =========================================================================

    #[test]
    fn test_exact_unicode_case_insensitive() {
        let m = CompiledMatcher::Exact {
            value: "ärzte".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("ÄRZTE".into()), &event));
        assert!(m.matches(&EventValue::Str("Ärzte".into()), &event));
        assert!(m.matches(&EventValue::Str("ärzte".into()), &event));
    }

    #[test]
    fn test_contains_unicode_case_insensitive() {
        let m = CompiledMatcher::Contains {
            value: "ñ".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("España".into()), &event));
        assert!(m.matches(&EventValue::Str("ESPAÑA".into()), &event));
    }

    #[test]
    fn test_startswith_unicode_case_insensitive() {
        let m = CompiledMatcher::StartsWith {
            value: "über".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("Übersicht".into()), &event));
        assert!(m.matches(&EventValue::Str("ÜBERSICHT".into()), &event));
        assert!(!m.matches(&EventValue::Str("not-uber".into()), &event));
    }

    #[test]
    fn test_endswith_unicode_case_insensitive() {
        let m = CompiledMatcher::EndsWith {
            value: "ção".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("Aplicação".into()), &event));
        assert!(m.matches(&EventValue::Str("APLICAÇÃO".into()), &event));
        assert!(!m.matches(&EventValue::Str("Aplicacao".into()), &event));
    }

    #[test]
    fn test_greek_case_insensitive() {
        let m = CompiledMatcher::Exact {
            value: "σίγμα".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("ΣΊΓΜΑ".into()), &event));
        assert!(m.matches(&EventValue::Str("σίγμα".into()), &event));
    }

    // =========================================================================
    // Expand modifier tests
    // =========================================================================

    #[test]
    fn test_parse_expand_template() {
        let parts = parse_expand_template("C:\\Users\\%user%\\AppData");
        assert_eq!(parts.len(), 3);
        assert!(matches!(&parts[0], ExpandPart::Literal(s) if s == "C:\\Users\\"));
        assert!(matches!(&parts[1], ExpandPart::Placeholder(s) if s == "user"));
        assert!(matches!(&parts[2], ExpandPart::Literal(s) if s == "\\AppData"));
    }

    #[test]
    fn test_parse_expand_template_no_placeholders() {
        let parts = parse_expand_template("just a literal");
        assert_eq!(parts.len(), 1);
        assert!(matches!(&parts[0], ExpandPart::Literal(s) if s == "just a literal"));
    }

    #[test]
    fn test_parse_expand_template_multiple_placeholders() {
        let parts = parse_expand_template("%a%:%b%");
        assert_eq!(parts.len(), 3);
        assert!(matches!(&parts[0], ExpandPart::Placeholder(s) if s == "a"));
        assert!(matches!(&parts[1], ExpandPart::Literal(s) if s == ":"));
        assert!(matches!(&parts[2], ExpandPart::Placeholder(s) if s == "b"));
    }

    #[test]
    fn test_expand_matcher() {
        let template = parse_expand_template("C:\\Users\\%user%\\Downloads");
        let m = CompiledMatcher::Expand {
            template,
            case_insensitive: true,
        };
        let e = json!({"user": "admin", "path": "C:\\Users\\admin\\Downloads"});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(
            &EventValue::Str("C:\\Users\\admin\\Downloads".into()),
            &event
        ));
        assert!(!m.matches(
            &EventValue::Str("C:\\Users\\other\\Downloads".into()),
            &event
        ));
    }

    #[test]
    fn test_expand_matcher_missing_field() {
        let template = parse_expand_template("%user%@%domain%");
        let m = CompiledMatcher::Expand {
            template,
            case_insensitive: false,
        };
        let e = json!({"user": "admin"});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("admin@".into()), &event));
    }

    // =========================================================================
    // Timestamp part tests
    // =========================================================================

    #[test]
    fn test_timestamp_part_hour() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Hour,
            inner: Box::new(CompiledMatcher::NumericEq(12.0)),
        };
        let e = json!({});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("2024-07-10T12:30:00Z".into()), &event));
        assert!(!m.matches(&EventValue::Str("2024-07-10T15:30:00Z".into()), &event));
    }

    #[test]
    fn test_timestamp_part_month() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Month,
            inner: Box::new(CompiledMatcher::NumericEq(7.0)),
        };
        let e = json!({});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("2024-07-10T12:30:00Z".into()), &event));
        assert!(!m.matches(&EventValue::Str("2024-08-10T12:30:00Z".into()), &event));
    }

    #[test]
    fn test_timestamp_part_day() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Day,
            inner: Box::new(CompiledMatcher::NumericEq(10.0)),
        };
        let e = json!({});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("2024-07-10T12:30:00Z".into()), &event));
        assert!(!m.matches(&EventValue::Str("2024-07-15T12:30:00Z".into()), &event));
    }

    #[test]
    fn test_timestamp_part_year() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Year,
            inner: Box::new(CompiledMatcher::NumericEq(2024.0)),
        };
        let e = json!({});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("2024-07-10T12:30:00Z".into()), &event));
        assert!(!m.matches(&EventValue::Str("2023-07-10T12:30:00Z".into()), &event));
    }

    #[test]
    fn test_timestamp_part_from_epoch() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Hour,
            inner: Box::new(CompiledMatcher::NumericEq(12.0)),
        };
        let e = json!({});
        let event = JsonEvent::borrow(&e);
        // 2024-07-10T12:30:00Z = 1720614600
        assert!(m.matches(&EventValue::Int(1720614600), &event));
    }
}
