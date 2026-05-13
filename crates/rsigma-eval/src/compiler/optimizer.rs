//! Optimization passes over compiled matcher trees.
//!
//! The optimizer rewrites composite `CompiledMatcher` groups into more
//! efficient equivalents:
//!
//! - Plain `Contains` matchers in groups of `AHO_CORASICK_THRESHOLD` or more
//!   are batched into `AhoCorasickSet`, replacing a sequential
//!   O(N * haystack_len) scan with a single linear pass over the haystack.
//! - When every child of the resulting group is case-insensitive and
//!   pre-lowerable, the entire group is wrapped in `CaseInsensitiveGroup`,
//!   which lowers the haystack once via `ascii_lowercase_cow` and dispatches
//!   to children via `matches_pre_lowered`. This eliminates the redundant
//!   `to_lowercase()` allocation that each CI matcher would otherwise do.
//!
//! Future extensions may add RegexSet batching for `Regex` groups.
//!
//! # Invariants
//!
//! - The Aho-Corasick collapse is only invoked from `AnyOf` (OR) construction
//!   sites. **Never** called on `AllOf` (`|all` modifier) groups: doing so
//!   would silently flip the semantics from "all patterns must match" to "any
//!   pattern matches".
//! - The `CaseInsensitiveGroup` wrapper requires every child to satisfy
//!   `is_pre_lowerable`. This is enforced at construction time. The hot path
//!   `matches_pre_lowered` `debug_assert!`s on violation.
//! - Pure rewrite. Same input event yields the same `bool` from the optimized
//!   tree as from the unoptimized tree.

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};

use crate::matcher::{CompiledMatcher, GroupMode};

/// Minimum number of patterns in an `AnyOf(Contains)` group required before
/// the optimizer collapses it into an `AhoCorasickSet`.
///
/// **Tuning**: Below this threshold, the sequential `str::contains` path
/// (which uses `memchr`/Two-Way SIMD acceleration) is faster than building
/// an Aho-Corasick automaton. The current value is a starting point; an
/// empirical sweep benchmark refines it for the typical Sigma workload.
pub const AHO_CORASICK_THRESHOLD: usize = 8;

/// Minimum number of pre-lowerable children to justify wrapping in a
/// `CaseInsensitiveGroup`.
///
/// Below this count, the per-child `to_lowercase` cost is dominated by other
/// work and the wrapper provides no measurable benefit.
pub(crate) const CI_GROUP_THRESHOLD: usize = 2;

/// Minimum number of `Regex` children in an `AnyOf` group required before the
/// optimizer collapses them into a single combined `RegexSetMatch`.
///
/// `regex::RegexSet` builds a unified DFA over all patterns; below this
/// threshold the per-pattern `is_match` cost wins because individual `Regex`
/// objects can leverage their own SIMD prefilters without combining.
pub const REGEX_SET_THRESHOLD: usize = 3;

/// Optimize an `AnyOf` group of compiled matchers.
///
/// Input is the raw vector of children that would otherwise be wrapped in
/// `CompiledMatcher::AnyOf(matchers)`. Output is a possibly-rewritten matcher
/// with the same matching semantics.
///
/// Pipeline:
/// 1. Trivial cases: empty input and singletons pass through.
/// 2. Partition into `Contains` (by case sensitivity), `Regex`, and other
///    matchers.
/// 3. Each `Contains` bucket of size >= `AHO_CORASICK_THRESHOLD` becomes one
///    `AhoCorasickSet`; the rest stay as individual `Contains`.
/// 4. The `Regex` bucket of size >= `REGEX_SET_THRESHOLD` becomes one
///    `RegexSetMatch`; otherwise the regexes stay individual.
/// 5. If all surviving children are pre-lowerable and there are >=
///    `CI_GROUP_THRESHOLD` of them, wrap the whole group in
///    `CaseInsensitiveGroup` (Any mode) to lower the haystack once.
pub(crate) fn optimize_any_of(matchers: Vec<CompiledMatcher>) -> CompiledMatcher {
    match matchers.len() {
        0 => return CompiledMatcher::AnyOf(Vec::new()),
        1 => {
            // SAFETY: length checked above.
            return matchers
                .into_iter()
                .next()
                .expect("len == 1 was just checked");
        }
        _ => {}
    }

    // Below the smallest consumer threshold, partitioning cannot pay off:
    // neither AC nor RegexSet would activate, so skip the partition step and
    // go straight to the CI group wrapper for the common short-AnyOf case.
    if matchers.len() < REGEX_SET_THRESHOLD {
        return wrap_ci_group_or_anyof(matchers);
    }

    let mut contains_ci: Vec<String> = Vec::new();
    let mut contains_cs: Vec<String> = Vec::new();
    let mut regexes: Vec<Regex> = Vec::new();
    let mut others: Vec<CompiledMatcher> = Vec::new();

    for m in matchers {
        match m {
            CompiledMatcher::Contains {
                value,
                case_insensitive: true,
            } => contains_ci.push(value),
            CompiledMatcher::Contains {
                value,
                case_insensitive: false,
            } => contains_cs.push(value),
            CompiledMatcher::Regex(re) => regexes.push(re),
            other => others.push(other),
        }
    }

    let mut result: Vec<CompiledMatcher> = Vec::with_capacity(others.len() + 3);
    consume_contains(&mut result, contains_ci, true);
    consume_contains(&mut result, contains_cs, false);
    consume_regexes(&mut result, regexes);
    result.extend(others);

    match result.len() {
        0 => CompiledMatcher::AnyOf(Vec::new()),
        1 => result
            .into_iter()
            .next()
            .expect("len == 1 was just checked"),
        _ => wrap_ci_group_or_anyof(result),
    }
}

/// Wrap `children` in `CaseInsensitiveGroup { mode: Any }` when every child is
/// pre-lowerable and the count meets `CI_GROUP_THRESHOLD`. Otherwise return
/// `AnyOf(children)` unchanged.
fn wrap_ci_group_or_anyof(children: Vec<CompiledMatcher>) -> CompiledMatcher {
    if children.len() >= CI_GROUP_THRESHOLD && children.iter().all(is_pre_lowerable) {
        CompiledMatcher::CaseInsensitiveGroup {
            children,
            mode: GroupMode::Any,
        }
    } else {
        CompiledMatcher::AnyOf(children)
    }
}

/// Returns true when this matcher can be evaluated against a pre-lowered
/// haystack via [`CompiledMatcher::matches_pre_lowered`].
///
/// The set is conservative: anything that is not provably equivalent under
/// pre-lowering returns false (and the caller falls back to `matches`).
pub(crate) fn is_pre_lowerable(m: &CompiledMatcher) -> bool {
    match m {
        // CI string leaves: stored value is already lowered, so a lowered
        // haystack matches iff the original CI-aware matcher would.
        CompiledMatcher::Contains {
            case_insensitive: true,
            ..
        }
        | CompiledMatcher::StartsWith {
            case_insensitive: true,
            ..
        }
        | CompiledMatcher::EndsWith {
            case_insensitive: true,
            ..
        }
        | CompiledMatcher::Exact {
            case_insensitive: true,
            ..
        }
        | CompiledMatcher::AhoCorasickSet {
            case_insensitive: true,
            ..
        } => true,

        // A regex is pre-lowerable iff its pattern carries the case-insensitive
        // flag. Inline `(?i)` and `(?...i...)` flag groups both qualify; we
        // detect them by scanning the leading flag region.
        CompiledMatcher::Regex(re) => regex_is_case_insensitive(re.as_str()),

        // A regex set is pre-lowerable iff every pattern in the set carries
        // the case-insensitive flag.
        CompiledMatcher::RegexSetMatch { set, .. } => {
            set.patterns().iter().all(|p| regex_is_case_insensitive(p))
        }

        // Compositions are pre-lowerable iff every leaf is.
        CompiledMatcher::Not(inner) => is_pre_lowerable(inner),
        CompiledMatcher::AnyOf(children) | CompiledMatcher::AllOf(children) => {
            children.iter().all(is_pre_lowerable)
        }
        CompiledMatcher::CaseInsensitiveGroup { children, .. } => {
            children.iter().all(is_pre_lowerable)
        }

        // Everything else: case-sensitive string matchers, numeric, CIDR,
        // FieldRef, Null, BoolEq, Expand, TimestampPart, etc. — not
        // pre-lowerable.
        _ => false,
    }
}

/// Best-effort detector for an inline `i` flag in a regex pattern string.
///
/// Recognizes `(?i)` and `(?...i...)` flag groups at the start of the pattern.
/// A negated form like `(?-i)` is rejected. False negatives are safe (the
/// regex stays out of the CI group); false positives would be a correctness
/// bug.
fn regex_is_case_insensitive(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    if bytes.len() < 4 || bytes[0] != b'(' || bytes[1] != b'?' {
        return false;
    }
    // Walk the flag set until the first character that ends the group:
    // ')', ':', or '-' (negation onset).
    let mut i = 2;
    while i < bytes.len() {
        match bytes[i] {
            b'i' => return true,
            b')' | b':' | b'-' => return false,
            b'a'..=b'z' | b'A'..=b'Z' => {}
            _ => return false,
        }
        i += 1;
    }
    false
}

/// Consume a bucket of `Regex` matchers, building a single `RegexSetMatch`
/// when the count meets the threshold; otherwise restoring individual
/// `Regex` matchers.
///
/// Pattern reconstruction uses [`Regex::as_str`], which returns the original
/// pattern string with any inline flags (e.g. `(?i)`, `(?ims)`) intact. The
/// eval crate's `build_regex` helper inlines flags into the pattern string
/// rather than configuring them via `RegexBuilder`, so reconstruction is
/// lossless. A unit test guards this contract.
fn consume_regexes(result: &mut Vec<CompiledMatcher>, regexes: Vec<Regex>) {
    if regexes.is_empty() {
        return;
    }
    if regexes.len() >= REGEX_SET_THRESHOLD {
        let patterns: Vec<&str> = regexes.iter().map(Regex::as_str).collect();
        if let Ok(set) = RegexSet::new(&patterns) {
            result.push(CompiledMatcher::RegexSetMatch {
                set,
                mode: GroupMode::Any,
            });
            return;
        }
    }
    for re in regexes {
        result.push(CompiledMatcher::Regex(re));
    }
}

/// Consume a bucket of `Contains` needles, building an `AhoCorasickSet`
/// when the count meets the threshold; otherwise, restoring individual
/// `Contains` matchers.
fn consume_contains(result: &mut Vec<CompiledMatcher>, needles: Vec<String>, ci: bool) {
    if needles.is_empty() {
        return;
    }
    if needles.len() >= AHO_CORASICK_THRESHOLD
        && let Ok(automaton) = AhoCorasick::new(&needles)
    {
        // Needles are already pre-lowered when ci=true (Contains invariant from
        // `compile_string_value`). The automaton itself is built case-sensitively;
        // the hot path lowers the haystack before searching.
        result.push(CompiledMatcher::AhoCorasickSet {
            automaton,
            case_insensitive: ci,
            needles,
        });
        return;
    }
    for value in needles {
        result.push(CompiledMatcher::Contains {
            value,
            case_insensitive: ci,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventValue, JsonEvent};
    use serde_json::json;

    fn ci_contains(s: &str) -> CompiledMatcher {
        CompiledMatcher::Contains {
            value: s.to_lowercase(),
            case_insensitive: true,
        }
    }

    fn cs_contains(s: &str) -> CompiledMatcher {
        CompiledMatcher::Contains {
            value: s.to_string(),
            case_insensitive: false,
        }
    }

    #[test]
    fn empty_input_returns_empty_anyof() {
        let m = optimize_any_of(Vec::new());
        assert!(matches!(m, CompiledMatcher::AnyOf(ref v) if v.is_empty()));
    }

    #[test]
    fn singleton_unwraps() {
        let m = optimize_any_of(vec![ci_contains("foo")]);
        assert!(matches!(
            m,
            CompiledMatcher::Contains {
                case_insensitive: true,
                ..
            }
        ));
    }

    #[test]
    fn below_ac_threshold_wraps_ci_group_when_all_pre_lowerable() {
        let needles: Vec<_> = (0..AHO_CORASICK_THRESHOLD - 1)
            .map(|i| ci_contains(&format!("p{i}")))
            .collect();
        let m = optimize_any_of(needles);
        match m {
            CompiledMatcher::CaseInsensitiveGroup {
                children,
                mode: GroupMode::Any,
            } => assert_eq!(children.len(), AHO_CORASICK_THRESHOLD - 1),
            other => panic!("expected CaseInsensitiveGroup, got {other:?}"),
        }
    }

    #[test]
    fn below_ac_threshold_keeps_anyof_when_mixed_case() {
        // Mixing CI and CS Contains makes the group non-pre-lowerable: the CS
        // Contains has its needle in original case and would not match a
        // pre-lowered haystack.
        let needles: Vec<CompiledMatcher> = vec![ci_contains("foo"), cs_contains("BAR")];
        let m = optimize_any_of(needles);
        assert!(matches!(m, CompiledMatcher::AnyOf(ref v) if v.len() == 2));
    }

    #[test]
    fn at_threshold_builds_aho_corasick() {
        // At threshold all needles collapse into a single AhoCorasickSet.
        // After CI grouping the singleton bypasses CaseInsensitiveGroup
        // wrapping (since CI_GROUP_THRESHOLD requires >= 2 children) and the
        // top-level result is the bare AhoCorasickSet.
        let needles: Vec<_> = (0..AHO_CORASICK_THRESHOLD)
            .map(|i| ci_contains(&format!("p{i}")))
            .collect();
        let m = optimize_any_of(needles);
        assert!(matches!(
            m,
            CompiledMatcher::AhoCorasickSet {
                case_insensitive: true,
                ..
            }
        ));
    }

    #[test]
    fn separate_buckets_for_ci_and_cs() {
        let mut needles = Vec::new();
        for i in 0..AHO_CORASICK_THRESHOLD {
            needles.push(ci_contains(&format!("ci{i}")));
        }
        for i in 0..AHO_CORASICK_THRESHOLD {
            needles.push(cs_contains(&format!("CS{i}")));
        }
        let m = optimize_any_of(needles);
        let children = match m {
            CompiledMatcher::AnyOf(v) => v,
            _ => panic!("expected AnyOf wrapping two AC sets"),
        };
        assert_eq!(children.len(), 2);
        assert!(children.iter().any(|c| matches!(
            c,
            CompiledMatcher::AhoCorasickSet {
                case_insensitive: true,
                ..
            }
        )));
        assert!(children.iter().any(|c| matches!(
            c,
            CompiledMatcher::AhoCorasickSet {
                case_insensitive: false,
                ..
            }
        )));
    }

    #[test]
    fn mixed_pre_lowerable_children_are_wrapped_in_ci_group() {
        // AhoCorasickSet{ci=true} + CI StartsWith + CI EndsWith are all
        // pre-lowerable, so the optimizer should wrap them in a
        // CaseInsensitiveGroup to lower the haystack once for all three.
        let mut needles: Vec<_> = (0..AHO_CORASICK_THRESHOLD)
            .map(|i| ci_contains(&format!("p{i}")))
            .collect();
        needles.push(CompiledMatcher::StartsWith {
            value: "cmd".into(),
            case_insensitive: true,
        });
        needles.push(CompiledMatcher::EndsWith {
            value: ".exe".into(),
            case_insensitive: true,
        });

        let m = optimize_any_of(needles);
        let children = match m {
            CompiledMatcher::CaseInsensitiveGroup {
                children,
                mode: GroupMode::Any,
            } => children,
            other => panic!("expected CaseInsensitiveGroup, got {other:?}"),
        };
        assert_eq!(children.len(), 3);
        assert!(matches!(
            children[0],
            CompiledMatcher::AhoCorasickSet { .. }
        ));
        assert!(matches!(children[1], CompiledMatcher::StartsWith { .. }));
        assert!(matches!(children[2], CompiledMatcher::EndsWith { .. }));
    }

    #[test]
    fn ci_group_skipped_when_a_child_is_case_sensitive() {
        // One CS Contains poisons the group: it must NOT see a pre-lowered
        // haystack, so the optimizer must keep AnyOf as-is.
        let mut needles: Vec<_> = (0..AHO_CORASICK_THRESHOLD)
            .map(|i| ci_contains(&format!("p{i}")))
            .collect();
        needles.push(cs_contains("EXACT"));

        let m = optimize_any_of(needles);
        assert!(matches!(m, CompiledMatcher::AnyOf(ref v) if v.len() == 2));
    }

    #[test]
    fn is_pre_lowerable_classifies_correctly() {
        use regex::Regex;

        // Pre-lowerable cases.
        assert!(is_pre_lowerable(&ci_contains("foo")));
        assert!(is_pre_lowerable(&CompiledMatcher::StartsWith {
            value: "x".into(),
            case_insensitive: true,
        }));
        assert!(is_pre_lowerable(&CompiledMatcher::EndsWith {
            value: "x".into(),
            case_insensitive: true,
        }));
        assert!(is_pre_lowerable(&CompiledMatcher::Exact {
            value: "x".into(),
            case_insensitive: true,
        }));
        assert!(is_pre_lowerable(&CompiledMatcher::Regex(
            Regex::new(r"(?i)foo.*bar").unwrap()
        )));
        assert!(is_pre_lowerable(&CompiledMatcher::Regex(
            Regex::new(r"(?ims)foo").unwrap()
        )));

        // Not pre-lowerable.
        assert!(!is_pre_lowerable(&cs_contains("foo")));
        assert!(!is_pre_lowerable(&CompiledMatcher::Exact {
            value: "X".into(),
            case_insensitive: false,
        }));
        // Regex without the i flag: case-sensitive, must not appear in CI group.
        assert!(!is_pre_lowerable(&CompiledMatcher::Regex(
            Regex::new(r"^foo").unwrap()
        )));
        // Numeric and CIDR are never pre-lowerable.
        assert!(!is_pre_lowerable(&CompiledMatcher::NumericEq(42.0)));
        assert!(!is_pre_lowerable(&CompiledMatcher::Cidr(
            "10.0.0.0/8".parse().unwrap()
        )));
    }

    #[test]
    fn regex_is_case_insensitive_recognizer() {
        assert!(regex_is_case_insensitive("(?i)foo"));
        assert!(regex_is_case_insensitive("(?im)foo"));
        assert!(regex_is_case_insensitive("(?si)foo"));
        // No flags.
        assert!(!regex_is_case_insensitive("foo"));
        // Other flags only.
        assert!(!regex_is_case_insensitive("(?m)foo"));
        // Empty / malformed.
        assert!(!regex_is_case_insensitive(""));
        assert!(!regex_is_case_insensitive("(?"));
        // Negated flag (not yet trusted to keep things simple).
        assert!(!regex_is_case_insensitive("(?-i)foo"));
        // Group with subpattern (we conservatively bail at ':').
        assert!(!regex_is_case_insensitive("(?:foo)"));
    }

    #[test]
    fn ci_group_matches_same_haystacks_as_anyof() {
        let event_json = json!({});
        let event = JsonEvent::borrow(&event_json);

        let make_children = || -> Vec<CompiledMatcher> {
            vec![
                ci_contains("powershell"),
                CompiledMatcher::StartsWith {
                    value: "cmd".to_lowercase(),
                    case_insensitive: true,
                },
                CompiledMatcher::EndsWith {
                    value: ".exe".to_lowercase(),
                    case_insensitive: true,
                },
                CompiledMatcher::Exact {
                    value: "whoami".to_lowercase(),
                    case_insensitive: true,
                },
            ]
        };
        let optimized = optimize_any_of(make_children());
        let unoptimized = CompiledMatcher::AnyOf(make_children());

        // Optimizer must have wrapped in CaseInsensitiveGroup.
        assert!(matches!(
            optimized,
            CompiledMatcher::CaseInsensitiveGroup {
                mode: GroupMode::Any,
                ..
            }
        ));

        for s in [
            "PowerShell.exe -enc XYZ",
            "CMD.exe /c whoami",
            "C:/Windows/System32/notepad.exe",
            "WHOAMI",
            "no match",
            "",
        ] {
            let v = EventValue::Str(s.into());
            assert_eq!(
                optimized.matches(&v, &event),
                unoptimized.matches(&v, &event),
                "CI group disagrees with AnyOf on {s:?}"
            );
        }
    }

    #[test]
    fn ac_matches_same_haystack_as_anyof() {
        // Equivalence smoke test: the optimized matcher must match the same
        // haystacks as the unoptimized one.
        let needles_str = [
            "whoami",
            "mimikatz",
            "powershell",
            "invoke",
            "iex",
            "rundll32",
            "regsvr32",
            "certutil",
        ];
        assert!(needles_str.len() >= AHO_CORASICK_THRESHOLD);

        let optimized = optimize_any_of(needles_str.iter().map(|s| ci_contains(s)).collect());
        let unoptimized =
            CompiledMatcher::AnyOf(needles_str.iter().map(|s| ci_contains(s)).collect());

        let event_json = json!({});
        let event = JsonEvent::borrow(&event_json);

        let test_strings = [
            "cmd.exe /c whoami",
            "Invoke-Mimikatz with PowerShell",
            "no patterns here",
            "RUNDLL32.EXE foo.dll",
            "WHOAMI in caps",
            "",
        ];
        for s in test_strings {
            let v = EventValue::Str(s.into());
            assert_eq!(
                optimized.matches(&v, &event),
                unoptimized.matches(&v, &event),
                "mismatch on haystack {s:?}"
            );
        }
    }

    // =========================================================================
    // RegexSet batching
    // =========================================================================

    fn ci_regex(pattern: &str) -> CompiledMatcher {
        // Mimic the eval crate's `compile_sigma_string` which inlines `(?i)`
        // into the pattern string when CI is on.
        CompiledMatcher::Regex(regex::Regex::new(&format!("(?i){pattern}")).unwrap())
    }

    #[test]
    fn at_threshold_builds_regex_set() {
        let regexes: Vec<_> = (0..REGEX_SET_THRESHOLD)
            .map(|i| ci_regex(&format!("foo{i}")))
            .collect();
        let m = optimize_any_of(regexes);
        assert!(matches!(
            m,
            CompiledMatcher::RegexSetMatch {
                mode: GroupMode::Any,
                ..
            }
        ));
    }

    #[test]
    fn below_regex_set_threshold_keeps_individual_regexes() {
        let regexes: Vec<_> = (0..REGEX_SET_THRESHOLD - 1)
            .map(|i| ci_regex(&format!("foo{i}")))
            .collect();
        let m = optimize_any_of(regexes);
        // 2 CI regexes are pre-lowerable, so they get wrapped in CI group.
        match m {
            CompiledMatcher::CaseInsensitiveGroup { children, .. } => {
                assert_eq!(children.len(), REGEX_SET_THRESHOLD - 1);
                assert!(
                    children
                        .iter()
                        .all(|c| matches!(c, CompiledMatcher::Regex(_)))
                );
            }
            other => panic!("expected CaseInsensitiveGroup with individual regexes, got {other:?}"),
        }
    }

    #[test]
    fn regex_set_matches_same_haystacks_as_individual_regexes() {
        let patterns = [r"^cmd\.exe", r"powershell", r"\.ps1$", r"mimikatz"];
        let make_children =
            || -> Vec<CompiledMatcher> { patterns.iter().map(|p| ci_regex(p)).collect() };
        let optimized = optimize_any_of(make_children());
        let unoptimized = CompiledMatcher::AnyOf(make_children());

        let event_json = json!({});
        let event = JsonEvent::borrow(&event_json);

        for s in [
            "cmd.exe /c whoami",
            "POWERSHELL.EXE -enc",
            "C:/scripts/run.PS1",
            "Invoke-MIMIKATZ",
            "notepad.exe",
            "",
        ] {
            let v = EventValue::Str(s.into());
            assert_eq!(
                optimized.matches(&v, &event),
                unoptimized.matches(&v, &event),
                "RegexSet disagrees with AnyOf(Regex) on {s:?}"
            );
        }
    }

    #[test]
    fn mixed_contains_and_regex_partitions_correctly() {
        // 8 CI Contains -> AC; 3 CI Regex -> RegexSet; one CS Exact -> stays.
        // Expected result: AnyOf([AhoCorasickSet, RegexSetMatch, Exact{cs}])
        // (CI group skipped because the CS Exact is not pre-lowerable.)
        let mut input = Vec::new();
        for i in 0..AHO_CORASICK_THRESHOLD {
            input.push(ci_contains(&format!("c{i}")));
        }
        for i in 0..REGEX_SET_THRESHOLD {
            input.push(ci_regex(&format!("r{i}")));
        }
        input.push(CompiledMatcher::Exact {
            value: "EXACT".into(),
            case_insensitive: false,
        });

        let m = optimize_any_of(input);
        let children = match m {
            CompiledMatcher::AnyOf(v) => v,
            other => panic!("expected AnyOf, got {other:?}"),
        };
        assert_eq!(children.len(), 3);
        assert!(
            children
                .iter()
                .any(|c| matches!(c, CompiledMatcher::AhoCorasickSet { .. }))
        );
        assert!(
            children
                .iter()
                .any(|c| matches!(c, CompiledMatcher::RegexSetMatch { .. }))
        );
        assert!(children.iter().any(|c| matches!(
            c,
            CompiledMatcher::Exact {
                case_insensitive: false,
                ..
            }
        )));
    }

    /// Guard against future regressions where someone switches `build_regex`
    /// from inlined `(?i)` flags to `regex::RegexBuilder::case_insensitive`,
    /// which would silently strip the flag from `Regex::as_str()` and break
    /// pattern reconstruction inside `RegexSet`.
    #[test]
    fn build_regex_keeps_flags_in_pattern_string() {
        use super::super::helpers::build_regex;
        let re = build_regex("foo", true, false, false).unwrap();
        let s = re.as_str();
        assert!(
            s.starts_with("(?") && s.contains('i'),
            "build_regex must inline case-insensitive flag into pattern string, got {s:?}"
        );

        // Round-trip through RegexSet must preserve case insensitivity.
        let set = regex::RegexSet::new([s]).unwrap();
        assert!(set.is_match("FOO"), "RegexSet lost the (?i) flag");
    }

    #[test]
    fn regex_set_pre_lowerable_when_all_patterns_are_ci() {
        let set = regex::RegexSet::new(["(?i)foo", "(?i)bar"]).unwrap();
        let m = CompiledMatcher::RegexSetMatch {
            set,
            mode: GroupMode::Any,
        };
        assert!(is_pre_lowerable(&m));
    }

    #[test]
    fn regex_set_not_pre_lowerable_when_any_pattern_is_cs() {
        let set = regex::RegexSet::new(["(?i)foo", "bar"]).unwrap();
        let m = CompiledMatcher::RegexSetMatch {
            set,
            mode: GroupMode::Any,
        };
        assert!(!is_pre_lowerable(&m));
    }
}
