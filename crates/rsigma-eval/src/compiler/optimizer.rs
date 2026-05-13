//! Optimization passes over compiled matcher trees.
//!
//! The optimizer rewrites `CompiledMatcher::AnyOf(...)` groups into more
//! efficient equivalents:
//!
//! - **Phase 1**: Plain `Contains` matchers in groups of `AHO_CORASICK_THRESHOLD`
//!   or more are batched into `AhoCorasickSet`, replacing a sequential
//!   O(N * haystack_len) scan with a single linear pass over the haystack.
//!
//! Future extensions may add RegexSet batching for `Regex` groups, and
//! a case-insensitive group wrapper that lowers the haystack once before
//! dispatching to children.
//!
//! # Invariants
//!
//! - Only invoked from `AnyOf` (OR) construction sites. **Never** called on
//!   `AllOf` (`|all` modifier) groups: doing so would silently flip the
//!   semantics from "all patterns must match" to "any pattern matches".
//! - Pure rewrite. Same input event yields the same `bool` from the optimized
//!   tree as from the unoptimized tree.

use aho_corasick::AhoCorasick;

use crate::matcher::CompiledMatcher;

/// Minimum number of patterns in an `AnyOf(Contains)` group required before
/// the optimizer collapses it into an `AhoCorasickSet`.
///
/// **Tuning**: Below this threshold, the sequential `str::contains` path
/// (which uses `memchr`/Two-Way SIMD acceleration) is faster than building
/// an Aho-Corasick automaton. The current value is a starting point; an
/// empirical sweep benchmark refines it for the typical Sigma workload.
pub const AHO_CORASICK_THRESHOLD: usize = 8;

/// Optimize an `AnyOf` group of compiled matchers.
///
/// Input is the raw vector of children that would otherwise be wrapped in
/// `CompiledMatcher::AnyOf(matchers)`. Output is a possibly-rewritten matcher
/// with the same matching semantics.
///
/// - `matchers.len() == 0` produces an empty `AnyOf` (always-false).
/// - `matchers.len() == 1` unwraps the singleton matcher (no AnyOf wrapper).
/// - Otherwise, partitions children into buckets and tries to build an
///   `AhoCorasickSet` for `Contains` buckets exceeding the threshold.
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
        n if n < AHO_CORASICK_THRESHOLD => {
            return CompiledMatcher::AnyOf(matchers);
        }
        _ => {}
    }

    let mut contains_ci: Vec<String> = Vec::new();
    let mut contains_cs: Vec<String> = Vec::new();
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
            other => others.push(other),
        }
    }

    let mut result: Vec<CompiledMatcher> = Vec::with_capacity(others.len() + 2);
    consume_contains(&mut result, contains_ci, true);
    consume_contains(&mut result, contains_cs, false);
    result.extend(others);

    match result.len() {
        0 => CompiledMatcher::AnyOf(Vec::new()),
        1 => result
            .into_iter()
            .next()
            .expect("len == 1 was just checked"),
        _ => CompiledMatcher::AnyOf(result),
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
    fn below_threshold_keeps_anyof() {
        let needles: Vec<_> = (0..AHO_CORASICK_THRESHOLD - 1)
            .map(|i| ci_contains(&format!("p{i}")))
            .collect();
        let m = optimize_any_of(needles);
        match m {
            CompiledMatcher::AnyOf(v) => assert_eq!(v.len(), AHO_CORASICK_THRESHOLD - 1),
            _ => panic!("expected AnyOf below threshold"),
        }
    }

    #[test]
    fn at_threshold_builds_aho_corasick() {
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
    fn mixed_with_other_matchers_preserves_them() {
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
            CompiledMatcher::AnyOf(v) => v,
            _ => panic!("expected AnyOf wrapping AC + StartsWith + EndsWith"),
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
}
