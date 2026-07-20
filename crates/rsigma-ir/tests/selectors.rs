//! Mandatory selector fixtures.
//!
//! Common Sigma regression points:
//! - vacuous `all of <pattern>` over zero matching detection names → true
//! - `them` skips `_`-prefixed detection names
//! - glob/prefix patterns still match `_`-prefixed names when selected explicitly
//!
//! Vacuous cases use [`common::compiled_from`] + [`common::rule_matches`] so
//! unused detections cannot be dropped by the engine rule index.

mod common;

use common::{compiled_from, engine_from, matches, rule_matches, titles_for};
use serde_json::json;

// =============================================================================
// Vacuous `all of`
// =============================================================================

#[test]
fn vacuous_all_of_zero_matches_is_true() {
    // Pattern `selection_*` matches zero detection names (`filter_main` does not).
    // Legacy eval: Quantifier::All over an empty name set → 0 == 0 → true.
    // HIR lowering must emit vacuous `IrCondition::And([])` with the same meaning.
    let rule = compiled_from(
        r#"
title: Vacuous All Of Zero
id: vacuous-all-of-zero
logsource:
    category: test
detection:
    filter_main:
        Image: 'notepad.exe'
    condition: all of selection_*
level: low
"#,
    );
    assert!(rule_matches(&rule, &json!({"Image": "evil.exe"})));
    assert!(rule_matches(&rule, &json!({"CommandLine": "whoami"})));
    assert!(rule_matches(&rule, &json!({})));
}

#[test]
fn vacuous_all_of_multiple_patterns_is_true() {
    let rule = compiled_from(
        r#"
title: Vacuous All Of Multiple
id: vacuous-all-of-multi
logsource:
    category: test
detection:
    filter_main:
        Image: 'notepad.exe'
    condition: all of selection_a* and all of selection_b*
level: low
"#,
    );
    assert!(rule_matches(&rule, &json!({"Image": "evil.exe"})));
    assert!(rule_matches(&rule, &json!({})));
}

#[test]
fn nonvacuous_all_of_requires_matching_detection() {
    // Control: `selection_main` matches `selection_*`, so the condition is not vacuous.
    let engine = engine_from(
        r#"
title: Nonvacuous All Of
id: nonvacuous-all-of
logsource:
    category: test
detection:
    selection_main:
        Image: 'notepad.exe'
    condition: all of selection_*
level: low
"#,
    );
    assert!(matches(&engine, &json!({"Image": "notepad.exe"})));
    assert!(!matches(&engine, &json!({"Image": "evil.exe"})));
}

// =============================================================================
// `them` skips `_`-prefixed detection names
// =============================================================================

#[test]
fn them_skips_underscore_prefixed_detection_names() {
    let yaml = r#"
title: Them Skip Prefix
id: them-skip-prefix
logsource:
    category: test
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 1 of them
level: low
"#;
    let rule = compiled_from(yaml);
    // Direct evaluate_rule: proves them-skipping, not engine index pruning.
    assert!(rule_matches(&rule, &json!({"Image": "notepad.exe"})));
    assert!(
        !rule_matches(&rule, &json!({"Image": "evil.exe"})),
        "`them` must skip `_internal` even when that detection matches the event"
    );
    assert!(!rule_matches(&rule, &json!({})));

    let engine = engine_from(yaml);
    assert_eq!(
        titles_for(&engine, &json!({"Image": "notepad.exe"})),
        vec!["Them Skip Prefix".to_string()]
    );
}

#[test]
fn all_of_them_skips_underscore_prefixed_names() {
    let engine = engine_from(
        r#"
title: Them All Skip
id: them-all-skip
logsource:
    category: test
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: all of them
level: low
"#,
    );
    assert!(matches(&engine, &json!({"Image": "notepad.exe"})));
    assert!(!matches(&engine, &json!({"Image": "evil.exe"})));
}

#[test]
fn count_of_them_ignores_underscore_prefixed_names() {
    // Only one non-`_` detection exists, so `2 of them` can never match.
    let engine = engine_from(
        r#"
title: Them Count Skip
id: them-count-skip
logsource:
    category: test
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 2 of them
level: low
"#,
    );
    assert!(!matches(&engine, &json!({"Image": "notepad.exe"})));
    assert!(!matches(&engine, &json!({"Image": "evil.exe"})));
}

// =============================================================================
// Glob/prefix patterns match `_`-prefixed names (unlike `them`)
// =============================================================================

#[test]
fn glob_pattern_matches_underscore_prefixed_detection_name() {
    // The `_` convention applies only to `them`, not to explicit patterns.
    let engine = engine_from(
        r#"
title: Glob Matches Underscore
id: glob-underscore
logsource:
    category: test
detection:
    selection_main:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 1 of _*
level: low
"#,
    );
    assert!(!matches(&engine, &json!({"Image": "notepad.exe"})));
    assert_eq!(
        titles_for(&engine, &json!({"Image": "evil.exe"})),
        vec!["Glob Matches Underscore".to_string()]
    );
}

#[test]
fn exact_pattern_matches_underscore_prefixed_detection_name() {
    let engine = engine_from(
        r#"
title: Exact Underscore Pattern
id: exact-underscore
logsource:
    category: test
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 1 of _internal
level: low
"#,
    );
    assert!(!matches(&engine, &json!({"Image": "notepad.exe"})));
    assert!(matches(&engine, &json!({"Image": "evil.exe"})));
}

#[test]
fn selection_star_does_not_match_bare_selection_name() {
    // Documents glob semantics: `selection_*` requires the underscore suffix.
    // `selection` alone is not a match (regression guard for fixture authors).
    let rule = compiled_from(
        r#"
title: Selection Star Semantics
id: selection-star-semantics
logsource:
    category: test
detection:
    selection:
        Image: 'notepad.exe'
    condition: 1 of selection_*
level: low
"#,
    );
    assert!(
        !rule_matches(&rule, &json!({"Image": "notepad.exe"})),
        "`selection` must not match pattern `selection_*`"
    );
}
