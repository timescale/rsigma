use serde_yaml::Value;

use super::super::{
    Fix, FixDisposition, FixPatch, LintRule, LintWarning, Severity, closest_match, err, info, key,
    safe_fix, warning,
};

/// Valid status values.
const VALID_STATUSES: &[&str] = &[
    "stable",
    "test",
    "experimental",
    "deprecated",
    "unsupported",
];

/// Valid level values.
const VALID_LEVELS: &[&str] = &["informational", "low", "medium", "high", "critical"];

/// Validate a date string matches YYYY-MM-DD with correct day-of-month.
fn is_valid_date(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let year_ok = bytes[0..4].iter().all(|b| b.is_ascii_digit());
    let year: u16 = s[0..4].parse().unwrap_or(0);
    let month: u8 = s[5..7].parse().unwrap_or(0);
    let day: u8 = s[8..10].parse().unwrap_or(0);
    if !year_ok || !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let is_leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    day <= max_day
}

/// Extract a date string from a YAML value, handling serde_yaml auto-parsing.
///
/// `serde_yaml` sometimes deserialises `YYYY-MM-DD` as a tagged/non-string
/// type. This helper coerces such values back to a trimmed string.
fn extract_date_string(raw: &Value) -> Option<String> {
    raw.as_str().map(|s| s.to_string()).or_else(|| {
        serde_yaml::to_string(raw)
            .ok()
            .map(|s| s.trim().to_string())
    })
}

/// Validate a UUID string (any version, hyphenated form).
pub(crate) fn is_valid_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    parts
        .iter()
        .zip(expected_lens.iter())
        .all(|(part, &len)| part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit()))
}

pub(crate) fn lint_shared(m: &serde_yaml::Mapping, warnings: &mut Vec<LintWarning>) {
    // ── title ────────────────────────────────────────────────────────────
    match super::super::get_str(m, "title") {
        None => warnings.push(err(
            LintRule::MissingTitle,
            "missing required field 'title'",
            "/title",
        )),
        Some(t) if t.trim().is_empty() => {
            warnings.push(err(
                LintRule::EmptyTitle,
                "title must not be empty",
                "/title",
            ));
        }
        Some(t) if t.len() > 256 => {
            warnings.push(warning(
                LintRule::TitleTooLong,
                format!("title is {} characters, maximum is 256", t.len()),
                "/title",
            ));
        }
        _ => {}
    }

    // ── id ───────────────────────────────────────────────────────────────
    if let Some(id) = super::super::get_str(m, "id")
        && !is_valid_uuid(id)
    {
        warnings.push(warning(
            LintRule::InvalidId,
            format!("id \"{id}\" is not a valid UUID"),
            "/id",
        ));
    }

    // ── status ───────────────────────────────────────────────────────────
    if let Some(status) = super::super::get_str(m, "status")
        && !VALID_STATUSES.contains(&status)
    {
        let fix = closest_match(status, VALID_STATUSES, 3).map(|closest| Fix {
            title: format!("replace '{status}' with '{closest}'"),
            disposition: FixDisposition::Safe,
            patches: vec![FixPatch::ReplaceValue {
                path: "/status".into(),
                new_value: closest.into(),
            }],
        });
        warnings.push(LintWarning {
            rule: LintRule::InvalidStatus,
            severity: Severity::Error,
            message: format!(
                "invalid status \"{status}\", expected one of: {}",
                VALID_STATUSES.join(", ")
            ),
            path: "/status".into(),
            span: None,
            fix,
        });
    }

    // ── level ────────────────────────────────────────────────────────────
    if let Some(level) = super::super::get_str(m, "level")
        && !VALID_LEVELS.contains(&level)
    {
        let fix = closest_match(level, VALID_LEVELS, 3).map(|closest| Fix {
            title: format!("replace '{level}' with '{closest}'"),
            disposition: FixDisposition::Safe,
            patches: vec![FixPatch::ReplaceValue {
                path: "/level".into(),
                new_value: closest.into(),
            }],
        });
        warnings.push(LintWarning {
            rule: LintRule::InvalidLevel,
            severity: Severity::Error,
            message: format!(
                "invalid level \"{level}\", expected one of: {}",
                VALID_LEVELS.join(", ")
            ),
            path: "/level".into(),
            span: None,
            fix,
        });
    }

    // ── date ─────────────────────────────────────────────────────────────
    let date_string = m.get(key("date")).and_then(extract_date_string);
    if let Some(d) = &date_string
        && !is_valid_date(d)
    {
        warnings.push(err(
            LintRule::InvalidDate,
            format!("invalid date \"{d}\", expected YYYY-MM-DD"),
            "/date",
        ));
    }

    // ── modified ─────────────────────────────────────────────────────────
    let modified_string = m.get(key("modified")).and_then(extract_date_string);
    if let Some(d) = &modified_string
        && !is_valid_date(d)
    {
        warnings.push(err(
            LintRule::InvalidModified,
            format!("invalid modified date \"{d}\", expected YYYY-MM-DD"),
            "/modified",
        ));
    }

    // ── modified >= date ─────────────────────────────────────────────────
    if let (Some(date_val), Some(mod_val)) = (&date_string, &modified_string)
        && is_valid_date(date_val)
        && is_valid_date(mod_val)
        && mod_val.as_str() < date_val.as_str()
    {
        warnings.push(warning(
            LintRule::ModifiedBeforeDate,
            format!("modified date \"{mod_val}\" is before creation date \"{date_val}\""),
            "/modified",
        ));
    }

    // ── description (missing) ──────────────────────────────────────────
    if !m.contains_key(key("description")) {
        warnings.push(info(
            LintRule::MissingDescription,
            "missing recommended field 'description'",
            "/description",
        ));
    }

    // ── author (missing) ─────────────────────────────────────────────
    if !m.contains_key(key("author")) {
        warnings.push(info(
            LintRule::MissingAuthor,
            "missing recommended field 'author'",
            "/author",
        ));
    }

    // ── description (too long) ───────────────────────────────────────
    if let Some(desc) = super::super::get_str(m, "description")
        && desc.len() > 65535
    {
        warnings.push(warning(
            LintRule::DescriptionTooLong,
            format!("description is {} characters, maximum is 65535", desc.len()),
            "/description",
        ));
    }

    // ── name ─────────────────────────────────────────────────────────────
    if let Some(name) = super::super::get_str(m, "name")
        && name.len() > 256
    {
        warnings.push(warning(
            LintRule::NameTooLong,
            format!("name is {} characters, maximum is 256", name.len()),
            "/name",
        ));
    }

    // ── taxonomy ─────────────────────────────────────────────────────────
    if let Some(tax) = super::super::get_str(m, "taxonomy")
        && tax.len() > 256
    {
        warnings.push(warning(
            LintRule::TaxonomyTooLong,
            format!("taxonomy is {} characters, maximum is 256", tax.len()),
            "/taxonomy",
        ));
    }

    // ── lowercase keys ───────────────────────────────────────────────────
    for k in m.keys() {
        if let Some(ks) = k.as_str()
            && ks != ks.to_ascii_lowercase()
        {
            let lower = ks.to_ascii_lowercase();
            let mut w = warning(
                LintRule::NonLowercaseKey,
                format!("key \"{ks}\" should be lowercase"),
                format!("/{ks}"),
            );
            w.fix = safe_fix(
                format!("rename '{ks}' to '{lower}'"),
                vec![FixPatch::ReplaceKey {
                    path: format!("/{ks}"),
                    new_key: lower,
                }],
            );
            warnings.push(w);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{Fix, LintRule, LintWarning, Severity, lint_yaml_value};
    use super::*;

    fn yaml_value(yaml: &str) -> serde_yaml::Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    fn lint(yaml: &str) -> Vec<LintWarning> {
        lint_yaml_value(&yaml_value(yaml))
    }

    fn has_rule(warnings: &[LintWarning], rule: LintRule) -> bool {
        warnings.iter().any(|w| w.rule == rule)
    }

    fn has_no_rule(warnings: &[LintWarning], rule: LintRule) -> bool {
        !has_rule(warnings, rule)
    }

    fn find_fix(warnings: &[LintWarning], rule: LintRule) -> Option<&Fix> {
        warnings
            .iter()
            .find(|w| w.rule == rule)
            .and_then(|w| w.fix.as_ref())
    }

    fn fix_summary(fix: &Fix) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        writeln!(s, "title: {}", fix.title).unwrap();
        writeln!(s, "disposition: {:?}", fix.disposition).unwrap();
        for (i, p) in fix.patches.iter().enumerate() {
            match p {
                super::super::super::FixPatch::ReplaceValue { path, new_value } => {
                    writeln!(s, "patch[{i}]: ReplaceValue {path} -> {new_value}").unwrap();
                }
                super::super::super::FixPatch::ReplaceKey { path, new_key } => {
                    writeln!(s, "patch[{i}]: ReplaceKey {path} -> {new_key}").unwrap();
                }
                super::super::super::FixPatch::Remove { path } => {
                    writeln!(s, "patch[{i}]: Remove {path}").unwrap();
                }
            }
        }
        s
    }

    #[test]
    fn missing_title() {
        let w = lint(
            r#"
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingTitle));
    }

    #[test]
    fn empty_title() {
        let w = lint(
            r#"
title: ''
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::EmptyTitle));
    }

    #[test]
    fn title_too_long() {
        let long_title = "a".repeat(257);
        let yaml = format!(
            r#"
title: '{long_title}'
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#
        );
        let w = lint(&yaml);
        assert!(has_rule(&w, LintRule::TitleTooLong));
    }

    #[test]
    fn invalid_id() {
        let w = lint(
            r#"
title: Test
id: not-a-uuid
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidId));
    }

    #[test]
    fn valid_id_no_warning() {
        let w = lint(
            r#"
title: Test
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_no_rule(&w, LintRule::InvalidId));
    }

    #[test]
    fn invalid_status() {
        let w = lint(
            r#"
title: Test
status: invalid
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidStatus));
    }

    #[test]
    fn invalid_level() {
        let w = lint(
            r#"
title: Test
level: important
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidLevel));
    }

    #[test]
    fn invalid_date_format() {
        let w = lint(
            r#"
title: Test
date: 'Jan 2025'
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidDate));
    }

    #[test]
    fn modified_before_date() {
        let w = lint(
            r#"
title: Test
date: '2025-06-15'
modified: '2025-06-10'
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::ModifiedBeforeDate));
    }

    #[test]
    fn non_lowercase_key() {
        let w = lint(
            r#"
title: Test
Status: test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::NonLowercaseKey));
    }

    #[test]
    fn invalid_date_feb_30() {
        assert!(!is_valid_date("2025-02-30"));
    }

    #[test]
    fn invalid_date_apr_31() {
        assert!(!is_valid_date("2025-04-31"));
    }

    #[test]
    fn valid_date_feb_28() {
        assert!(is_valid_date("2025-02-28"));
    }

    #[test]
    fn valid_date_leap_year_feb_29() {
        assert!(is_valid_date("2024-02-29"));
    }

    #[test]
    fn invalid_date_non_leap_feb_29() {
        assert!(!is_valid_date("2025-02-29"));
    }

    #[test]
    fn missing_description_info() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::MissingDescription));
        let md = w
            .iter()
            .find(|w| w.rule == LintRule::MissingDescription)
            .unwrap();
        assert_eq!(md.severity, Severity::Info);
    }

    #[test]
    fn has_description_no_info() {
        let w = lint(
            r#"
title: Test
description: A fine description
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::MissingDescription));
    }

    #[test]
    fn missing_author_info() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::MissingAuthor));
        let ma = w
            .iter()
            .find(|w| w.rule == LintRule::MissingAuthor)
            .unwrap();
        assert_eq!(ma.severity, Severity::Info);
    }

    #[test]
    fn has_author_no_info() {
        let w = lint(
            r#"
title: Test
author: tester
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::MissingAuthor));
    }

    #[test]
    fn fix_invalid_status() {
        let w = lint(
            r#"
title: Test
status: expreimental
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#,
        );
        let fix = find_fix(&w, LintRule::InvalidStatus).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: replace 'expreimental' with 'experimental'
        disposition: Safe
        patch[0]: ReplaceValue /status -> experimental
        ");
    }

    #[test]
    fn fix_invalid_level() {
        let w = lint(
            r#"
title: Test
level: hgih
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#,
        );
        let fix = find_fix(&w, LintRule::InvalidLevel).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: replace 'hgih' with 'high'
        disposition: Safe
        patch[0]: ReplaceValue /level -> high
        ");
    }

    #[test]
    fn fix_non_lowercase_key() {
        let w = lint(
            r#"
title: Test
Status: test
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#,
        );
        let fix = find_fix(&w, LintRule::NonLowercaseKey).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: rename 'Status' to 'status'
        disposition: Safe
        patch[0]: ReplaceKey /Status -> status
        ");
    }

    #[test]
    fn no_fix_for_far_invalid_status() {
        let w = lint(
            r#"
title: Test
status: totallyinvalidxyz
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidStatus));
        assert!(
            find_fix(&w, LintRule::InvalidStatus).is_none(),
            "no fix when edit distance is too large"
        );
    }
}
