//! Integration tests for the lint subcommand.

mod common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

const LINT_VALID_RULE: &str = r#"
title: Valid Rule
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
status: test
description: A valid detection rule for testing
author: tester
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1059
date: '2025-01-15'
modified: '2025-06-01'
"#;

const LINT_INVALID_LEVEL: &str = r#"
title: Bad Level
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: important
"#;

const LINT_INVALID_STATUS: &str = r#"
title: Bad Status
status: invalid_status
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;

const LINT_INVALID_DATE: &str = r#"
title: Bad Date
date: 'Jan 2025'
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;

const LINT_INVALID_TAGS: &str = r#"
title: Bad Tags
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
tags:
    - 'Invalid Tag'
    - attack.execution
    - attack.execution
"#;

const LINT_MISSING_DETECTION: &str = r#"
title: No Detection
logsource:
    category: test
"#;

const LINT_DEPRECATED_NO_RELATED: &str = r#"
title: Deprecated Rule
status: deprecated
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;

const LINT_VALID_CORRELATION: &str = r#"
title: Brute Force
description: Correlation for brute force detection
author: tester
correlation:
    type: event_count
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 100
level: high
"#;

const LINT_INVALID_CORRELATION: &str = r#"
title: Bad Correlation
correlation:
    type: invalid_type
    rules:
        - some-rule
    timespan: 1hour
"#;

const LINT_VALID_FILTER: &str = r#"
title: Filter Admin
description: Filter for admin users
author: tester
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    selection:
        User|startswith: 'adm_'
    condition: selection
"#;

const LINT_FILTER_WITH_LEVEL: &str = r#"
title: Filter With Level
logsource:
    category: test
level: high
filter:
    rules:
        - some-rule
    selection:
        User: admin
    condition: selection
"#;

const LINT_MULTI_DOC: &str = r#"
action: global
logsource:
    product: windows
---
title: Rule A
detection:
    selection:
        EventID: 1
    condition: selection
level: high
---
title: Rule B
detection:
    selection:
        EventID: 2
    condition: selection
level: invalid_level
"#;

#[test]
fn lint_valid_rule_passes() {
    let rule = temp_file(".yml", LINT_VALID_RULE);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 failed"));
}

#[test]
fn lint_valid_rule_verbose() {
    let rule = temp_file(".yml", LINT_VALID_RULE);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap(), "--verbose"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn lint_invalid_level() {
    let rule = temp_file(".yml", LINT_INVALID_LEVEL);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("invalid_level"))
        .stdout(predicate::str::contains("important"));
}

#[test]
fn lint_invalid_status() {
    let rule = temp_file(".yml", LINT_INVALID_STATUS);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("invalid_status"));
}

#[test]
fn lint_invalid_date() {
    let rule = temp_file(".yml", LINT_INVALID_DATE);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("invalid_date"));
}

#[test]
fn lint_invalid_tags() {
    let rule = temp_file(".yml", LINT_INVALID_TAGS);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .stdout(predicate::str::contains("invalid_tag"))
        .stdout(predicate::str::contains("duplicate_tags"));
}

#[test]
fn lint_missing_detection() {
    let rule = temp_file(".yml", LINT_MISSING_DETECTION);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("missing_detection"));
}

#[test]
fn lint_deprecated_without_related() {
    let rule = temp_file(".yml", LINT_DEPRECATED_NO_RELATED);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .stdout(predicate::str::contains("deprecated_without_related"));
}

#[test]
fn lint_valid_correlation() {
    let rule = temp_file(".yml", LINT_VALID_CORRELATION);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 failed"));
}

#[test]
fn lint_invalid_correlation() {
    let rule = temp_file(".yml", LINT_INVALID_CORRELATION);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("invalid_correlation_type"))
        .stdout(predicate::str::contains("invalid_timespan_format"));
}

#[test]
fn lint_valid_filter() {
    let rule = temp_file(".yml", LINT_VALID_FILTER);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 failed"));
}

#[test]
fn lint_filter_has_level() {
    let rule = temp_file(".yml", LINT_FILTER_WITH_LEVEL);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .stdout(predicate::str::contains("filter_has_level"));
}

#[test]
fn lint_multi_doc_yaml() {
    let rule = temp_file(".yml", LINT_MULTI_DOC);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("invalid_level"))
        .stdout(predicate::str::contains("1 failed"));
}

#[test]
fn lint_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("good.yml"), LINT_VALID_RULE).unwrap();
    std::fs::write(dir.path().join("bad.yml"), LINT_INVALID_LEVEL).unwrap();

    rsigma()
        .args(["lint", dir.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("1 failed"))
        .stdout(predicate::str::contains("invalid_level"));
}

#[test]
fn lint_nonexistent_path() {
    rsigma()
        .args(["lint", "/tmp/nonexistent_rsigma_lint_path.yml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn lint_with_local_schema() {
    let schema_json = r#"{
        "$schema": "https://json-schema.org/draft/2020-12/schema#",
        "type": "object",
        "required": ["title"],
        "properties": {
            "title": { "type": "string", "maxLength": 10 }
        }
    }"#;
    let schema_file = temp_file(".json", schema_json);

    let rule_yaml = r#"
title: This Title Is Way Too Long
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;
    let rule = temp_file(".yml", rule_yaml);

    rsigma()
        .args([
            "lint",
            rule.path().to_str().unwrap(),
            "--schema",
            schema_file.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("schema:"));
}

// =========================================================================
// lint --fix
// =========================================================================

#[test]
fn lint_fix_corrects_invalid_status() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rule.yml");
    std::fs::write(
        &path,
        r#"title: Test
status: expreimental
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#,
    )
    .unwrap();

    rsigma()
        .args(["lint", path.to_str().unwrap(), "--fix"])
        .assert()
        .stdout(predicate::str::contains("Applied"));

    let fixed = std::fs::read_to_string(&path).unwrap();
    assert!(
        fixed.contains("status: experimental"),
        "file should have corrected status, got:\n{fixed}"
    );
    assert!(!fixed.contains("expreimental"), "old value should be gone");
}

#[test]
fn lint_fix_renames_uppercase_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rule.yml");
    std::fs::write(
        &path,
        r#"title: Test
Status: test
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#,
    )
    .unwrap();

    rsigma()
        .args(["lint", path.to_str().unwrap(), "--fix"])
        .assert()
        .stdout(predicate::str::contains("Applied"));

    let fixed = std::fs::read_to_string(&path).unwrap();
    assert!(
        fixed.contains("status: test"),
        "key should be lowercased, got:\n{fixed}"
    );
}

#[test]
fn lint_fix_removes_duplicate_tag() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rule.yml");
    std::fs::write(
        &path,
        r#"title: Test
status: test
tags:
    - attack.execution
    - attack.execution
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#,
    )
    .unwrap();

    rsigma()
        .args(["lint", path.to_str().unwrap(), "--fix"])
        .assert()
        .stdout(predicate::str::contains("Applied"));

    let fixed = std::fs::read_to_string(&path).unwrap();
    let count = fixed.matches("attack.execution").count();
    assert_eq!(count, 1, "duplicate tag should be removed, got:\n{fixed}");
}

#[test]
fn lint_fix_no_changes_on_clean_rule() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rule.yml");
    let original = r#"title: Test
status: test
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#;
    std::fs::write(&path, original).unwrap();

    rsigma()
        .args(["lint", path.to_str().unwrap(), "--fix"])
        .assert()
        .success();

    let after = std::fs::read_to_string(&path).unwrap();
    assert_eq!(original, after, "clean file should not be modified");
}

#[test]
fn lint_fix_multiple_issues() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rule.yml");
    std::fs::write(
        &path,
        r#"title: Test
status: expreimental
tags:
    - attack.execution
    - attack.execution
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#,
    )
    .unwrap();

    rsigma()
        .args(["lint", path.to_str().unwrap(), "--fix"])
        .assert()
        .stdout(predicate::str::contains("Applied"));

    let fixed = std::fs::read_to_string(&path).unwrap();
    assert!(
        fixed.contains("status: experimental"),
        "status should be fixed"
    );
    assert_eq!(
        fixed.matches("attack.execution").count(),
        1,
        "duplicate tag should be removed"
    );
}
