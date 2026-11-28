//! Directory inputs without `--rules-dir`: links that loop load each rule
//! once, and links out of the directory are skipped unless the server follows
//! external links. With a root, any symlink in a directory input is refused
//! (see `confinement_tests`).

use std::os::unix::fs::symlink;

use rsigma_parser::LintConfig;
use tempfile::TempDir;

use super::RsigmaMcp;
use super::shared::SourceInput;
use super::validate_rules::{FailLevel, ValidateInput};
use crate::tools::{VALID_RULE, block_on};

const SECRET: &str = "TOPSECRET-CONTENT-6b0e";

/// A rules directory with a link back to itself and a link to a directory
/// outside it that holds a rule and a secret.
fn tree() -> (TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(rules.join("sub")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(rules.join("rule.yml"), VALID_RULE).unwrap();
    std::fs::write(
        outside.join("other.yml"),
        VALID_RULE.replace("title: ", "title: Other "),
    )
    .unwrap();
    std::fs::write(outside.join("secret.yml"), format!("title: [{SECRET}\n")).unwrap();
    symlink(&rules, rules.join("sub/loop")).unwrap();
    symlink(&outside, rules.join("vendor")).unwrap();
    let path = rules.display().to_string();
    (dir, path)
}

fn validate(server: &RsigmaMcp, path: &str) -> serde_json::Value {
    block_on(server.run_validate_rules(ValidateInput {
        yaml: None,
        path: Some(path.to_string()),
        ruleset: None,
        pipelines: vec![],
        resolve_sources: false,
        fail_level: FailLevel::Error,
    }))
    .unwrap()
}

#[test]
fn unconfined_directory_skips_links_out_of_it() {
    let (_dir, path) = tree();
    let server = RsigmaMcp::new(None, LintConfig::default(), false);
    let value = validate(&server, &path);
    assert_eq!(value["summary"]["detection_rules"], 1, "{value}");
    let warnings = value["parse_warnings"].to_string();
    assert!(warnings.contains("vendor"), "{warnings}");
    assert!(!value.to_string().contains(SECRET), "{value}");

    let lint = server
        .run_lint_rules(SourceInput {
            yaml: None,
            path: Some(path.clone()),
        })
        .unwrap();
    assert!(lint.to_string().contains("skipped_path"), "{lint}");
    assert!(!lint.to_string().contains(SECRET), "{lint}");
}

#[test]
fn following_external_links_loads_each_rule_once() {
    let (_dir, path) = tree();
    let server =
        RsigmaMcp::new(None, LintConfig::default(), false).with_follow_external_links(true);
    let value = validate(&server, &path);
    assert_eq!(value["summary"]["detection_rules"], 2, "{value}");
}
