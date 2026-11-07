//! `--rules-dir` confinement across every path-accepting tool.

use std::collections::HashMap;

use rsigma_parser::LintConfig;
use tempfile::TempDir;

use super::RsigmaMcp;
use super::convert_rules::ConvertInput;
use super::evaluate_events::EvaluateInput;
use super::fix_rules::FixInput;
use super::format_rules::FormatInput;
use super::list_fields::FieldsInput;
use super::resolve_pipeline::ResolvePipelineInput;
use super::shared::SourceInput;
use super::validate_rules::ValidateInput;
use crate::tools::{VALID_RULE, block_on};

const PIPELINE: &str = "name: p\ntransformations: []\n";
const ENRICHERS: &str = "enrichers: []\n";
const EVENTS: &str = "{\"CommandLine\": \"cmd /c whoami\"}\n";

/// A rules root and a sibling directory outside it, both holding the same
/// fixtures, plus a server confined to the root.
struct Fixture {
    root: TempDir,
    outside: TempDir,
    server: RsigmaMcp,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        for dir in [root.path(), outside.path()] {
            std::fs::write(dir.join("rule.yml"), VALID_RULE).unwrap();
            std::fs::write(dir.join("pipeline.yml"), PIPELINE).unwrap();
            std::fs::write(dir.join("enrichers.yml"), ENRICHERS).unwrap();
            std::fs::write(dir.join("events.ndjson"), EVENTS).unwrap();
        }
        let server = RsigmaMcp::new(
            Some(root.path().to_path_buf()),
            LintConfig::default(),
            false,
        );
        Self {
            root,
            outside,
            server,
        }
    }

    /// Paths to `file` that leave the root: absolute, `../` traversal, and a
    /// missing file (which must fail the same way, so it cannot be probed).
    fn escaping(&self, file: &str) -> Vec<String> {
        let outside_name = self.outside.path().file_name().unwrap().to_string_lossy();
        vec![
            self.outside.path().join(file).display().to_string(),
            format!("../{outside_name}/{file}"),
            self.outside
                .path()
                .join("missing.yml")
                .display()
                .to_string(),
        ]
    }
}

fn source(path: &str) -> SourceInput {
    SourceInput {
        yaml: None,
        path: Some(path.to_string()),
    }
}

fn evaluate() -> EvaluateInput {
    EvaluateInput {
        yaml: Some(VALID_RULE.to_string()),
        path: None,
        events: None,
        events_path: Some("events.ndjson".to_string()),
        pipelines: vec![],
        match_detail: None,
        timestamp_fields: vec![],
        emit_detections: false,
        enrichers: None,
        enrichers_path: None,
    }
}

fn assert_escapes<T: std::fmt::Debug>(tool: &str, path: &str, result: Result<T, rmcp::ErrorData>) {
    let err = result.expect_err(&format!("{tool} accepted '{path}'"));
    assert!(
        format!("{err:?}").contains("escapes the configured --rules-dir"),
        "{tool} with '{path}': {err:?}"
    );
}

#[test]
fn every_path_input_is_confined_to_rules_dir() {
    let fx = Fixture::new();
    let s = &fx.server;

    for p in fx.escaping("rule.yml") {
        assert_escapes("parse_rule", &p, s.run_parse_rule(source(&p)));
        assert_escapes("lint_rules", &p, s.run_lint_rules(source(&p)));
        assert_escapes("author_ads", &p, s.run_author_ads(source(&p)));
        assert_escapes(
            "fix_rules",
            &p,
            s.run_fix_rules(FixInput {
                yaml: None,
                path: Some(p.clone()),
                lint_rules: vec![],
                write: false,
            }),
        );
        assert_escapes(
            "format_rules",
            &p,
            s.run_format_rules(FormatInput {
                yaml: None,
                path: Some(p.clone()),
                write: false,
            }),
        );
        assert_escapes(
            "list_fields",
            &p,
            s.run_list_fields(FieldsInput {
                yaml: None,
                path: Some(p.clone()),
                pipelines: vec![],
                include_filters: false,
            }),
        );
        assert_escapes(
            "validate_rules",
            &p,
            block_on(s.run_validate_rules(ValidateInput {
                yaml: None,
                path: Some(p.clone()),
                pipelines: vec![],
                resolve_sources: false,
                fail_level: Default::default(),
            })),
        );
        assert_escapes(
            "convert_rules",
            &p,
            s.run_convert_rules(ConvertInput {
                yaml: None,
                path: Some(p.clone()),
                target: "postgres".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            }),
        );
        let mut input = evaluate();
        input.yaml = None;
        input.path = Some(p.clone());
        assert_escapes(
            "evaluate_events path",
            &p,
            block_on(s.run_evaluate_events(input)),
        );
    }

    for p in fx.escaping("events.ndjson") {
        let mut input = evaluate();
        input.events_path = Some(p.clone());
        assert_escapes(
            "evaluate_events events_path",
            &p,
            block_on(s.run_evaluate_events(input)),
        );
    }

    for p in fx.escaping("enrichers.yml") {
        let mut input = evaluate();
        input.enrichers_path = Some(p.clone());
        assert_escapes(
            "evaluate_events enrichers_path",
            &p,
            block_on(s.run_evaluate_events(input)),
        );
    }

    for p in fx.escaping("pipeline.yml") {
        assert_escapes(
            "resolve_pipeline",
            &p,
            block_on(s.run_resolve_pipeline(ResolvePipelineInput {
                pipeline: p.clone(),
                resolve_sources: false,
            })),
        );
        assert_escapes(
            "list_fields pipelines",
            &p,
            s.run_list_fields(FieldsInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                pipelines: vec![p.clone()],
                include_filters: false,
            }),
        );
    }
}

#[test]
fn paths_inside_rules_dir_still_resolve() {
    let fx = Fixture::new();
    let s = &fx.server;

    assert!(s.run_parse_rule(source("rule.yml")).is_ok());
    assert!(s.run_lint_rules(source("rule.yml")).is_ok());
    let absolute = fx.root.path().join("rule.yml").display().to_string();
    assert!(s.run_parse_rule(source(&absolute)).is_ok());

    let mut input = evaluate();
    input.pipelines = vec!["pipeline.yml".to_string()];
    input.enrichers_path = Some("enrichers.yml".to_string());
    let v = block_on(s.run_evaluate_events(input)).unwrap();
    assert_eq!(v["summary"]["detection_matches"], 1);
}

#[cfg(unix)]
#[test]
fn format_rules_write_does_not_follow_symlink_out_of_rules_dir() {
    use std::os::unix::fs::symlink;

    let fx = Fixture::new();
    let target = fx.outside.path().join("unformatted.yml");
    let original =
        "title: T\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n";
    std::fs::write(&target, original).unwrap();
    symlink(&target, fx.root.path().join("link.yml")).unwrap();

    let result = fx.server.run_format_rules(FormatInput {
        yaml: None,
        path: Some("link.yml".to_string()),
        write: true,
    });
    assert_escapes("format_rules write", "link.yml", result);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn fix_rules_write_does_not_follow_symlink_out_of_rules_dir() {
    use std::os::unix::fs::symlink;

    let fx = Fixture::new();
    let target = fx.outside.path().join("fixable.yml");
    let original = "title: T\nStatus: test\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n";
    std::fs::write(&target, original).unwrap();
    symlink(&target, fx.root.path().join("link.yml")).unwrap();

    let result = fx.server.run_fix_rules(FixInput {
        yaml: None,
        path: Some("link.yml".to_string()),
        lint_rules: vec![],
        write: true,
    });
    assert_escapes("fix_rules write", "link.yml", result);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn directory_inputs_reject_nested_symlinks() {
    use std::os::unix::fs::symlink;

    let fx = Fixture::new();
    let nested = fx.root.path().join("rules").join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    symlink(
        fx.outside.path().join("rule.yml"),
        nested.join("escape.yml"),
    )
    .unwrap();

    let assert_symlink = |tool: &str, result: Result<serde_json::Value, rmcp::ErrorData>| {
        let err = result.expect_err(tool);
        assert!(format!("{err:?}").contains("symlink"), "{tool}: {err:?}");
    };
    assert_symlink("lint_rules", fx.server.run_lint_rules(source("rules")));
    assert_symlink("author_ads", fx.server.run_author_ads(source("rules")));
    assert_symlink(
        "validate_rules",
        block_on(fx.server.run_validate_rules(ValidateInput {
            yaml: None,
            path: Some("rules".to_string()),
            pipelines: vec![],
            resolve_sources: false,
            fail_level: Default::default(),
        })),
    );
}

#[test]
fn no_rules_dir_leaves_paths_unconfined() {
    let outside = tempfile::tempdir().unwrap();
    let rule = outside.path().join("rule.yml");
    std::fs::write(&rule, VALID_RULE).unwrap();
    let server = crate::tools::handler();
    assert!(
        server
            .run_parse_rule(source(&rule.display().to_string()))
            .is_ok()
    );
}
