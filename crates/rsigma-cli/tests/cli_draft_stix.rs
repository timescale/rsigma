//! `rule draft --from-stix`: golden rules, the report, and the feature gate.

mod common;

#[cfg(feature = "stix-draft")]
use std::path::PathBuf;

#[cfg(feature = "stix-draft")]
use common::{assert_golden, assert_json_golden, rsigma, temp_file};

#[cfg(feature = "stix-draft")]
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/draft-stix")
        .join(name)
}

#[cfg(feature = "stix-draft")]
fn draft(args: &[&str]) -> std::process::Output {
    rsigma().args(args).output().expect("run rule draft")
}

#[cfg(feature = "stix-draft")]
#[test]
fn one_indicator_matches_the_golden_rule() {
    let path = fixture("one-ip.json");
    let out = draft(&[
        "rule",
        "draft",
        "--from-stix",
        path.to_str().unwrap(),
        "--date",
        "2026-06-01",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_golden(
        "draft-stix/one-ip.yml",
        &String::from_utf8(out.stdout).unwrap(),
    );
}

#[cfg(feature = "stix-draft")]
#[test]
fn one_indicator_report_lists_the_rule_and_the_value() {
    let path = fixture("one-ip.json");
    let out = draft(&[
        "rule",
        "draft",
        "--from-stix",
        path.to_str().unwrap(),
        "--date",
        "2026-06-01",
        "--emit",
        "report",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_json_golden(
        "draft-stix/one-ip.report.json",
        &String::from_utf8(out.stdout).unwrap(),
    );
}

#[cfg(feature = "stix-draft")]
#[test]
fn a_mixed_bundle_emits_one_rule_per_logsource() {
    let path = fixture("mixed.json");
    let out = draft(&[
        "rule",
        "draft",
        "--from-stix",
        path.to_str().unwrap(),
        "--date",
        "2026-06-01",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let yaml = String::from_utf8(out.stdout).unwrap();
    assert_golden("draft-stix/mixed.yml", &yaml);
    for document in yaml.split("\n---\n") {
        let file = temp_file(".yml", document);
        let lint = rsigma()
            .args(["rule", "lint", file.path().to_str().unwrap()])
            .output()
            .expect("lint");
        assert!(
            lint.status.success(),
            "lint failed: {}",
            String::from_utf8_lossy(&lint.stderr)
        );
    }
}

#[cfg(feature = "stix-draft")]
#[test]
fn cidr_and_hashes_use_their_modifiers() {
    for (fixture_name, golden) in [
        ("cidr.json", "draft-stix/cidr.yml"),
        ("hashes.json", "draft-stix/hashes.yml"),
    ] {
        let path = fixture(fixture_name);
        let out = draft(&[
            "rule",
            "draft",
            "--from-stix",
            path.to_str().unwrap(),
            "--date",
            "2026-06-01",
        ]);
        assert!(
            out.status.success(),
            "{fixture_name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_golden(golden, &String::from_utf8(out.stdout).unwrap());
    }
}

#[cfg(feature = "stix-draft")]
#[test]
fn observable_filter_keeps_only_the_requested_kind() {
    let path = fixture("mixed.json");
    let out = draft(&[
        "rule",
        "draft",
        "--from-stix",
        path.to_str().unwrap(),
        "--date",
        "2026-06-01",
        "--observable",
        "domain",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_golden(
        "draft-stix/domain.yml",
        &String::from_utf8(out.stdout).unwrap(),
    );
}

#[cfg(feature = "stix-draft")]
#[test]
fn include_expired_keeps_both_windows_and_still_drops_revoked() {
    let path = fixture("include-expired.json");
    let out = draft(&[
        "rule",
        "draft",
        "--from-stix",
        path.to_str().unwrap(),
        "--date",
        "2026-06-01",
        "--include-expired",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let yaml = String::from_utf8(out.stdout).unwrap();
    assert_golden("draft-stix/include-expired.yml", &yaml);
    assert!(!yaml.contains("198.51.100.12"));
}

#[cfg(feature = "stix-draft")]
#[test]
fn stdin_matches_the_indicator_golden() {
    let raw = std::fs::read_to_string(fixture("one-ip.json")).unwrap();
    let out = rsigma()
        .args(["rule", "draft", "--from-stix", "-", "--date", "2026-06-01"])
        .write_stdin(raw)
        .output()
        .expect("run draft");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_golden(
        "draft-stix/one-ip.yml",
        &String::from_utf8(out.stdout).unwrap(),
    );
}

#[cfg(feature = "stix-draft")]
#[test]
fn nothing_draftable_exits_1_and_reports_every_skip() {
    let path = fixture("all-skipped.json");
    let out = draft(&[
        "rule",
        "draft",
        "--from-stix",
        path.to_str().unwrap(),
        "--emit",
        "report",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("no draftable indicators"), "{stderr}");
    assert_json_golden(
        "draft-stix/all-skipped.report.json",
        &String::from_utf8(out.stdout).unwrap(),
    );
}

#[cfg(feature = "stix-draft")]
#[test]
fn unknown_observable_and_conflicting_flags_exit_3() {
    let unknown = draft(&[
        "rule",
        "draft",
        "--from-stix",
        "-",
        "--observable",
        "hostname",
    ]);
    assert_eq!(unknown.status.code(), Some(3));
    let stderr = String::from_utf8(unknown.stderr).unwrap();
    assert!(stderr.contains("unknown observable hostname"), "{stderr}");
    assert!(stderr.contains("ipv4"), "{stderr}");

    let path = fixture("one-ip.json");
    let path = path.to_str().unwrap();
    let cases: &[(&[&str], &str)] = &[
        (&["--event", "{}"], "--event"),
        (&["--groups", "@groups.jsonl"], "--groups"),
        (&["--negative", "@neg.jsonl"], "--negative"),
        (&["--baseline", "@base.jsonl"], "--baseline"),
        (&["--group-by", "Image"], "--group-by"),
        (&["--correlation-type", "temporal"], "--correlation-type"),
        (&["--min-groups", "2"], "--min-groups"),
        (&["--window-margin", "2.0"], "--window-margin"),
        (&["--max-fields", "2"], "--max-fields"),
        (&["--min-prevalence", "0.5"], "--min-prevalence"),
        (&["--include-field", "Image"], "--include-field"),
        (&["--exclude-field", "Image"], "--exclude-field"),
        (&["--skip-baseline-eval"], "--skip-baseline-eval"),
    ];
    for (extra, flag) in cases {
        let mut args = vec!["rule", "draft", "--from-stix", path];
        args.extend_from_slice(extra);
        let conflict = draft(&args);
        assert_eq!(
            conflict.status.code(),
            Some(3),
            "{flag} {}",
            String::from_utf8_lossy(&conflict.stderr)
        );
        let stderr = String::from_utf8(conflict.stderr).unwrap();
        let expected = format!("cannot be combined with {flag}");
        assert!(stderr.contains(&expected), "{flag}: {stderr}");
    }
}

#[cfg(feature = "stix-draft")]
#[test]
fn a_url_question_mark_stays_literal() {
    let path = fixture("url.json");
    let out = draft(&[
        "rule",
        "draft",
        "--from-stix",
        path.to_str().unwrap(),
        "--date",
        "2026-06-01",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_golden(
        "draft-stix/url.yml",
        &String::from_utf8(out.stdout).unwrap(),
    );
}

#[cfg(feature = "stix-draft")]
#[test]
fn a_registry_key_matches_a_sysmon_event() {
    let path = fixture("registry.json");
    let drafted = draft(&[
        "rule",
        "draft",
        "--from-stix",
        path.to_str().unwrap(),
        "--date",
        "2026-06-01",
    ]);
    assert!(
        drafted.status.success(),
        "{}",
        String::from_utf8_lossy(&drafted.stderr)
    );
    let yaml = String::from_utf8(drafted.stdout).unwrap();
    assert_golden("draft-stix/registry.yml", &yaml);
    let rule = temp_file(".yml", &yaml);

    let hit = r#"{"EventID":13,"TargetObject":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil"}"#;
    let long = r#"{"EventID":13,"TargetObject":"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil"}"#;
    let miss = r#"{"EventID":13,"TargetObject":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\evil"}"#;
    let exact = r#"{"EventID":13,"TargetObject":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"}"#;
    for event in [hit, long] {
        let out = rsigma()
            .args([
                "engine",
                "eval",
                "--rules",
                rule.path().to_str().unwrap(),
                "--event",
                event,
            ])
            .output()
            .expect("engine eval");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert!(stdout.contains("Run key"), "{event}\n{stdout}");
    }
    for event in [miss, exact] {
        let out = rsigma()
            .args([
                "engine",
                "eval",
                "--rules",
                rule.path().to_str().unwrap(),
                "--event",
                event,
            ])
            .output()
            .expect("engine eval");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains("No matches"), "{event}\n{stderr}");
    }
}

#[cfg(feature = "stix-draft")]
#[test]
fn invalid_date_exits_3_on_the_stix_path() {
    let path = fixture("one-ip.json");
    let out = draft(&[
        "rule",
        "draft",
        "--from-stix",
        path.to_str().unwrap(),
        "--date",
        "not a date",
    ]);
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("YYYY-MM-DD"), "{stderr}");
}

#[cfg(feature = "stix-draft")]
#[test]
fn observable_and_include_expired_require_from_stix() {
    let cases: &[&[&str]] = &[
        &["rule", "draft", "--observable", "ipv4"],
        &["rule", "draft", "--include-expired"],
        &["rule", "draft", "--event", "{}", "--observable", "ipv4"],
        &["rule", "draft", "--event", "{}", "--include-expired"],
    ];
    for args in cases {
        let out = draft(args);
        assert!(
            !out.status.success(),
            "{args:?} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(
            stderr.contains("from-stix") || stderr.contains("from_stix"),
            "{args:?}: {stderr}"
        );
    }
}

#[cfg(feature = "stix-draft")]
#[test]
fn help_lists_from_stix() {
    let out = draft(&["rule", "draft", "--help"]);
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap();
    assert!(help.contains("--from-stix"), "{help}");
    assert!(help.contains("--include-expired"), "{help}");
}

#[cfg(not(feature = "stix-draft"))]
#[test]
fn from_stix_is_absent_without_the_feature() {
    let help = common::rsigma()
        .args(["rule", "draft", "--help"])
        .output()
        .expect("help");
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(!text.contains("--from-stix"), "{text}");

    let denied = common::rsigma()
        .args(["rule", "draft", "--from-stix", "bundle.json"])
        .output()
        .expect("denied");
    assert!(!denied.status.success());
}
