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
    let conflict = draft(&[
        "rule",
        "draft",
        "--from-stix",
        path.to_str().unwrap(),
        "--event",
        "{}",
    ]);
    assert_eq!(conflict.status.code(), Some(3));
    assert!(
        String::from_utf8(conflict.stderr)
            .unwrap()
            .contains("cannot be combined with --event")
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
