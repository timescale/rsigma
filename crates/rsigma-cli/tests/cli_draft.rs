//! Integration tests for `rsigma rule draft`: the golden draft YAML, input
//! modes (inline, @file, stdin), the baseline contrast, the report emit mode,
//! and the round-trip of the emitted rule back through `rule lint` and
//! `engine eval`. Profiling, scoring, and inference logic is unit-tested in
//! rsigma-eval's rule_draft module; these tests cover the CLI surface only.

mod common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

const DRAFT_GOLDEN: &str = include_str!("golden/draft_rule.yaml");

/// Sysmon process-creation exemplars: constant Channel/EventID, patterned
/// Image/CommandLine, volatile UtcTime/ProcessGuid/ProcessId.
const SYSMON_EXEMPLARS: &str = concat!(
    r#"{"Channel":"Microsoft-Windows-Sysmon/Operational","EventID":1,"UtcTime":"2026-07-01T10:00:01Z","ProcessGuid":"6bde842e-a2f4-441e-b027-3aa79b1b2fc1","ProcessId":4211,"Image":"C:\\Tools\\whoami.exe","CommandLine":"whoami /all","User":"CORP\\alice"}"#,
    "\n",
    r#"{"Channel":"Microsoft-Windows-Sysmon/Operational","EventID":1,"UtcTime":"2026-07-01T10:02:07Z","ProcessGuid":"6bde842e-a2f4-441e-b027-3aa79b1b2fc2","ProcessId":9922,"Image":"C:\\Windows\\System32\\whoami.exe","CommandLine":"whoami /priv","User":"CORP\\bob"}"#,
    "\n",
    r#"{"Channel":"Microsoft-Windows-Sysmon/Operational","EventID":1,"UtcTime":"2026-07-01T10:05:44Z","ProcessGuid":"6bde842e-a2f4-441e-b027-3aa79b1b2fc3","ProcessId":1044,"Image":"D:\\stage\\whoami.exe","CommandLine":"whoami","User":"CORP\\carol"}"#,
    "\n",
);

const CORRELATION_GROUPS: &str = concat!(
    r#"{"group":"g1","offset":"0s","event":{"kind":"reset","user":"alice","factor":"totp","reset_reason":"recovery"}}"#,
    "\n",
    r#"{"group":"g1","offset":"20s","event":{"kind":"session","user":"alice","new_asn":true,"asn":64512,"session_type":"web"}}"#,
    "\n",
    r#"{"group":"g2","offset":"0s","event":{"kind":"reset","user":"bob","factor":"totp","reset_reason":"recovery"}}"#,
    "\n",
    r#"{"group":"g2","offset":"25s","event":{"kind":"session","user":"bob","new_asn":true,"asn":64512,"session_type":"web"}}"#,
    "\n",
    r#"{"group":"g3","offset":"0s","event":{"kind":"reset","user":"carol","factor":"totp","reset_reason":"recovery"}}"#,
    "\n",
    r#"{"group":"g3","offset":"30s","event":{"kind":"session","user":"carol","new_asn":true,"asn":64512,"session_type":"web"}}"#,
    "\n",
);

/// Replace the volatile `id:` (random UUIDv4) and `date:` (today) lines with
/// placeholders so the draft compares byte-for-byte against the golden.
/// Splitting on `lines()` also normalizes CRLF to LF.
fn normalize_draft(s: &str) -> String {
    s.lines()
        .map(|line| {
            if line.starts_with("id: ") {
                "id: <ID>".to_string()
            } else if line.starts_with("date: ") {
                "date: <DATE>".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn draft_from_stdin_matches_golden() {
    let out = rsigma()
        .args(["rule", "draft"])
        .write_stdin(SYSMON_EXEMPLARS)
        .output()
        .expect("run draft");
    assert!(out.status.success());
    let yaml = String::from_utf8(out.stdout).expect("utf8");
    assert_eq!(
        normalize_draft(&yaml).trim_end(),
        normalize_draft(DRAFT_GOLDEN).trim_end(),
        "draft YAML drifted from golden"
    );
}

#[test]
fn draft_carries_a_fresh_uuid_v4_id() {
    let out = rsigma()
        .args(["rule", "draft"])
        .write_stdin(SYSMON_EXEMPLARS)
        .output()
        .expect("run draft");
    assert!(out.status.success());
    let yaml = String::from_utf8(out.stdout).expect("utf8");
    let id = yaml
        .lines()
        .find_map(|l| l.strip_prefix("id: "))
        .expect("draft must carry an id");
    assert_eq!(id.len(), 36, "UUID shape: {id}");
    assert_eq!(id.as_bytes()[14], b'4', "UUIDv4 version nibble: {id}");
}

#[test]
fn draft_round_trips_through_lint_and_eval() {
    let out = rsigma()
        .args(["rule", "draft"])
        .write_stdin(SYSMON_EXEMPLARS)
        .output()
        .expect("run draft");
    assert!(out.status.success());
    let yaml = String::from_utf8(out.stdout).expect("utf8");
    let rule = temp_file(".yml", &yaml);

    // The draft lints without errors.
    rsigma()
        .args(["rule", "lint", rule.path().to_str().unwrap()])
        .assert()
        .success();

    // And fires on the exemplar it was drafted from.
    rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"Channel":"Microsoft-Windows-Sysmon/Operational","EventID":1,"Image":"C:\\Tools\\whoami.exe","CommandLine":"whoami /all"}"#,
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Draft:"));
}

#[test]
fn baseline_reports_hits_and_rarity() {
    let baseline_lines: String = (0..10)
        .map(|i| {
            format!(
                r#"{{"Channel":"Microsoft-Windows-Sysmon/Operational","EventID":1,"Image":"C:\\Windows\\System32\\svchost.exe","CommandLine":"svchost -k netsvcs {i}","User":"NT AUTHORITY\\SYSTEM"}}"#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let baseline = temp_file(".ndjson", &baseline_lines);

    rsigma()
        .args([
            "rule",
            "draft",
            "--baseline",
            &format!("@{}", baseline.path().display()),
            "--emit",
            "report",
            "--output-format",
            "json",
        ])
        .write_stdin(SYSMON_EXEMPLARS)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"exemplar_matched\": 3"))
        .stdout(predicate::str::contains("\"baseline_total\": 10"))
        .stdout(predicate::str::contains("\"baseline_hits\": 0"));
}

#[test]
fn skip_baseline_eval_omits_hits() {
    let baseline = temp_file(
        ".ndjson",
        r#"{"Channel":"Microsoft-Windows-Sysmon/Operational","EventID":1,"Image":"C:\\x\\svchost.exe","CommandLine":"svchost"}"#,
    );
    rsigma()
        .args([
            "rule",
            "draft",
            "--baseline",
            &format!("@{}", baseline.path().display()),
            "--skip-baseline-eval",
            "--emit",
            "report",
            "--output-format",
            "json",
        ])
        .write_stdin(SYSMON_EXEMPLARS)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"baseline_total\": 1"))
        .stdout(predicate::str::contains("\"baseline_hits\"").not());
}

#[test]
fn inline_exemplar_and_file_exemplars_work() {
    // A single inline exemplar: every field constant, still a valid draft.
    rsigma()
        .args([
            "rule",
            "draft",
            "-e",
            r#"{"vendor":"acme","action":"exfil","dst_port":443}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("vendor: acme"))
        .stdout(predicate::str::contains("condition: selection"));

    // @file NDJSON.
    let file = temp_file(".ndjson", SYSMON_EXEMPLARS);
    rsigma()
        .args([
            "rule",
            "draft",
            "-e",
            &format!("@{}", file.path().display()),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Image|endswith"));
}

#[test]
fn logsource_and_title_overrides_win() {
    rsigma()
        .args([
            "rule",
            "draft",
            "-e",
            r#"{"vendor":"acme","action":"exfil"}"#,
            "--title",
            "Acme Exfiltration",
            "--logsource-product",
            "acme_fw",
            "--logsource-category",
            "firewall",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("title: Acme Exfiltration"))
        .stdout(predicate::str::contains("product: acme_fw"))
        .stdout(predicate::str::contains("category: firewall"));
}

#[test]
fn report_table_lists_volatile_fields_unselected() {
    rsigma()
        .args([
            "rule",
            "draft",
            "--emit",
            "report",
            "--output-format",
            "table",
        ])
        .write_stdin(SYSMON_EXEMPLARS)
        .assert()
        .success()
        .stdout(predicate::str::contains("FIELD"))
        .stdout(predicate::str::contains("volatile"))
        .stdout(predicate::str::contains("# Draft rule"));
}

#[test]
fn unparseable_lines_warn_loudly() {
    let input = format!("not json at all\n{SYSMON_EXEMPLARS}");
    rsigma()
        .args(["rule", "draft"])
        .write_stdin(input)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "1 exemplar line(s) failed to parse",
        ));
}

#[test]
fn forced_field_absent_from_exemplars_names_the_culprit() {
    let input = concat!(
        r#"{"vendor":"acme","action":"alert","extra":"x"}"#,
        "\n",
        r#"{"vendor":"acme","action":"alert"}"#,
        "\n",
    );
    rsigma()
        .args([
            "rule",
            "draft",
            "--include-field",
            "extra",
            "--min-prevalence",
            "0.4",
        ])
        .write_stdin(input)
        .assert()
        .failure()
        .stderr(predicate::str::contains("forced field(s)"))
        .stderr(predicate::str::contains("extra"));
}

#[test]
fn missing_exemplar_file_fails() {
    rsigma()
        .args(["rule", "draft", "-e", "@/nonexistent/exemplars.ndjson"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn all_volatile_exemplars_fail_with_guidance() {
    rsigma()
        .args([
            "rule",
            "draft",
            "-e",
            r#"{"UtcTime":"2026-07-03T10:00:00Z","ProcessGuid":"6bde842e-a2f4-441e-b027-3aa79b1b2fc1"}"#,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no candidate fields"));
}

#[test]
fn grouped_draft_emits_reparseable_temporal_collection() {
    let groups = temp_file(".ndjson", CORRELATION_GROUPS);
    let output = rsigma()
        .args([
            "rule",
            "draft",
            "--groups",
            &format!("@{}", groups.path().display()),
        ])
        .output()
        .expect("run grouped draft");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    assert!(yaml.contains("type: temporal_ordered"));
    assert!(yaml.contains("rsigma.exemplars:"));
    let rule = temp_file(".yml", &yaml);
    rsigma()
        .args(["rule", "lint", rule.path().to_str().unwrap()])
        .assert()
        .success();
    rsigma()
        .args(["rule", "test", "--rules", rule.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn grouped_directory_uses_file_stems_as_group_ids() {
    let directory = tempfile::tempdir().unwrap();
    for (id, user) in [("g1", "alice"), ("g2", "bob"), ("g3", "carol")] {
        let contents = format!(
            "{{\"offset\":\"0s\",\"event\":{{\"kind\":\"reset\",\"user\":\"{user}\",\"factor\":\"totp\",\"reset_reason\":\"recovery\"}}}}\n{{\"offset\":\"20s\",\"event\":{{\"kind\":\"session\",\"user\":\"{user}\",\"new_asn\":true,\"asn\":64512,\"session_type\":\"web\"}}}}\n"
        );
        std::fs::write(directory.path().join(format!("{id}.ndjson")), contents).unwrap();
    }
    rsigma()
        .args([
            "rule",
            "draft",
            "--groups",
            &format!("@{}", directory.path().display()),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("type: temporal_ordered"));
}

#[test]
fn grouped_draft_reports_malformed_line_context() {
    let groups = temp_file(
        ".ndjson",
        "{\"group\":\"g1\",\"offset\":\"0s\",\"event\":{}}\nnot-json\n",
    );
    rsigma()
        .args([
            "rule",
            "draft",
            "--groups",
            &format!("@{}", groups.path().display()),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(":2: invalid JSON"));
}

#[test]
fn grouped_auto_mode_downgrades_inverted_order() {
    let input = CORRELATION_GROUPS.replace(
        r#"{"group":"g3","offset":"0s","event":{"kind":"reset""#,
        r#"{"group":"g3","offset":"40s","event":{"kind":"reset""#,
    );
    let groups = temp_file(".ndjson", &input);
    rsigma()
        .args([
            "rule",
            "draft",
            "--groups",
            &format!("@{}", groups.path().display()),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("type: temporal\n"));
}
