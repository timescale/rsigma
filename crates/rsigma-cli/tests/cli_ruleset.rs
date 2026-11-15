//! Integration tests for `rsigma ruleset list`, `show`, and `build`.
//!
//! The fixture directory carries a copy of the parser ruleset fixtures plus
//! two config files: `rsigma.yaml` declares a working ruleset and a broken
//! one, and `vendor-only.yaml` declares only the working ruleset.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use common::{assert_golden, assert_json_golden, rsigma_isolated as rsigma};
use predicates::prelude::*;

const W1: &str = "aaaaaaaa-0000-4000-8000-000000000001";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rulesets")
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A writable copy of the fixtures, so a test can edit sources.
fn fixture_copy() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_tree(&fixtures(), dir.path());
    dir
}

fn build_json(dir: &Path, out: &Path, extra: &[&str]) -> serde_json::Value {
    let mut command = rsigma();
    command.current_dir(dir).args([
        "ruleset",
        "build",
        "vendor",
        "--config",
        "vendor-only.yaml",
        "-o",
        out.to_str().unwrap(),
        "--output-format",
        "json",
    ]);
    command.args(extra);
    let output = command.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).unwrap()
}

fn walk(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    fn visit(root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &path, files);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_path_buf();
                files.insert(rel, fs::read(&path).unwrap());
            }
        }
    }
    visit(root, root, &mut files);
    files
}

fn assert_build_golden(out: &Path) {
    let files = walk(out);
    let golden_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/ruleset_build");
    let update = std::env::var_os("RSIGMA_UPDATE_GOLDEN").is_some();
    if update {
        let _ = fs::remove_dir_all(&golden_root);
    }
    for (rel, contents) in &files {
        let golden = golden_root.join(rel);
        if rel == Path::new("ruleset.lock.json") {
            let mut actual: serde_json::Value = serde_json::from_slice(contents).unwrap();
            actual["generator"] = serde_json::json!("rsigma <version>");
            if update {
                fs::create_dir_all(golden.parent().unwrap()).unwrap();
                let mut text = serde_json::to_string_pretty(&actual).unwrap();
                text.push('\n');
                fs::write(&golden, text).unwrap();
                continue;
            }
            let expected: serde_json::Value =
                serde_json::from_slice(&fs::read(&golden).unwrap()).unwrap();
            assert_eq!(
                actual,
                expected,
                "golden mismatch for {}; rerun with RSIGMA_UPDATE_GOLDEN=1",
                golden.display()
            );
            continue;
        }
        if update {
            fs::create_dir_all(golden.parent().unwrap()).unwrap();
            fs::write(&golden, contents).unwrap();
            continue;
        }
        let expected = fs::read(&golden)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", golden.display()));
        assert_eq!(
            contents,
            &expected,
            "golden mismatch for {}; rerun with RSIGMA_UPDATE_GOLDEN=1",
            golden.display()
        );
    }
    if !update {
        let golden_files = walk(&golden_root);
        assert_eq!(
            files.keys().collect::<Vec<_>>(),
            golden_files.keys().collect::<Vec<_>>(),
            "golden tree has a different file set"
        );
    }
}

#[test]
fn list_table_reports_a_working_ruleset() {
    rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "list",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("vendor"))
        .stdout(predicate::str::contains("sysmon"))
        .stdout(predicate::str::contains("ok"));
}

#[test]
fn list_json_reports_counts() {
    let output = rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "list",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let envelope: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let rulesets = envelope["rulesets"].as_array().unwrap();
    assert_eq!(rulesets.len(), 1);
    assert_eq!(rulesets[0]["name"], serde_json::json!("vendor"));
    assert_eq!(rulesets[0]["detection"], serde_json::json!(4));
    assert_eq!(rulesets[0]["correlation"], serde_json::json!(2));
    assert_eq!(rulesets[0]["filter"], serde_json::json!(1));
    assert_eq!(rulesets[0]["overlays"], serde_json::json!(3));
    assert_eq!(rulesets[0]["pipelines"], serde_json::json!("sysmon"));
    assert_eq!(rulesets[0]["status"], serde_json::json!("ok"));
    assert_eq!(rulesets[0]["error"], serde_json::json!(""));
}

#[test]
fn list_reports_source_parse_errors() {
    let dir = tempfile::tempdir().unwrap();
    copy_tree(&fixtures(), dir.path());
    fs::write(dir.path().join("vendor/broken.yml"), "title: [unclosed\n").unwrap();
    let output = rsigma()
        .current_dir(dir.path())
        .args([
            "ruleset",
            "list",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let envelope: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let ruleset = &envelope["rulesets"][0];
    assert_eq!(ruleset["status"], serde_json::json!("ok"));
    assert_eq!(
        ruleset["error"],
        serde_json::json!("1 source parse error(s)")
    );
}

#[test]
fn show_all_golden_table() {
    let output = rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--all",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_golden("ruleset_show_all.txt", &String::from_utf8(output).unwrap());
}

#[test]
fn show_all_golden_json() {
    let output = rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--all",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_json_golden("ruleset_show.json", &String::from_utf8(output).unwrap());
}

#[test]
fn show_defaults_to_kept_documents_only() {
    let output = rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("Windows whoami execution"), "{stdout}");
    assert!(stdout.contains("Linux SSH login"), "{stdout}");
    assert!(
        !stdout.contains("Windows curl download"),
        "excluded documents must be hidden by default: {stdout}"
    );
    assert!(
        !stdout.contains("Linux sudo elevation"),
        "unselected documents must be hidden by default: {stdout}"
    );
}

#[test]
fn show_id_yaml_emits_the_overlaid_document() {
    rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--id",
            W1,
            "--yaml",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("level: critical"))
        .stdout(predicate::str::contains("rsigma.exemplars"))
        .stdout(predicate::str::contains("name: windows_whoami"));
}

#[test]
fn show_id_reports_the_kept_copy_of_a_forked_rule() {
    let dir = tempfile::tempdir().unwrap();
    copy_tree(&fixtures(), dir.path());
    fs::write(
        dir.path().join("fork.yaml"),
        "rulesets:
  fork:
    sources: [vendor, local]
    exclude:
      - path: [windows/proc_creation.yml]
    dependencies: drop
",
    )
    .unwrap();
    let output = rsigma()
        .current_dir(dir.path())
        .args([
            "ruleset",
            "show",
            "fork",
            "--config",
            "fork.yaml",
            "--id",
            W1,
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let envelope: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let document = &envelope["document"];
    assert!(
        document["decision"]
            .as_str()
            .unwrap()
            .starts_with("included"),
        "{document}"
    );
    assert_eq!(document["origin"], serde_json::json!("s1:fork.yml#0"));
}

#[test]
fn show_id_detail_lists_applied_overlays() {
    let output = rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--id",
            &W1.to_uppercase(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let envelope: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let document = &envelope["document"];
    assert_eq!(document["kind"], serde_json::json!("detection"));
    assert_eq!(document["decision"], serde_json::json!("included:0"));
    assert_eq!(
        document["origin"],
        serde_json::json!("s0:windows/proc_creation.yml#0")
    );
    let overlays = document["overlays"].as_array().unwrap();
    assert_eq!(overlays.len(), 3);
    assert_eq!(
        overlays[0]["origin"],
        serde_json::json!("overlays/levels.yml:0")
    );
    assert_eq!(overlays[0]["set"], serde_json::json!(["level"]));
    assert_eq!(overlays[1]["origin"], serde_json::json!("inline:1"));
    assert_eq!(
        overlays[2]["appended"],
        serde_json::json!(["custom_attributes.rsigma.exemplars"])
    );
}

#[test]
fn unknown_name_exits_three_and_lists_defined_names() {
    rsigma()
        .current_dir(fixtures())
        .args(["ruleset", "show", "nope", "--config", "vendor-only.yaml"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("unknown ruleset 'nope'"))
        .stderr(predicate::str::contains("defined rulesets: vendor"));
}

#[test]
fn broken_ruleset_is_reported_without_hiding_other_rows() {
    let output = rsigma()
        .current_dir(fixtures())
        .args(["ruleset", "list", "--output-format", "table"])
        .assert()
        .failure()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("broken"), "{stdout}");
    assert!(stdout.contains("missing"), "{stdout}");
    assert!(stdout.contains("vendor"), "{stdout}");
    assert!(stdout.contains("error"), "{stdout}");
}

#[test]
fn empty_config_prints_a_hint() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("rsigma.yaml");
    std::fs::write(&cfg, "version: 1\n").unwrap();

    rsigma()
        .args(["ruleset", "list", "--config", cfg.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("No rulesets defined"))
        .stderr(predicate::str::contains("rsigma.yaml"));
}

#[test]
fn yaml_requires_an_id() {
    rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--yaml",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--id"));
}

#[test]
fn build_matches_the_golden_tree() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    let envelope = build_json(dir.path(), &out, &[]);
    assert_eq!(envelope["ruleset"], serde_json::json!("vendor"));
    assert_eq!(envelope["documents"], serde_json::json!(7));
    assert_eq!(envelope["written"], serde_json::json!(8));
    assert_eq!(envelope["unchanged"], serde_json::json!(0));
    assert_eq!(envelope["removed"], serde_json::json!(0));
    assert_build_golden(&out);
}

#[test]
fn second_build_writes_nothing() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    build_json(dir.path(), &out, &[]);
    let envelope = build_json(dir.path(), &out, &[]);
    assert_eq!(envelope["written"], serde_json::json!(0));
    assert_eq!(envelope["unchanged"], serde_json::json!(8));
    assert_eq!(envelope["removed"], serde_json::json!(0));
}

#[test]
fn check_is_clean_then_reports_a_source_edit() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    build_json(dir.path(), &out, &[]);

    rsigma()
        .current_dir(dir.path())
        .args([
            "ruleset",
            "build",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "-o",
            out.to_str().unwrap(),
            "--check",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("No drift"));

    let source = dir.path().join("vendor/windows/proc_creation.yml");
    let text = fs::read_to_string(&source).unwrap();
    fs::write(
        &source,
        text.replace("title: Windows whoami execution", "title: Whoami changed"),
    )
    .unwrap();

    rsigma()
        .current_dir(dir.path())
        .args([
            "ruleset",
            "build",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "-o",
            out.to_str().unwrap(),
            "--check",
            "--output-format",
            "table",
        ])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains(format!("rules/{W1}.yml")))
        .stdout(predicate::str::contains("ruleset.lock.json"));
}

#[test]
fn removing_a_source_rule_removes_its_output() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    let extra = dir.path().join("vendor/extra.yml");
    fs::write(
        &extra,
        "title: Windows extra\nid: aaaaaaaa-0000-4000-8000-000000000009\nstatus: test\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        CommandLine|contains: 'extra'\n    condition: selection\ntags:\n    - attack.t1059.009\n",
    )
    .unwrap();
    build_json(dir.path(), &out, &[]);
    let extra_output = out.join("rules/aaaaaaaa-0000-4000-8000-000000000009.yml");
    assert!(extra_output.is_file());

    fs::remove_file(&extra).unwrap();
    let envelope = build_json(dir.path(), &out, &[]);
    assert_eq!(envelope["removed"], serde_json::json!(1));
    assert!(!extra_output.exists());
}

#[test]
fn refuses_a_non_empty_directory_without_a_lockfile() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("keep.txt"), "not ours").unwrap();

    rsigma()
        .current_dir(dir.path())
        .args([
            "ruleset",
            "build",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("--force"));

    rsigma()
        .current_dir(dir.path())
        .args([
            "ruleset",
            "build",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "-o",
            out.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success();
    assert!(out.join("keep.txt").is_file());
}

#[test]
fn a_source_parse_error_fails_with_exit_two() {
    let dir = fixture_copy();
    fs::write(dir.path().join("vendor/broken.yml"), "title: [unclosed\n").unwrap();
    let out = dir.path().join("out");

    rsigma()
        .current_dir(dir.path())
        .args([
            "ruleset",
            "build",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("parse error"));
}

#[test]
fn built_directory_validates_and_lints() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    build_json(dir.path(), &out, &[]);

    rsigma()
        .args(["rule", "validate", out.to_str().unwrap()])
        .assert()
        .success();
    rsigma()
        .args(["rule", "lint", out.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn output_defaults_to_the_spec_output() {
    let dir = fixture_copy();
    let config = dir.path().join("with-output.yaml");
    let text = fs::read_to_string(dir.path().join("vendor-only.yaml"))
        .unwrap()
        .replace(
            "    pipelines: [sysmon]\n",
            "    pipelines: [sysmon]\n    output: built\n",
        );
    fs::write(&config, text).unwrap();

    rsigma()
        .current_dir(dir.path())
        .args([
            "ruleset",
            "build",
            "vendor",
            "--config",
            "with-output.yaml",
            "--output-format",
            "json",
        ])
        .assert()
        .success();
    assert!(dir.path().join("built/ruleset.lock.json").is_file());
}

#[test]
fn missing_output_hints_at_the_flag_and_the_spec_key() {
    let dir = fixture_copy();
    rsigma()
        .current_dir(dir.path())
        .args(["ruleset", "build", "vendor", "--config", "vendor-only.yaml"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("-o <DIR>"))
        .stderr(predicate::str::contains("output"));
}

fn diff_json(dir: &Path, lock: &str, extra: &[&str]) -> (serde_json::Value, std::process::Output) {
    let mut command = rsigma();
    command.current_dir(dir).args([
        "ruleset",
        "diff",
        "vendor",
        "--config",
        "vendor-only.yaml",
        "--lock",
        lock,
        "--output-format",
        "json",
    ]);
    command.args(extra);
    let output = command.assert().get_output().clone();
    let value = if output.status.success() {
        serde_json::from_slice(&output.stdout).unwrap()
    } else {
        serde_json::Value::Null
    };
    (value, output)
}

fn diff_table(dir: &Path, lock: &str, extra: &[&str]) -> std::process::Output {
    let mut command = rsigma();
    command.current_dir(dir).args([
        "ruleset",
        "diff",
        "vendor",
        "--config",
        "vendor-only.yaml",
        "--lock",
        lock,
        "--output-format",
        "table",
    ]);
    command.args(extra);
    command.assert().get_output().clone()
}

fn remove_document(path: &Path, id: &str) {
    let text = fs::read_to_string(path).unwrap();
    let kept: Vec<&str> = text
        .split("---\n")
        .filter(|document| !document.contains(id))
        .collect();
    fs::write(path, kept.join("---\n")).unwrap();
}

fn append_inline_overlay(dir: &Path) {
    let config = dir.join("vendor-only.yaml");
    let text = fs::read_to_string(&config).unwrap();
    let marker = "      - file: overlays/exemplars.yml\n";
    let overlay = format!("{marker}      - id: {W1}\n        set:\n          level: high\n");
    fs::write(&config, text.replace(marker, &overlay)).unwrap();
}

#[test]
fn diff_without_changes_is_clean() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    build_json(dir.path(), &out, &[]);
    let (envelope, output) = diff_json(dir.path(), "out/ruleset.lock.json", &["--fail-on-change"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(envelope["added"], serde_json::json!(0));
    assert_eq!(envelope["removed"], serde_json::json!(0));
    assert_eq!(envelope["changed"], serde_json::json!(0));
    assert_eq!(envelope["unchanged"], serde_json::json!(7));
    assert_eq!(envelope["sources_changed"], serde_json::json!(false));
    assert_eq!(envelope["overlays_changed"], serde_json::json!(false));
    assert_eq!(envelope["spec_changed"], serde_json::json!(false));
}

#[test]
fn diff_reports_a_rule_edit() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    build_json(dir.path(), &out, &[]);
    let source = dir.path().join("vendor/windows/proc_creation.yml");
    let text = fs::read_to_string(&source).unwrap();
    fs::write(
        &source,
        text.replace("title: Windows whoami execution", "title: Whoami changed"),
    )
    .unwrap();

    let (envelope, output) = diff_json(dir.path(), "out/ruleset.lock.json", &[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(envelope["changed"], serde_json::json!(1));
    let output = diff_table(dir.path(), "out/ruleset.lock.json", &[]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("title"), "{stdout}");
    assert!(stdout.contains("changed"), "{stdout}");
}

#[test]
fn diff_reports_a_new_rule() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    build_json(dir.path(), &out, &[]);
    fs::write(
        dir.path().join("vendor/extra.yml"),
        "title: Windows extra\nid: aaaaaaaa-0000-4000-8000-000000000009\nstatus: test\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        CommandLine|contains: 'extra'\n    condition: selection\ntags:\n    - attack.t1059.009\n",
    )
    .unwrap();

    let (envelope, output) = diff_json(dir.path(), "out/ruleset.lock.json", &[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(envelope["added"], serde_json::json!(1));
    let output = diff_table(dir.path(), "out/ruleset.lock.json", &[]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("added"), "{stdout}");
    assert!(stdout.contains("Windows extra"), "{stdout}");
}

#[test]
fn diff_reports_an_overlay_edit_with_the_overlay_field() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    build_json(dir.path(), &out, &[]);
    append_inline_overlay(dir.path());

    let (envelope, output) = diff_json(dir.path(), "out/ruleset.lock.json", &[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(envelope["changed"], serde_json::json!(1));
    assert_eq!(envelope["spec_changed"], serde_json::json!(true));
    let output = diff_table(dir.path(), "out/ruleset.lock.json", &[]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("overlays"), "{stdout}");
}

#[test]
fn diff_rejects_an_unknown_lock_version() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    build_json(dir.path(), &out, &[]);
    let lock = out.join("ruleset.lock.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&lock).unwrap()).unwrap();
    value["lock_version"] = serde_json::json!(2);
    fs::write(&lock, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    rsigma()
        .current_dir(dir.path())
        .args([
            "ruleset",
            "diff",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--lock",
            "out/ruleset.lock.json",
        ])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("lock_version 2"));
}

#[test]
fn diff_fail_on_change_exits_one() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    build_json(dir.path(), &out, &[]);
    let source = dir.path().join("vendor/windows/proc_creation.yml");
    let text = fs::read_to_string(&source).unwrap();
    fs::write(
        &source,
        text.replace("author: Test Author", "author: Someone Else"),
    )
    .unwrap();

    rsigma()
        .current_dir(dir.path())
        .args([
            "ruleset",
            "diff",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--lock",
            "out/ruleset.lock.json",
            "--fail-on-change",
        ])
        .assert()
        .failure()
        .code(1);
}

#[test]
fn diff_golden_mixed_case() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    build_json(dir.path(), &out, &[]);

    let proc_creation = dir.path().join("vendor/windows/proc_creation.yml");
    let text = fs::read_to_string(&proc_creation).unwrap();
    fs::write(
        &proc_creation,
        text.replace("title: Windows whoami execution", "title: Whoami changed"),
    )
    .unwrap();
    remove_document(&proc_creation, "aaaaaaaa-0000-4000-8000-000000000002");
    fs::write(
        dir.path().join("vendor/extra.yml"),
        "title: Windows extra\nid: aaaaaaaa-0000-4000-8000-000000000009\nstatus: test\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        CommandLine|contains: 'extra'\n    condition: selection\ntags:\n    - attack.t1059.009\n",
    )
    .unwrap();
    append_inline_overlay(dir.path());

    let (_, output) = diff_json(dir.path(), "out/ruleset.lock.json", &[]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_json_golden("ruleset_diff_mixed.json", &stdout);
}
