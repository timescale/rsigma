//! Rule loading limits end to end: directory links that loop or leave the
//! rules directory, `--follow-external-links`, and the `|windash` expansion
//! budget agreeing across lint, validate, eval, and convert.

use std::path::{Path, PathBuf};

use predicates::prelude::*;
use predicates::str::contains;
use tempfile::TempDir;

use crate::common::{SIMPLE_RULE, rsigma};

const SECRET: &str = "TOPSECRET-CONTENT-31a7";

const OUTSIDE_RULE: &str = r#"
title: Outside Rule
id: 00000000-0000-0000-0000-0000000000aa
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: "outside"
    condition: selection
"#;

const WINDASH_BOMB: &str = r#"
title: Windash Bomb
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|windash|contains:
            - 'a -b -c -d -e -f -g -h'
            - 'a /b /c /d /e /f /g /h'
    condition: selection
"#;

/// Link `link` to the directory `target`: a symlink on Unix, a junction on
/// Windows.
fn link_dir(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    {
        // `cmd` reads a `/` inside an argument as the start of a switch.
        let native = |path: &Path| PathBuf::from(path.to_string_lossy().replace('/', "\\"));
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(native(link))
            .arg(native(target))
            .output()
            .unwrap();
        assert!(output.status.success(), "mklink /J failed: {output:?}");
    }
}

/// A rules directory with one rule, a link back to itself, a link to a
/// directory of outside rules, and (where file symlinks are allowed) a link
/// to an outside file holding a secret. Returns the temp dir, the rules
/// directory, and the outside directory.
fn tree() -> (TempDir, PathBuf, PathBuf) {
    let dir = TempDir::new().unwrap();
    let rules = dir.path().join("rules");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(rules.join("sub")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(rules.join("rule.yml"), SIMPLE_RULE).unwrap();
    std::fs::write(outside.join("outside.yml"), OUTSIDE_RULE).unwrap();
    std::fs::write(dir.path().join("secret.yml"), format!("title: [{SECRET}\n")).unwrap();
    link_dir(&rules, &rules.join("sub").join("loop"));
    link_dir(&outside, &rules.join("vendor"));
    #[cfg(unix)]
    std::os::unix::fs::symlink(dir.path().join("secret.yml"), rules.join("leak.yml")).unwrap();
    (dir, rules, outside)
}

#[test]
fn eval_loads_each_rule_once_and_skips_links_out_of_the_directory() {
    let (_dir, rules, _outside) = tree();
    rsigma()
        .args(["engine", "eval", "-r"])
        .arg(&rules)
        .write_stdin("{\"CommandLine\": \"malware outside\"}\n")
        .assert()
        .success()
        .stderr(contains("Loaded 1 rules"))
        .stderr(contains("vendor: it resolves outside"))
        .stderr(contains("--follow-external-links"))
        .stderr(contains(SECRET).not());
}

#[test]
fn follow_external_links_loads_linked_rules_once() {
    let (_dir, rules, _outside) = tree();
    let assert = rsigma()
        .args(["engine", "eval", "--follow-external-links", "-r"])
        .arg(&rules)
        .write_stdin("{\"CommandLine\": \"malware outside\"}\n")
        .assert()
        .success()
        .stderr(contains("Loaded 2 rules"));
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert_eq!(stdout.matches("\"rule_title\":\"Outside Rule\"").count(), 1);
    assert_eq!(stdout.matches("\"rule_title\":\"Test Rule\"").count(), 1);
}

#[test]
fn validate_and_lint_report_skipped_links() {
    let (_dir, rules, _outside) = tree();
    rsigma()
        .args(["rule", "validate", "--verbose"])
        .arg(&rules)
        .assert()
        .success()
        .stdout(contains("Detection rules:   1"))
        .stdout(contains(SECRET).not());
    rsigma()
        .args(["rule", "lint", "--output-format", "table"])
        .arg(&rules)
        .assert()
        .stdout(contains("skipped_path"))
        .stdout(contains(SECRET).not());
}

#[test]
fn windash_budget_outcome_agrees_across_commands() {
    let dir = TempDir::new().unwrap();
    let rule = dir.path().join("bomb.yml");
    std::fs::write(&rule, WINDASH_BOMB).unwrap();

    rsigma()
        .args(["rule", "lint", "--output-format", "table"])
        .arg(&rule)
        .assert()
        .code(1)
        .stdout(contains("windash_expansion_too_large"));
    rsigma()
        .args(["rule", "validate", "--verbose"])
        .arg(&rule)
        .assert()
        .code(2)
        .stdout(contains("rule 'Windash Bomb'"));
    rsigma()
        .args(["engine", "eval", "-r"])
        .arg(&rule)
        .write_stdin("{\"CommandLine\": \"x\"}\n")
        .assert()
        .stderr(contains("rule 'Windash Bomb'"))
        .stderr(contains("Loaded 0 rules"));
    rsigma()
        .args(["backend", "convert", "-t", "postgres"])
        .arg(&rule)
        .assert()
        .code(2)
        .stderr(contains("rule 'Windash Bomb'"));
}

#[cfg(feature = "daemon")]
mod daemon {
    use super::*;
    use crate::common::DaemonProcess;
    use crate::common::{http_get, poll_until};
    use std::time::Duration;

    fn loaded(daemon: &DaemonProcess) -> Option<i64> {
        let (_, body) = http_get(&daemon.url("/metrics"));
        body.lines().find_map(|line| {
            line.strip_prefix("rsigma_detection_rules_loaded ")?
                .parse()
                .ok()
        })
    }

    #[test]
    fn daemon_skips_links_out_of_the_rules_directory() {
        let (_dir, rules, _outside) = tree();
        let daemon = DaemonProcess::spawn_http(rules.to_str().unwrap());
        assert_eq!(loaded(&daemon), Some(1));
    }

    #[test]
    fn daemon_follows_external_links_across_reloads() {
        let (_dir, rules, outside) = tree();
        let daemon = DaemonProcess::spawn_http_with_args(
            rules.to_str().unwrap(),
            &["--follow-external-links"],
        );
        assert_eq!(loaded(&daemon), Some(2));

        std::fs::write(
            outside.join("another.yml"),
            OUTSIDE_RULE
                .replace("Outside Rule", "Another Rule")
                .replace("0000000000aa", "0000000000ab"),
        )
        .unwrap();
        let reloaded = poll_until(Duration::from_secs(15), || {
            let (status, _) = crate::common::http_post(&daemon.url("/api/v1/reload"), "");
            assert!(status == 200 || status == 429, "reload status {status}");
            loaded(&daemon).filter(|n| *n == 3)
        });
        assert_eq!(
            reloaded,
            Some(3),
            "the reload keeps following external links"
        );
    }
}
