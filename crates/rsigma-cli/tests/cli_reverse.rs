//! Integration tests for `rsigma rule reverse`.

use crate::common;

use common::rsigma;

#[test]
fn reverse_requires_a_logsource() {
    for extra in [None, Some("--logsource-product")] {
        let mut cmd = rsigma();
        cmd.args(["rule", "reverse", "--from", "lucene", "EventID:1"]);
        if let Some(flag) = extra {
            cmd.args([flag, ""]);
        }
        let out = cmd.output().unwrap();
        assert_eq!(out.status.code(), Some(3));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("needs a logsource; pass --logsource-product"),
            "{stderr}"
        );
    }
}

#[test]
fn reverse_emits_the_given_logsource() {
    let out = rsigma()
        .args([
            "rule",
            "reverse",
            "--from",
            "lucene",
            "EventID:1",
            "--logsource-category",
            "process_creation",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("logsource:\n    category: process_creation"),
        "{stdout}"
    );
}
