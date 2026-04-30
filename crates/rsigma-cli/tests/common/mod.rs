//! Shared helpers and fixture constants for CLI integration tests.
#![allow(dead_code)]

use std::io::Write;

use assert_cmd::Command;
use tempfile::NamedTempFile;

#[allow(deprecated)]
pub fn rsigma() -> Command {
    Command::cargo_bin("rsigma").expect("binary not found")
}

/// Write `contents` to a temporary file with the given suffix and return it.
pub fn temp_file(suffix: &str, contents: &str) -> NamedTempFile {
    let mut f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

pub const SIMPLE_RULE: &str = r#"
title: Test Rule
id: 00000000-0000-0000-0000-000000000001
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: "malware"
    condition: selection
level: high
"#;

pub const PIPELINE_YAML: &str = r#"
name: test-pipeline
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
"#;
