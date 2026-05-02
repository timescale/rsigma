//! Integration tests for the `fields` subcommand.
//!
//! Uses insta inline snapshot testing for stdout/stderr output verification.

mod common;

use common::{rsigma, temp_file};
use insta::assert_snapshot;
use tempfile::TempDir;

const SIMPLE_DETECTION: &str = r#"
title: Detect Whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
        CommandLine|contains:
            - '/c'
            - '/k'
    condition: selection
level: medium
"#;

const RULE_WITH_FIELDS_METADATA: &str = r#"
title: Failed Login
id: failed-login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        TargetUserName|endswith: '@company.com'
    condition: selection
fields:
    - SourceIP
    - LogonType
level: medium
"#;

const CORRELATION_RULES: &str = r#"
title: Failed Login
id: failed-login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        TargetUserName|endswith: '@company.com'
    condition: selection
fields:
    - SourceIP
    - LogonType
level: medium
---
title: Brute Force
correlation:
    type: event_count
    rules:
        - failed-login
    group-by:
        - TargetUserName
        - SourceIP
    timespan: 5m
    condition:
        gte: 10
level: high
"#;

const WITH_FILTER: &str = r#"
title: Failed Login
id: failed-login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        TargetUserName|endswith: '@company.com'
    condition: selection
fields:
    - SourceIP
    - LogonType
level: medium
---
title: Brute Force
correlation:
    type: event_count
    rules:
        - failed-login
    group-by:
        - TargetUserName
        - SourceIP
    timespan: 5m
    condition:
        gte: 10
level: high
---
title: Exclude Service Accounts
logsource:
    product: windows
    service: security
filter:
    rules:
        - failed-login
    selection:
        TargetUserName|startswith: 'svc_'
    condition: selection
"#;

const VALUE_COUNT_CORRELATION: &str = r#"
title: DNS Query
id: dns-query
logsource:
    category: dns
detection:
    selection:
        QueryType: A
    condition: selection
---
title: Too Many Unique Domains
correlation:
    type: value_count
    rules:
        - dns-query
    group-by:
        - SourceIP
    timespan: 10m
    condition:
        field: QueryName
        gte: 50
level: high
"#;

const FIELD_ALIAS_CORRELATION: &str = r#"
title: Login Attempt
id: login-attempt
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: SSH Login
id: ssh-login
logsource:
    category: ssh
detection:
    selection:
        action: login
    condition: selection
---
title: Cross-Source Login Correlation
correlation:
    type: temporal
    rules:
        - login-attempt
        - ssh-login
    group-by:
        - user
    timespan: 5m
    condition:
        gte: 1
    aliases:
        user:
            login-attempt: UserName
            ssh-login: ssh_user
level: high
"#;

const PIPELINE_YAML: &str = r#"
name: ecs-mapping
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      Image: process.executable
    rule_conditions:
      - type: logsource
        product: windows
"#;

const KEYWORDS_ONLY: &str = r#"
title: Keyword Rule
logsource:
    category: test
detection:
    keywords:
        - 'malware'
        - 'virus'
    condition: keywords
level: high
"#;

// ---------------------------------------------------------------------------
// Basic field extraction
// ---------------------------------------------------------------------------

#[test]
fn fields_simple_detection() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let output = rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r"
    FIELD        RULES  SOURCES  
    -----------  -----  ---------
    CommandLine      1  detection
    Image            1  detection
    ");
    assert_snapshot!(String::from_utf8_lossy(&output.stderr), @r"
    Rules: 1 detection, 0 correlation, 0 filter | Pipelines: 0 | Unique fields: 2

    ");
}

#[test]
fn fields_with_metadata_fields() {
    let rule = temp_file(".yml", RULE_WITH_FIELDS_METADATA);
    let output = rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r"
    FIELD           RULES  SOURCES  
    --------------  -----  ---------
    EventID             1  detection
    LogonType           1  metadata 
    SourceIP            1  metadata 
    TargetUserName      1  detection
    ");
}

#[test]
fn fields_correlation_adds_group_by() {
    let rule = temp_file(".yml", CORRELATION_RULES);
    let output = rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r"
    FIELD           RULES  SOURCES               
    --------------  -----  ----------------------
    EventID             1  detection             
    LogonType           1  metadata              
    SourceIP            2  correlation, metadata 
    TargetUserName      2  detection, correlation
    ");
    assert_snapshot!(String::from_utf8_lossy(&output.stderr), @r"
    Rules: 1 detection, 1 correlation, 0 filter | Pipelines: 0 | Unique fields: 4

    ");
}

#[test]
fn fields_value_count_condition_field() {
    let rule = temp_file(".yml", VALUE_COUNT_CORRELATION);
    let output = rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r"
    FIELD      RULES  SOURCES    
    ---------  -----  -----------
    QueryName      1  correlation
    QueryType      1  detection  
    SourceIP       1  correlation
    ");
}

#[test]
fn fields_alias_mapping_values() {
    let rule = temp_file(".yml", FIELD_ALIAS_CORRELATION);
    let output = rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r"
    FIELD      RULES  SOURCES    
    ---------  -----  -----------
    EventType      1  detection  
    UserName       1  correlation
    action         1  detection  
    ssh_user       1  correlation
    user           1  correlation
    ");
}

#[test]
fn fields_keywords_only_rule_has_no_fields() {
    let rule = temp_file(".yml", KEYWORDS_ONLY);
    let output = rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Unique fields: 0"));
    assert!(stderr.contains("No fields found."));
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

#[test]
fn fields_includes_filters_by_default() {
    let rule = temp_file(".yml", WITH_FILTER);
    let output = rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r"
    FIELD           RULES  SOURCES                       
    --------------  -----  ------------------------------
    EventID             1  detection                     
    LogonType           1  metadata                      
    SourceIP            2  correlation, metadata         
    TargetUserName      3  detection, correlation, filter
    ");
    assert_snapshot!(String::from_utf8_lossy(&output.stderr), @r"
    Rules: 1 detection, 1 correlation, 1 filter | Pipelines: 0 | Unique fields: 4

    ");
}

#[test]
fn fields_no_filters_excludes_filter_fields() {
    let rule = temp_file(".yml", WITH_FILTER);
    let output = rsigma()
        .args([
            "fields",
            "-r",
            rule.path().to_str().unwrap(),
            "--no-filters",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r"
    FIELD           RULES  SOURCES               
    --------------  -----  ----------------------
    EventID             1  detection             
    LogonType           1  metadata              
    SourceIP            2  correlation, metadata 
    TargetUserName      2  detection, correlation
    ");
}

// ---------------------------------------------------------------------------
// Pipelines
// ---------------------------------------------------------------------------

#[test]
fn fields_with_pipeline_transforms_names() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let pipeline = temp_file(".yml", PIPELINE_YAML);
    let output = rsigma()
        .args([
            "fields",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipeline.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r"
    FIELD                 RULES  SOURCES  
    --------------------  -----  ---------
    process.command_line      1  detection
    process.executable        1  detection
    ");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Pipelines: 1"));
    assert!(stderr.contains("Pipeline field mappings:"));
    assert!(stderr.contains("CommandLine -> process.command_line"));
    assert!(stderr.contains("Image -> process.executable"));
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

#[test]
fn fields_json_output() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let output = rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["summary"]["total_rules"], 1);
    assert_eq!(json["summary"]["unique_fields"], 2);
    assert_eq!(json["summary"]["pipelines_applied"], 0);
    let fields = json["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0]["field"], "CommandLine");
    assert_eq!(fields[1]["field"], "Image");
}

#[test]
fn fields_json_with_pipeline_includes_mappings() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let pipeline = temp_file(".yml", PIPELINE_YAML);
    let output = rsigma()
        .args([
            "fields",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipeline.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["summary"]["pipelines_applied"], 1);
    let mappings = json["pipeline_mappings"].as_array().unwrap();
    assert!(mappings.len() >= 2);
    let originals: Vec<&str> = mappings
        .iter()
        .map(|m| m["original"].as_str().unwrap())
        .collect();
    assert!(originals.contains(&"CommandLine"));
    assert!(originals.contains(&"Image"));
}

#[test]
fn fields_json_with_filter() {
    let rule = temp_file(".yml", WITH_FILTER);
    let output = rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["summary"]["total_filters"], 1);

    let fields = json["fields"].as_array().unwrap();
    let target_user = fields
        .iter()
        .find(|f| f["field"] == "TargetUserName")
        .unwrap();
    assert_eq!(target_user["rule_count"], 3);
    let sources = target_user["sources"].as_array().unwrap();
    assert!(sources.iter().any(|s| s == "filter"));
}

#[test]
fn fields_json_snapshot() {
    let rule = temp_file(".yml", CORRELATION_RULES);
    let output = rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r#"
    {
      "summary": {
        "total_rules": 1,
        "total_correlations": 1,
        "total_filters": 0,
        "unique_fields": 4,
        "pipelines_applied": 0
      },
      "fields": [
        {
          "field": "EventID",
          "rule_count": 1,
          "sources": [
            "detection"
          ]
        },
        {
          "field": "LogonType",
          "rule_count": 1,
          "sources": [
            "metadata"
          ]
        },
        {
          "field": "SourceIP",
          "rule_count": 2,
          "sources": [
            "correlation",
            "metadata"
          ]
        },
        {
          "field": "TargetUserName",
          "rule_count": 2,
          "sources": [
            "detection",
            "correlation"
          ]
        }
      ]
    }
    "#);
}

// ---------------------------------------------------------------------------
// Directory of rules
// ---------------------------------------------------------------------------

#[test]
fn fields_directory_of_rules() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("rule_a.yml"), SIMPLE_DETECTION).unwrap();
    std::fs::write(dir.path().join("rule_b.yml"), RULE_WITH_FIELDS_METADATA).unwrap();

    let output = rsigma()
        .args(["fields", "-r", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r"
    FIELD           RULES  SOURCES  
    --------------  -----  ---------
    CommandLine         1  detection
    EventID             1  detection
    Image               1  detection
    LogonType           1  metadata 
    SourceIP            1  metadata 
    TargetUserName      1  detection
    ");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Rules: 2 detection"));
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn fields_nonexistent_path() {
    rsigma()
        .args(["fields", "-r", "/nonexistent/path"])
        .assert()
        .failure();
}

#[test]
fn fields_missing_rules_arg() {
    rsigma()
        .args(["fields"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--rules"));
}
