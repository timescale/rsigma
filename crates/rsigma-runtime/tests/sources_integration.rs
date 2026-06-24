//! Integration tests for dynamic source resolution.

use std::collections::HashMap;

use rsigma_eval::Pipeline;
use rsigma_eval::pipeline::sources::{
    DataFormat, DynamicSource, ErrorPolicy, ExtractExpr, RefreshPolicy, SourceType,
};
use rsigma_runtime::sources::cache::SourceCache;
use rsigma_runtime::sources::file::resolve_file;
use rsigma_runtime::sources::template::TemplateExpander;
use rsigma_runtime::sources::{DefaultSourceResolver, SourceResolver, resolve_all};

// =============================================================================
// File source tests
// =============================================================================

#[tokio::test]
async fn file_source_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, r#"{"emails": ["a@b.com", "c@d.com"]}"#).unwrap();

    let result = resolve_file(&path, DataFormat::Json, None).await.unwrap();
    let expected = serde_json::json!({"emails": ["a@b.com", "c@d.com"]});
    assert_eq!(result.data, expected);
}

#[tokio::test]
async fn file_source_json_with_extract_jq() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, r#"{"emails": ["a@b.com", "c@d.com"]}"#).unwrap();

    let extract = ExtractExpr::Jq(".emails[]".to_string());
    let result = resolve_file(&path, DataFormat::Json, Some(&extract))
        .await
        .unwrap();
    let expected = serde_json::json!(["a@b.com", "c@d.com"]);
    assert_eq!(result.data, expected);
}

#[tokio::test]
async fn file_source_json_with_extract_jsonpath() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, r#"{"emails": ["a@b.com", "c@d.com"]}"#).unwrap();

    let extract = ExtractExpr::JsonPath("$.emails[*]".to_string());
    let result = resolve_file(&path, DataFormat::Json, Some(&extract))
        .await
        .unwrap();
    let expected = serde_json::json!(["a@b.com", "c@d.com"]);
    assert_eq!(result.data, expected);
}

#[tokio::test]
async fn file_source_json_with_extract_jsonpath_single() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, r#"{"name": "rsigma", "version": 9}"#).unwrap();

    let extract = ExtractExpr::JsonPath("$.name".to_string());
    let result = resolve_file(&path, DataFormat::Json, Some(&extract))
        .await
        .unwrap();
    assert_eq!(result.data, serde_json::json!("rsigma"));
}

#[tokio::test]
async fn file_source_json_with_extract_cel() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, r#"{"emails": ["a@b.com", "c@d.com"], "count": 2}"#).unwrap();

    let extract = ExtractExpr::Cel("data.count".to_string());
    let result = resolve_file(&path, DataFormat::Json, Some(&extract))
        .await
        .unwrap();
    assert_eq!(result.data, serde_json::json!(2));
}

#[tokio::test]
async fn file_source_json_with_extract_cel_list() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, r#"{"items": [1, 2, 3, 4, 5]}"#).unwrap();

    let extract = ExtractExpr::Cel("data.items.filter(x, x > 3)".to_string());
    let result = resolve_file(&path, DataFormat::Json, Some(&extract))
        .await
        .unwrap();
    assert_eq!(result.data, serde_json::json!([4, 5]));
}

#[tokio::test]
async fn extract_invalid_jq_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, r#"{"x": 1}"#).unwrap();

    let extract = ExtractExpr::Jq("invalid[[[".to_string());
    let result = resolve_file(&path, DataFormat::Json, Some(&extract)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn extract_invalid_jsonpath_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, r#"{"x": 1}"#).unwrap();

    let extract = ExtractExpr::JsonPath("$[invalid".to_string());
    let result = resolve_file(&path, DataFormat::Json, Some(&extract)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn extract_invalid_cel_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, r#"{"x": 1}"#).unwrap();

    let extract = ExtractExpr::Cel("invalid(((syntax".to_string());
    let result = resolve_file(&path, DataFormat::Json, Some(&extract)).await;
    assert!(result.is_err());
}

#[test]
fn extract_jq_halt_does_not_exit_process() {
    use rsigma_runtime::sources::extract::apply_extract;

    let data = serde_json::json!([1, 2, 3]);

    // `halt` and `halt_error` are implemented in jaq-std with
    // `std::process::exit`. They must surface as ordinary errors so a single
    // bad expression cannot terminate a long-running process. If this filter
    // were still wired up, the test binary would exit here instead of failing.
    for expr in ["halt", "halt_error", ".[] | halt(0)", "halt_error(2)"] {
        let result = apply_extract(&data, &ExtractExpr::Jq(expr.to_string()));
        assert!(
            result.is_err(),
            "expected jq `{expr}` to error instead of exiting the process",
        );
    }
}

#[tokio::test]
async fn file_source_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ips.txt");
    std::fs::write(&path, "10.0.0.1\n10.0.0.2\n192.168.1.1\n").unwrap();

    let result = resolve_file(&path, DataFormat::Lines, None).await.unwrap();
    let expected = serde_json::json!(["10.0.0.1", "10.0.0.2", "192.168.1.1"]);
    assert_eq!(result.data, expected);
}

#[tokio::test]
async fn file_source_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(
        &path,
        "field_mapping:\n  EventID: event_id\n  HostName: hostname\n",
    )
    .unwrap();

    let result = resolve_file(&path, DataFormat::Yaml, None).await.unwrap();
    let expected = serde_json::json!({
        "field_mapping": {
            "EventID": "event_id",
            "HostName": "hostname"
        }
    });
    assert_eq!(result.data, expected);
}

#[tokio::test]
async fn file_source_csv() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("assets.csv");
    std::fs::write(&path, "hostname,owner\nserver1,alice\nserver2,bob\n").unwrap();

    let result = resolve_file(&path, DataFormat::Csv, None).await.unwrap();
    let expected = serde_json::json!([
        {"hostname": "server1", "owner": "alice"},
        {"hostname": "server2", "owner": "bob"}
    ]);
    assert_eq!(result.data, expected);
}

#[tokio::test]
async fn file_source_missing_file() {
    let result = resolve_file(
        std::path::Path::new("/nonexistent/file.json"),
        DataFormat::Json,
        None,
    )
    .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err.kind,
        rsigma_runtime::SourceErrorKind::Fetch(_)
    ));
}

// =============================================================================
// Command source tests
// =============================================================================

#[tokio::test]
async fn command_source_echo_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, r#"{"status": "ok", "count": 42}"#).unwrap();

    #[cfg(unix)]
    let cmd = vec!["cat".to_string(), path.to_str().unwrap().to_string()];
    #[cfg(windows)]
    let cmd = vec![
        "cmd".to_string(),
        "/C".to_string(),
        format!("type {}", path.to_str().unwrap()),
    ];

    let result =
        rsigma_runtime::sources::command::resolve_command(&cmd, DataFormat::Json, None, None)
            .await
            .unwrap();

    let expected = serde_json::json!({"status": "ok", "count": 42});
    assert_eq!(result.data, expected);
}

#[tokio::test]
async fn command_source_with_extract() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.json");
    std::fs::write(&path, r#"{"items": [1, 2, 3]}"#).unwrap();

    #[cfg(unix)]
    let cmd = vec!["cat".to_string(), path.to_str().unwrap().to_string()];
    #[cfg(windows)]
    let cmd = vec![
        "cmd".to_string(),
        "/C".to_string(),
        format!("type {}", path.to_str().unwrap()),
    ];

    let extract = ExtractExpr::Jq(".items[]".to_string());
    let result = rsigma_runtime::sources::command::resolve_command(
        &cmd,
        DataFormat::Json,
        Some(&extract),
        None,
    )
    .await
    .unwrap();

    let expected = serde_json::json!([1, 2, 3]);
    assert_eq!(result.data, expected);
}

#[tokio::test]
async fn command_source_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lines.txt");
    std::fs::write(&path, "line1\nline2\nline3\n").unwrap();

    #[cfg(unix)]
    let cmd = vec!["cat".to_string(), path.to_str().unwrap().to_string()];
    #[cfg(windows)]
    let cmd = vec![
        "cmd".to_string(),
        "/C".to_string(),
        format!("type {}", path.to_str().unwrap()),
    ];

    let result =
        rsigma_runtime::sources::command::resolve_command(&cmd, DataFormat::Lines, None, None)
            .await
            .unwrap();

    let expected = serde_json::json!(["line1", "line2", "line3"]);
    assert_eq!(result.data, expected);
}

#[tokio::test]
async fn command_source_failing_command() {
    #[cfg(unix)]
    let cmd = vec!["false".to_string()];
    #[cfg(windows)]
    let cmd = vec!["cmd".to_string(), "/C".to_string(), "exit 1".to_string()];

    let result =
        rsigma_runtime::sources::command::resolve_command(&cmd, DataFormat::Json, None, None).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err.kind,
        rsigma_runtime::SourceErrorKind::Fetch(_)
    ));
}

#[tokio::test]
async fn command_source_empty_command() {
    let result =
        rsigma_runtime::sources::command::resolve_command(&[], DataFormat::Json, None, None).await;

    assert!(result.is_err());
}

// =============================================================================
// DefaultSourceResolver with error policies
// =============================================================================

#[tokio::test]
async fn resolver_file_source_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("admins.json");
    std::fs::write(&path, r#"["admin@corp.com", "root@corp.com"]"#).unwrap();

    let source = DynamicSource {
        id: "admin_emails".to_string(),
        source_type: SourceType::File {
            path: path.clone(),
            format: DataFormat::Json,
            extract: None,
        },
        refresh: RefreshPolicy::Once,
        timeout: None,
        on_error: ErrorPolicy::Fail,
        required: true,
        default: None,
    };

    let resolver = DefaultSourceResolver::new();
    let result = resolver.resolve(&source).await.unwrap();
    assert_eq!(
        result.data,
        serde_json::json!(["admin@corp.com", "root@corp.com"])
    );
}

#[tokio::test]
async fn resolver_use_cached_on_failure() {
    let resolver = DefaultSourceResolver::new();

    // Pre-populate cache
    resolver
        .cache()
        .store("missing_source", &serde_json::json!(["cached_value"]));

    let source = DynamicSource {
        id: "missing_source".to_string(),
        source_type: SourceType::File {
            path: "/nonexistent/file.json".into(),
            format: DataFormat::Json,
            extract: None,
        },
        refresh: RefreshPolicy::Once,
        timeout: None,
        on_error: ErrorPolicy::UseCached,
        required: true,
        default: None,
    };

    let result = resolver.resolve(&source).await.unwrap();
    assert_eq!(result.data, serde_json::json!(["cached_value"]));
}

#[tokio::test]
async fn resolver_use_default_on_failure() {
    let resolver = DefaultSourceResolver::new();

    let default_val =
        yaml_serde::Value::Sequence(vec![yaml_serde::Value::String("fallback@corp.com".into())]);

    let source = DynamicSource {
        id: "missing_source".to_string(),
        source_type: SourceType::File {
            path: "/nonexistent/file.json".into(),
            format: DataFormat::Json,
            extract: None,
        },
        refresh: RefreshPolicy::Once,
        timeout: None,
        on_error: ErrorPolicy::UseDefault,
        required: true,
        default: Some(default_val),
    };

    let result = resolver.resolve(&source).await.unwrap();
    assert_eq!(result.data, serde_json::json!(["fallback@corp.com"]));
}

#[tokio::test]
async fn resolver_fail_policy_returns_error() {
    let resolver = DefaultSourceResolver::new();

    let source = DynamicSource {
        id: "bad_source".to_string(),
        source_type: SourceType::File {
            path: "/nonexistent/file.json".into(),
            format: DataFormat::Json,
            extract: None,
        },
        refresh: RefreshPolicy::Once,
        timeout: None,
        on_error: ErrorPolicy::Fail,
        required: true,
        default: None,
    };

    let result = resolver.resolve(&source).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().source_id, "bad_source");
}

// =============================================================================
// resolve_all + TemplateExpander end-to-end
// =============================================================================

#[tokio::test]
async fn end_to_end_dynamic_pipeline_resolution() {
    let dir = tempfile::tempdir().unwrap();

    // Create source files
    let emails_path = dir.path().join("admins.json");
    std::fs::write(&emails_path, r#"["admin@corp.com", "sec@corp.com"]"#).unwrap();

    let config_path = dir.path().join("config.json");
    std::fs::write(
        &config_path,
        r#"{"env": "production", "index": "security-logs"}"#,
    )
    .unwrap();

    // Build a dynamic pipeline
    let mut vars = HashMap::new();
    vars.insert(
        "admin_emails".to_string(),
        vec!["${source.admin_emails}".to_string()],
    );
    vars.insert(
        "log_index".to_string(),
        vec!["${source.env_config.index}".to_string()],
    );
    vars.insert("static_var".to_string(), vec!["unchanged".to_string()]);

    let sources = vec![
        DynamicSource {
            id: "admin_emails".to_string(),
            source_type: SourceType::File {
                path: emails_path,
                format: DataFormat::Json,
                extract: None,
            },
            refresh: RefreshPolicy::Once,
            timeout: None,
            on_error: ErrorPolicy::Fail,
            required: true,
            default: None,
        },
        DynamicSource {
            id: "env_config".to_string(),
            source_type: SourceType::File {
                path: config_path,
                format: DataFormat::Json,
                extract: None,
            },
            refresh: RefreshPolicy::Once,
            timeout: None,
            on_error: ErrorPolicy::Fail,
            required: true,
            default: None,
        },
    ];

    let pipeline = Pipeline {
        name: "dynamic-test".to_string(),
        priority: 10,
        vars,
        transformations: vec![],
        finalizers: vec![],
        sources: sources.clone(),
        source_refs: vec![],
    };

    assert!(pipeline.is_dynamic());

    // Resolve sources
    let resolver = DefaultSourceResolver::new();
    let resolved_data = resolve_all(&resolver, &sources).await.unwrap();

    assert_eq!(resolved_data.len(), 2);
    assert_eq!(
        resolved_data["admin_emails"],
        serde_json::json!(["admin@corp.com", "sec@corp.com"])
    );

    // Expand templates
    let expanded = TemplateExpander::expand(&pipeline, &resolved_data);

    assert_eq!(
        expanded.vars["admin_emails"],
        vec!["admin@corp.com", "sec@corp.com"]
    );
    assert_eq!(expanded.vars["log_index"], vec!["security-logs"]);
    assert_eq!(expanded.vars["static_var"], vec!["unchanged"]);
}

// =============================================================================
// Cache tests
// =============================================================================

#[test]
fn cache_store_and_retrieve() {
    let cache = SourceCache::new();
    assert!(cache.is_empty());

    cache.store("src1", &serde_json::json!({"key": "value"}));
    assert_eq!(cache.len(), 1);

    let val = cache.get("src1").unwrap();
    assert_eq!(val, serde_json::json!({"key": "value"}));
}

#[test]
fn cache_invalidate() {
    let cache = SourceCache::new();
    cache.store("src1", &serde_json::json!("data"));
    cache.invalidate("src1");
    assert!(cache.get("src1").is_none());
}

#[test]
fn cache_clear() {
    let cache = SourceCache::new();
    cache.store("src1", &serde_json::json!("a"));
    cache.store("src2", &serde_json::json!("b"));
    assert_eq!(cache.len(), 2);
    cache.clear();
    assert!(cache.is_empty());
}

#[test]
fn cache_sqlite_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cache.db");

    // Store some data
    {
        let cache = SourceCache::with_sqlite(&db_path).unwrap();
        cache.store("src1", &serde_json::json!({"key": "value1"}));
        cache.store("src2", &serde_json::json!(["a", "b", "c"]));
    }

    // Re-open and verify data is still there
    {
        let cache = SourceCache::with_sqlite(&db_path).unwrap();
        assert_eq!(cache.len(), 2);
        assert_eq!(
            cache.get("src1").unwrap(),
            serde_json::json!({"key": "value1"})
        );
        assert_eq!(
            cache.get("src2").unwrap(),
            serde_json::json!(["a", "b", "c"])
        );
    }
}

#[test]
fn cache_sqlite_invalidate_persists() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cache.db");

    {
        let cache = SourceCache::with_sqlite(&db_path).unwrap();
        cache.store("src1", &serde_json::json!("data"));
        cache.invalidate("src1");
    }

    {
        let cache = SourceCache::with_sqlite(&db_path).unwrap();
        assert!(cache.get("src1").is_none());
        assert!(cache.is_empty());
    }
}

#[test]
fn cache_ttl_expiration() {
    use std::thread;
    use std::time::Duration;

    let cache = SourceCache::with_ttl(Duration::from_millis(50));
    cache.store("src1", &serde_json::json!("fresh"));

    // Immediately accessible
    assert_eq!(cache.get("src1").unwrap(), serde_json::json!("fresh"));

    // Wait for TTL to expire
    thread::sleep(Duration::from_millis(60));
    assert!(cache.get("src1").is_none());
}

#[test]
fn cache_ttl_evict_expired() {
    use std::thread;
    use std::time::Duration;

    let cache = SourceCache::with_ttl(Duration::from_millis(50));
    cache.store("src1", &serde_json::json!("a"));
    cache.store("src2", &serde_json::json!("b"));

    thread::sleep(Duration::from_millis(60));

    // Entries still in map (len counts all, including expired)
    assert_eq!(cache.len(), 2);

    // Evict removes expired entries
    cache.evict_expired();
    assert!(cache.is_empty());
}

#[test]
fn cache_no_ttl_never_expires() {
    let cache = SourceCache::new();
    cache.store("src1", &serde_json::json!("persistent"));
    assert_eq!(cache.ttl(), None);
    assert_eq!(cache.get("src1").unwrap(), serde_json::json!("persistent"));
}

// =============================================================================
// Security hardening tests
// =============================================================================

#[tokio::test]
async fn command_source_timeout_kills_child() {
    #[cfg(unix)]
    let cmd = vec!["sleep".to_string(), "60".to_string()];
    #[cfg(windows)]
    let cmd = vec![
        "powershell".to_string(),
        "-Command".to_string(),
        "Start-Sleep -Seconds 60".to_string(),
    ];

    let result = rsigma_runtime::sources::command::resolve_command(
        &cmd,
        DataFormat::Json,
        None,
        Some(std::time::Duration::from_millis(100)),
    )
    .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err().kind,
        rsigma_runtime::SourceErrorKind::Timeout
    ));
}

#[tokio::test]
async fn command_source_stdout_size_limit() {
    #[cfg(unix)]
    {
        // Generate more than 100 bytes of stdout with a tiny limit
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            "yes | head -n 200".to_string(),
        ];
        let result = rsigma_runtime::sources::command::resolve_command_with_limit(
            &cmd,
            DataFormat::Lines,
            None,
            Some(std::time::Duration::from_secs(5)),
            100, // 100 byte cap
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().kind,
            rsigma_runtime::SourceErrorKind::ResourceLimit(_)
        ));
    }
}

#[cfg(feature = "nats")]
#[test]
fn nats_payload_size_rejected() {
    let oversized = vec![b'x'; 11 * 1024 * 1024]; // 11 MB
    let result =
        rsigma_runtime::sources::nats::parse_nats_message(&oversized, DataFormat::Json, None);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err().kind,
        rsigma_runtime::SourceErrorKind::ResourceLimit(_)
    ));
}

#[cfg(feature = "nats")]
#[test]
fn nats_payload_within_limit_accepted() {
    let small = br#"{"key": "value"}"#;
    let result = rsigma_runtime::sources::nats::parse_nats_message(small, DataFormat::Json, None);
    assert!(result.is_ok());
}
