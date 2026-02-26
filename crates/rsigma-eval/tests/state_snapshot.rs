mod helpers;

use helpers::{corr_engine, corr_engine_with_config, process};
use rsigma_eval::{CorrelationConfig, CorrelationEventMode, CorrelationSnapshot};
use serde_json::json;

const EVENT_COUNT_YAML: &str = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
id: many-logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 300s
    condition:
        gte: 3
level: high
"#;

const VALUE_COUNT_YAML: &str = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Sources
id: many-sources
correlation:
    type: value_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 300s
    condition:
        field: SourceIP
        gte: 3
level: high
"#;

const TEMPORAL_YAML: &str = r#"
title: Recon
id: recon-rule
logsource:
    category: network
detection:
    selection:
        EventType: recon
    condition: selection
---
title: Exploit
id: exploit-rule
logsource:
    category: network
detection:
    selection:
        EventType: exploit
    condition: selection
---
title: Recon Then Exploit
id: recon-exploit
correlation:
    type: temporal
    rules:
        - recon-rule
        - exploit-rule
    group-by:
        - Host
    timespan: 120s
    condition:
        gte: 2
level: critical
"#;

fn login_event(user: &str) -> serde_json::Value {
    json!({"EventType": "login", "User": user})
}

fn login_event_with_ip(user: &str, ip: &str) -> serde_json::Value {
    json!({"EventType": "login", "User": user, "SourceIP": ip})
}

// =============================================================================
// Snapshot round-trip serialization
// =============================================================================

#[test]
fn snapshot_empty_engine_exports_empty() {
    let engine = corr_engine(EVENT_COUNT_YAML);
    let snapshot = engine.export_state();
    assert!(snapshot.windows.is_empty());
    assert!(snapshot.last_alert.is_empty());
    assert!(snapshot.event_buffers.is_empty());
    assert!(snapshot.event_ref_buffers.is_empty());
}

#[test]
fn snapshot_json_round_trip() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    process(&mut engine, login_event("admin"), 1000);
    process(&mut engine, login_event("admin"), 1001);

    let snapshot = engine.export_state();
    let json = serde_json::to_string(&snapshot).unwrap();
    let restored: CorrelationSnapshot = serde_json::from_str(&json).unwrap();

    assert_eq!(snapshot.windows.len(), restored.windows.len());
    for (corr_id, entries) in &snapshot.windows {
        let restored_entries = restored.windows.get(corr_id).unwrap();
        assert_eq!(entries.len(), restored_entries.len());
    }
}

#[test]
fn snapshot_uses_stable_ids_not_indices() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    process(&mut engine, login_event("admin"), 1000);

    let snapshot = engine.export_state();
    assert!(
        snapshot.windows.contains_key("many-logins"),
        "snapshot should use correlation id as key, got: {:?}",
        snapshot.windows.keys().collect::<Vec<_>>()
    );
}

// =============================================================================
// Export → import preserves state
// =============================================================================

#[test]
fn export_import_preserves_event_count_state() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    // Feed 2 events (below threshold of 3)
    process(&mut engine, login_event("admin"), 1000);
    process(&mut engine, login_event("admin"), 1001);
    assert_eq!(engine.state_count(), 1);

    let snapshot = engine.export_state();

    // Create a fresh engine and import the snapshot
    let mut engine2 = corr_engine(EVENT_COUNT_YAML);
    assert_eq!(engine2.state_count(), 0);
    engine2.import_state(snapshot);
    assert_eq!(engine2.state_count(), 1);

    // One more event should trigger the correlation (2 restored + 1 new = 3)
    let result = process(&mut engine2, login_event("admin"), 1002);
    assert_eq!(
        result.correlations.len(),
        1,
        "correlation should fire with restored state + new event"
    );
    assert_eq!(result.correlations[0].aggregated_value, 3.0);
}

#[test]
fn export_import_preserves_value_count_state() {
    let mut engine = corr_engine(VALUE_COUNT_YAML);
    process(&mut engine, login_event_with_ip("admin", "10.0.0.1"), 1000);
    process(&mut engine, login_event_with_ip("admin", "10.0.0.2"), 1001);

    let snapshot = engine.export_state();
    let mut engine2 = corr_engine(VALUE_COUNT_YAML);
    engine2.import_state(snapshot);

    // Third distinct SourceIP should trigger value_count >= 3
    let result = process(&mut engine2, login_event_with_ip("admin", "10.0.0.3"), 1002);
    assert_eq!(result.correlations.len(), 1);
    assert_eq!(result.correlations[0].aggregated_value, 3.0);
}

#[test]
fn export_import_preserves_temporal_state() {
    let mut engine = corr_engine(TEMPORAL_YAML);
    process(
        &mut engine,
        json!({"EventType": "recon", "Host": "srv1"}),
        1000,
    );

    let snapshot = engine.export_state();
    let mut engine2 = corr_engine(TEMPORAL_YAML);
    engine2.import_state(snapshot);

    // Exploit after recon should trigger temporal correlation
    let result = process(
        &mut engine2,
        json!({"EventType": "exploit", "Host": "srv1"}),
        1010,
    );
    assert_eq!(
        result.correlations.len(),
        1,
        "temporal correlation should fire with restored recon + new exploit"
    );
}

#[test]
fn export_import_preserves_multiple_groups() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    process(&mut engine, login_event("admin"), 1000);
    process(&mut engine, login_event("admin"), 1001);
    process(&mut engine, login_event("bob"), 1000);
    assert_eq!(engine.state_count(), 2);

    let snapshot = engine.export_state();
    let mut engine2 = corr_engine(EVENT_COUNT_YAML);
    engine2.import_state(snapshot);
    assert_eq!(engine2.state_count(), 2);

    // admin: 2 restored + 1 = 3 → fires
    let r = process(&mut engine2, login_event("admin"), 1002);
    assert_eq!(r.correlations.len(), 1);

    // bob: 1 restored + 1 = 2 → doesn't fire
    let r = process(&mut engine2, login_event("bob"), 1002);
    assert!(r.correlations.is_empty());
}

// =============================================================================
// Suppression state persistence
// =============================================================================

#[test]
fn export_import_preserves_suppression_state() {
    let config = CorrelationConfig {
        suppress: Some(60),
        ..CorrelationConfig::default()
    };
    let mut engine = corr_engine_with_config(EVENT_COUNT_YAML, config.clone());

    // Trigger correlation
    for i in 0..3 {
        process(&mut engine, login_event("admin"), 1000 + i);
    }
    // Should be suppressed now
    let r = process(&mut engine, login_event("admin"), 1004);
    assert!(r.correlations.is_empty(), "should be suppressed");

    let snapshot = engine.export_state();
    assert!(
        !snapshot.last_alert.is_empty(),
        "last_alert should be populated"
    );

    let mut engine2 = corr_engine_with_config(EVENT_COUNT_YAML, config);
    engine2.import_state(snapshot);

    // Should still be suppressed in the restored engine (within 60s window)
    for i in 0..3 {
        process(&mut engine2, login_event("admin"), 1010 + i);
    }
    let r = process(&mut engine2, login_event("admin"), 1013);
    assert!(
        r.correlations.is_empty(),
        "suppression should survive restore"
    );
}

// =============================================================================
// Event buffer persistence
// =============================================================================

#[test]
fn export_import_preserves_event_buffers_full_mode() {
    let config = CorrelationConfig {
        correlation_event_mode: CorrelationEventMode::Full,
        max_correlation_events: 10,
        ..CorrelationConfig::default()
    };
    let mut engine = corr_engine_with_config(EVENT_COUNT_YAML, config.clone());

    process(&mut engine, login_event("admin"), 1000);
    process(&mut engine, login_event("admin"), 1001);

    let snapshot = engine.export_state();
    assert!(
        !snapshot.event_buffers.is_empty(),
        "event_buffers should be populated in Full mode"
    );

    // Serialize and deserialize the snapshot (simulates SQLite round-trip)
    let json = serde_json::to_string(&snapshot).unwrap();
    let restored: CorrelationSnapshot = serde_json::from_str(&json).unwrap();

    let mut engine2 = corr_engine_with_config(EVENT_COUNT_YAML, config);
    engine2.import_state(restored);

    // Third event triggers correlation with events from buffer
    let r = process(&mut engine2, login_event("admin"), 1002);
    assert_eq!(r.correlations.len(), 1);
    assert!(
        r.correlations[0].events.is_some(),
        "events should be included from restored buffer"
    );
}

#[test]
fn export_import_preserves_event_ref_buffers() {
    let config = CorrelationConfig {
        correlation_event_mode: CorrelationEventMode::Refs,
        max_correlation_events: 10,
        ..CorrelationConfig::default()
    };
    let mut engine = corr_engine_with_config(EVENT_COUNT_YAML, config.clone());

    process(&mut engine, login_event("admin"), 1000);
    process(&mut engine, login_event("admin"), 1001);

    let snapshot = engine.export_state();
    assert!(
        !snapshot.event_ref_buffers.is_empty(),
        "event_ref_buffers should be populated in Refs mode"
    );

    let json = serde_json::to_string(&snapshot).unwrap();
    let restored: CorrelationSnapshot = serde_json::from_str(&json).unwrap();

    let mut engine2 = corr_engine_with_config(EVENT_COUNT_YAML, config);
    engine2.import_state(restored);

    let r = process(&mut engine2, login_event("admin"), 1002);
    assert_eq!(r.correlations.len(), 1);
    assert!(
        r.correlations[0].event_refs.is_some(),
        "event_refs should be included from restored buffer"
    );
}

// =============================================================================
// Edge cases
// =============================================================================

#[test]
fn import_drops_unknown_correlation_ids() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    process(&mut engine, login_event("admin"), 1000);

    let mut snapshot = engine.export_state();
    // Rename the correlation id to something that doesn't exist
    let entries = snapshot.windows.remove("many-logins").unwrap();
    snapshot
        .windows
        .insert("nonexistent-rule".to_string(), entries);

    let mut engine2 = corr_engine(EVENT_COUNT_YAML);
    engine2.import_state(snapshot);
    assert_eq!(
        engine2.state_count(),
        0,
        "unknown correlation ids should be dropped"
    );
}

#[test]
fn import_into_empty_engine_is_noop() {
    let yaml = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
"#;
    // Engine with only detection rules, no correlations
    let mut engine = corr_engine(yaml);
    let snapshot = CorrelationSnapshot {
        windows: Default::default(),
        last_alert: Default::default(),
        event_buffers: Default::default(),
        event_ref_buffers: Default::default(),
    };
    engine.import_state(snapshot);
    assert_eq!(engine.state_count(), 0);
}

#[test]
fn expired_state_not_restored_after_window() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    process(&mut engine, login_event("admin"), 1000);
    process(&mut engine, login_event("admin"), 1001);

    let snapshot = engine.export_state();

    let mut engine2 = corr_engine(EVENT_COUNT_YAML);
    engine2.import_state(snapshot);

    // Process event far in the future (past the 300s window)
    // The restored timestamps (1000, 1001) should be evicted
    let r = process(&mut engine2, login_event("admin"), 2000);
    assert!(
        r.correlations.is_empty(),
        "old restored events should be evicted by the time window"
    );
}
