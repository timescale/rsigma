//! Correlation windows and suppression stay correct when events carry
//! out-of-range or out-of-order timestamps.

mod helpers;

use helpers::{corr_engine, corr_engine_with_config, process};
use rsigma_eval::{
    CorrelationAction, CorrelationConfig, CorrelationEngine, CorrelationSnapshot, JsonEvent,
    ProcessResultExt,
};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

/// 9999-12-31T23:59:59Z.
const YEAR_9999: i64 = 253_402_300_799;

fn wall_clock() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A timestamp an hour in the past, aligned to a minute so tumbling buckets
/// line up with the offsets the tests use.
fn recent_base() -> i64 {
    let t = wall_clock() - 3600;
    t - t.rem_euclid(60)
}

fn yaml(correlation_type: &str, window: &str, condition: &str) -> String {
    format!(
        r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Logins
id: logins
correlation:
    type: {correlation_type}
    rules:
        - login-rule
    group-by:
        - User
{window}
    condition:
{condition}
level: high
"#
    )
}

fn login(user: &str) -> serde_json::Value {
    json!({"EventType": "login", "User": user})
}

fn group_entries(engine: &CorrelationEngine) -> usize {
    engine.introspect().groups.iter().map(|g| g.entries).sum()
}

// =============================================================================
// Future timestamps
// =============================================================================

#[test]
fn sliding_far_future_event_does_not_pin_the_window() {
    // 60s sliding window, one event every 3s: about 21 events in any window,
    // so the gte-25 threshold is never met by current traffic.
    let mut engine = corr_engine(&yaml("event_count", "    timespan: 60s", "        gte: 25"));
    let r = process(&mut engine, login("admin"), YEAR_9999);
    assert_eq!(r.correlation_count(), 0);
    assert_eq!(engine.future_skipped(), 1);

    let base = recent_base();
    let mut fired = 0;
    for i in 0..60 {
        fired += process(&mut engine, login("admin"), base + i * 3).correlation_count();
        assert!(
            group_entries(&engine) <= 21,
            "the group must hold only the last 60s of events"
        );
    }
    assert_eq!(fired, 0);
}

#[test]
fn far_future_event_through_a_timestamp_field_is_skipped() {
    let mut engine = corr_engine(&yaml("event_count", "    timespan: 60s", "        gte: 1"));
    let v = json!({"EventType": "login", "User": "admin", "@timestamp": "9999-12-31T23:59:59Z"});
    let r = engine.process_event(&JsonEvent::borrow(&v));
    assert_eq!(
        r.detection_count(),
        0,
        "correlation-only output stays hidden"
    );
    assert_eq!(r.correlation_count(), 0);
    assert_eq!(engine.state_count(), 0);
    assert_eq!(engine.future_skipped(), 1);
    assert_eq!(engine.take_future_skipped(), 1);
    assert_eq!(engine.future_skipped(), 0);
}

#[test]
fn skew_within_the_bound_is_clamped_to_the_wall_clock() {
    let mut engine = corr_engine(&yaml("event_count", "    timespan: 60s", "        gte: 1"));
    let before = wall_clock();
    process(&mut engine, login("admin"), before + 120);
    let after = wall_clock();
    assert_eq!(engine.future_skipped(), 0);
    let latest = engine.introspect().groups[0].latest.unwrap();
    assert!(
        (before..=after).contains(&latest),
        "{latest} not clamped to [{before}, {after}]"
    );
}

#[test]
fn max_future_skew_is_configurable() {
    let config = CorrelationConfig {
        max_future_skew: 3600,
        ..Default::default()
    };
    let mut engine = corr_engine_with_config(
        &yaml("event_count", "    timespan: 60s", "        gte: 1"),
        config,
    );
    let r = process(&mut engine, login("admin"), wall_clock() + 1800);
    assert_eq!(r.correlation_count(), 1);
    let r = process(&mut engine, login("admin"), wall_clock() + 7200);
    assert_eq!(r.correlation_count(), 0);
    assert_eq!(engine.future_skipped(), 1);
}

#[test]
fn tumbling_far_future_event_does_not_make_current_events_late() {
    let mut engine = corr_engine(&yaml(
        "event_count",
        "    timespan: 60s\n    window: tumbling",
        "        gte: 3",
    ));
    process(&mut engine, login("admin"), YEAR_9999);
    let base = recent_base();
    process(&mut engine, login("admin"), base + 1);
    process(&mut engine, login("admin"), base + 2);
    let r = process(&mut engine, login("admin"), base + 3);
    assert_eq!(r.correlation_count(), 1);
}

#[test]
fn session_far_future_event_does_not_hold_the_session_open() {
    let mut engine = corr_engine(&yaml(
        "event_count",
        "    window: session\n    gap: 10s\n    timespan: 1h",
        "        gte: 3",
    ));
    let base = recent_base();
    process(&mut engine, login("admin"), base);
    process(&mut engine, login("admin"), YEAR_9999);
    process(&mut engine, login("admin"), base + 5);
    // A 30s gap closes the session even though a far-future event arrived.
    let r = process(&mut engine, login("admin"), base + 35);
    assert_eq!(r.correlation_count(), 0);
}

// =============================================================================
// Out-of-order timestamps
// =============================================================================

#[test]
fn sliding_eviction_does_not_depend_on_arrival_order() {
    let mut engine = corr_engine(&yaml("event_count", "    timespan: 60s", "        gte: 3"));
    process(&mut engine, login("admin"), 1000);
    process(&mut engine, login("admin"), 1050);
    // Late, but inside the window that ends at 1050.
    process(&mut engine, login("admin"), 995);
    // The window ending at 1100 holds only 1050 and 1100.
    let r = process(&mut engine, login("admin"), 1100);
    assert_eq!(r.correlation_count(), 0);
    assert_eq!(group_entries(&engine), 2);
}

#[test]
fn sliding_event_older_than_the_window_is_discarded() {
    let mut engine = corr_engine(&yaml("event_count", "    timespan: 60s", "        gte: 2"));
    process(&mut engine, login("admin"), 2000);
    let r = process(&mut engine, login("admin"), 1000);
    assert_eq!(r.correlation_count(), 0);
    assert_eq!(group_entries(&engine), 1);
}

#[test]
fn temporal_does_not_match_hits_outside_the_timespan() {
    let yaml = r#"
title: Recon
id: recon
logsource:
    category: test
detection:
    selection:
        action: recon
    condition: selection
---
title: Exploit
id: exploit
logsource:
    category: test
detection:
    selection:
        action: exploit
    condition: selection
---
title: Recon Then Exploit
correlation:
    type: temporal
    rules:
        - recon
        - exploit
    group-by:
        - Host
    timespan: 60s
level: high
"#;
    for window in ["", "    window: session\n    gap: 60s\n"] {
        let yaml = yaml.replace(
            "    timespan: 60s\n",
            &format!("{window}    timespan: 60s\n"),
        );
        let mut engine = corr_engine(&yaml);
        process(&mut engine, json!({"action": "exploit", "Host": "h"}), 2000);
        // The recon hit is 1000s before the exploit hit.
        let r = process(&mut engine, json!({"action": "recon", "Host": "h"}), 1000);
        assert_eq!(r.correlation_count(), 0, "window: {window:?}");
    }
}

#[test]
fn tumbling_out_of_order_event_in_the_bucket_counts() {
    let mut engine = corr_engine(&yaml(
        "event_count",
        "    timespan: 60s\n    window: tumbling",
        "        gte: 3",
    ));
    process(&mut engine, login("admin"), 1230);
    process(&mut engine, login("admin"), 1210);
    // Still the [1200, 1260) bucket: the earlier arrival did not move it.
    let r = process(&mut engine, login("admin"), 1250);
    assert_eq!(r.correlation_count(), 1);
}

#[test]
fn session_stale_events_do_not_reset_an_active_session() {
    let mut engine = corr_engine(&yaml(
        "event_count",
        "    window: session\n    gap: 30s\n    timespan: 120s",
        "        gte: 4",
    ));
    process(&mut engine, login("admin"), 1000);
    process(&mut engine, login("admin"), 1020);
    process(&mut engine, login("admin"), 1040);
    // An event from long before the session started belongs to a closed
    // session. It must neither restart this one nor become its new start.
    let r = process(&mut engine, login("admin"), 500);
    assert_eq!(r.correlation_count(), 0);
    let r = process(&mut engine, login("admin"), 1060);
    assert_eq!(r.correlation_count(), 1);
}

#[test]
fn session_stale_events_do_not_make_it_look_idle() {
    let mut engine = corr_engine(&yaml(
        "event_count",
        "    window: session\n    gap: 30s\n    timespan: 1h",
        "        gte: 3",
    ));
    process(&mut engine, login("admin"), 1050);
    process(&mut engine, login("admin"), 1080);
    process(&mut engine, login("admin"), 1100);
    // A late event inside the session must not move its latest activity back.
    process(&mut engine, login("admin"), 1090);
    // 25s after the newest event, within the 30s gap.
    engine.evict_expired(1125);
    assert_eq!(engine.state_count(), 1, "the session is still active");
    let groups = engine.introspect().groups;
    assert_eq!(groups[0].latest, Some(1100));
}

// =============================================================================
// Suppression
// =============================================================================

fn suppressed_engine(yaml: &str) -> CorrelationEngine {
    corr_engine_with_config(
        yaml,
        CorrelationConfig {
            suppress: Some(60),
            ..Default::default()
        },
    )
}

#[test]
fn suppression_recovers_after_a_far_future_alert() {
    let mut engine = suppressed_engine(&yaml("event_count", "    timespan: 60s", "        gte: 1"));
    let r = process(&mut engine, login("admin"), YEAR_9999);
    assert_eq!(r.correlation_count(), 0);

    let base = recent_base();
    assert_eq!(
        process(&mut engine, login("admin"), base).correlation_count(),
        1
    );
    assert_eq!(
        process(&mut engine, login("admin"), base + 10).correlation_count(),
        0
    );
    assert_eq!(
        process(&mut engine, login("admin"), base + 61).correlation_count(),
        1
    );
}

const CHAINED_YAML: &str = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Logins
id: logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 1
---
title: Repeated Logins
id: repeated-logins
correlation:
    type: event_count
    rules:
        - logins
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 1
level: high
"#;

fn fired_ids(r: &[rsigma_eval::EvaluationResult]) -> Vec<String> {
    r.correlations()
        .filter_map(|c| c.header.rule_id.clone())
        .collect()
}

#[test]
fn chained_suppression_recovers_after_a_far_future_alert() {
    let mut engine = suppressed_engine(CHAINED_YAML);
    let r = process(&mut engine, login("admin"), YEAR_9999);
    assert!(fired_ids(&r).is_empty());

    let base = recent_base();
    let r = process(&mut engine, login("admin"), base);
    assert!(fired_ids(&r).contains(&"repeated-logins".to_string()));
    let r = process(&mut engine, login("admin"), base + 10);
    assert!(!fired_ids(&r).contains(&"repeated-logins".to_string()));
    let r = process(&mut engine, login("admin"), base + 61);
    assert!(fired_ids(&r).contains(&"repeated-logins".to_string()));
}

#[test]
fn suppression_is_measured_on_the_group_time_not_a_late_event() {
    // A late event that fires must not open a suppression window that ends
    // earlier than one measured from the group's newest event.
    let mut engine = corr_engine_with_config(
        &yaml("event_count", "    timespan: 300s", "        gte: 2"),
        CorrelationConfig {
            suppress: Some(60),
            ..Default::default()
        },
    );
    process(&mut engine, login("admin"), 1100);
    // Late event: fires with the group at 1100.
    let r = process(&mut engine, login("admin"), 1050);
    assert_eq!(r.correlation_count(), 1);
    // 1150 is 50s after the group's newest event when the alert fired.
    let r = process(&mut engine, login("admin"), 1150);
    assert_eq!(r.correlation_count(), 0);
    let r = process(&mut engine, login("admin"), 1161);
    assert_eq!(r.correlation_count(), 1);
}

#[test]
fn chained_suppression_is_measured_on_the_group_time() {
    // Per-user logins feed a per-host parent, so each user's child alert is
    // its own first alert while the parent sees every one of them.
    let yaml = CHAINED_YAML
        .replacen("        - User\n", "        - User\n        - Host\n", 1)
        .replace(
            "        - User\n    timespan: 60s\n    condition:\n        gte: 1\nlevel: high",
            "        - Host\n    timespan: 300s\n    condition:\n        gte: 2\nlevel: high",
        );
    let mut engine = suppressed_engine(&yaml);
    let host_login = |user: &str| json!({"EventType": "login", "User": user, "Host": "h"});
    let r = process(&mut engine, host_login("alice"), 1100);
    assert!(!fired_ids(&r).contains(&"repeated-logins".to_string()));
    // Late child alert: the parent fires with its group at 1100.
    let r = process(&mut engine, host_login("bob"), 1050);
    assert!(fired_ids(&r).contains(&"repeated-logins".to_string()));
    // 50s after the parent group's newest event when it fired.
    let r = process(&mut engine, host_login("carol"), 1150);
    assert!(!fired_ids(&r).contains(&"repeated-logins".to_string()));
    let r = process(&mut engine, host_login("dave"), 1161);
    assert!(fired_ids(&r).contains(&"repeated-logins".to_string()));
}

#[test]
fn reset_then_late_events_after_an_alert_do_not_stay_suppressed() {
    // With `action: reset` the window empties after an alert. Events older
    // than the alert then carry an earlier group time, which counts as an
    // expired suppression rather than one that never ends.
    let mut engine = corr_engine_with_config(
        &yaml("event_count", "    timespan: 300s", "        gte: 1"),
        CorrelationConfig {
            suppress: Some(60),
            action_on_match: CorrelationAction::Reset,
            ..Default::default()
        },
    );
    assert_eq!(
        process(&mut engine, login("admin"), 2000).correlation_count(),
        1
    );
    assert_eq!(
        process(&mut engine, login("admin"), 1990).correlation_count(),
        1
    );
}

// =============================================================================
// Restored state
// =============================================================================

#[test]
fn restored_far_future_state_is_dropped() {
    let yaml = yaml("event_count", "    timespan: 60s", "        gte: 2");
    let mut engine = corr_engine_with_config(
        &yaml,
        CorrelationConfig {
            suppress: Some(60),
            ..Default::default()
        },
    );
    let snapshot: CorrelationSnapshot = serde_json::from_value(json!({
        "version": 1,
        "windows": {"logins": [
            [["admin"], {"EventCount": {"timestamps": [YEAR_9999, 1000]}}],
            [["bob"], {"EventCount": {"timestamps": [YEAR_9999]}}],
        ]},
        "last_alert": {"logins": [[["admin"], YEAR_9999]]},
    }))
    .unwrap();
    let stats = engine.import_state_detailed(snapshot).unwrap();
    assert_eq!(stats.restored, 1);
    assert_eq!(stats.discarded_future, 1, "bob's window held only 9999");
    let groups = engine.introspect().groups;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].latest, Some(1000));
    assert_eq!(groups[0].last_alert, None);

    // The restored entry at 1000 and a current one: the alert is not
    // suppressed by the restored far-future alert.
    let r = process(&mut engine, login("admin"), 1030);
    assert_eq!(r.correlation_count(), 1);
}

#[test]
fn restored_out_of_order_state_is_sorted() {
    let yaml = yaml("event_count", "    timespan: 60s", "        gte: 3");
    let mut engine = corr_engine(&yaml);
    let snapshot: CorrelationSnapshot = serde_json::from_value(json!({
        "version": 1,
        "windows": {"logins": [[["admin"], {"EventCount": {"timestamps": [1050, 900, 1040]}}]]},
    }))
    .unwrap();
    engine.import_state(snapshot);
    // The window ending at 1060 holds 1040, 1050, and 1060; 900 is evicted.
    let r = process(&mut engine, login("admin"), 1060);
    assert_eq!(r.correlation_count(), 1);
    assert_eq!(group_entries(&engine), 3);
}

// =============================================================================
// Default per-group cap
// =============================================================================

#[test]
fn default_group_cap_bounds_a_long_window() {
    let mut engine = corr_engine(&yaml("event_count", "    timespan: 30d", "        gte: 50"));
    for i in 0..12_000 {
        process(&mut engine, login("admin"), 1000 + i);
    }
    assert_eq!(group_entries(&engine), 10_000);
}

#[test]
fn default_group_cap_rises_to_fit_a_count_threshold() {
    let collection = parse_sigma_yaml(&yaml(
        "event_count",
        "    timespan: 30d",
        "        gte: 12000",
    ))
    .unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();
    let mut fired = 0;
    for i in 0..12_000 {
        fired += process(&mut engine, login("admin"), 1000 + i).correlation_count();
    }
    assert_eq!(fired, 1, "the 12,000th event meets the threshold");
}
