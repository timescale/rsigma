//! E2E tests for `engine daemon --cross-rule-ac`.

#![cfg(all(feature = "daemon", feature = "daachorse-index"))]

use crate::common;

use common::{DaemonProcess, http_get, poll_until, temp_file};
use std::fmt::Write as _;
use std::time::Duration;

/// One rule with more distinct `CommandLine` needles than the cross-rule
/// automaton indexes per field.
fn over_cap_rule() -> String {
    let mut yaml = String::from(
        "title: Huge IOC List\nid: r-huge\nlogsource:\n    category: test\ndetection:\n    selection:\n        CommandLine|contains:\n",
    );
    for i in 0..=100_000 {
        writeln!(yaml, "            - 'ioc-{i:06}'").unwrap();
    }
    yaml.push_str("    condition: selection\n");
    yaml
}

/// The gauge reports the field left without an automaton, and the flag
/// reaches the per-schema engines when schema routing is on.
#[test]
fn unindexed_field_gauge_reports_routed_engines() {
    let rule = temp_file(".yml", &over_cap_rule());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--cross-rule-ac", "--schema-routing"],
    );
    let metrics = poll_until(Duration::from_secs(10), || {
        let (status, body) = http_get(&daemon.url("/metrics"));
        (status == 200 && body.contains("rsigma_cross_rule_ac_unindexed_fields 1")).then_some(body)
    });
    assert!(
        metrics.is_some(),
        "expected rsigma_cross_rule_ac_unindexed_fields to report the over-cap field"
    );
}

/// Without `--cross-rule-ac` there is no index, so nothing is unindexed.
#[test]
fn unindexed_field_gauge_is_zero_without_the_prefilter() {
    let rule = temp_file(".yml", &over_cap_rule());
    let daemon = DaemonProcess::spawn_http_with_args(rule.path().to_str().unwrap(), &[]);
    let (status, body) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
    assert!(
        body.contains("rsigma_cross_rule_ac_unindexed_fields 0"),
        "gauge missing or non-zero"
    );
}
