//! Integration tests for `engine eval --logsource-routing`.

mod common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

/// One Linux rule and one Windows rule, both matching `whoami` on content so
/// only the logsource decides which fires.
const RULES: &str = r#"
title: Linux Whoami
id: r-linux
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
---
title: Windows Whoami
id: r-windows
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
"#;

#[test]
fn prunes_conflicting_product() {
    let rule = temp_file(".yml", RULES);
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "--logsource-routing",
            "-e",
            r#"{"CommandLine":"cmd /c whoami","product":"windows"}"#,
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rule_id\":\"r-windows\""))
        .stdout(predicate::str::contains("r-linux").not());
}

#[test]
fn off_by_default_evaluates_every_rule() {
    let rule = temp_file(".yml", RULES);
    // Without --logsource-routing the product tag is ignored, so both rules
    // fire: the feature is zero-behavior-change when off.
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "-e",
            r#"{"CommandLine":"cmd /c whoami","product":"windows"}"#,
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rule_id\":\"r-windows\""))
        .stdout(predicate::str::contains("\"rule_id\":\"r-linux\""));
}

#[test]
fn field_map_remaps_the_product_field() {
    let rule = temp_file(".yml", RULES);
    // The event carries `os` instead of `product`; the field map points the
    // product dimension at it.
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "--logsource-routing",
            "--logsource-field-map",
            "product=os",
            "-e",
            r#"{"CommandLine":"cmd /c whoami","os":"windows"}"#,
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rule_id\":\"r-windows\""))
        .stdout(predicate::str::contains("r-linux").not());
}

#[test]
fn static_event_logsource_prunes_without_a_field() {
    let rule = temp_file(".yml", RULES);
    // The event carries no product field; the static override supplies one.
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "--logsource-routing",
            "--event-logsource",
            "product=windows",
            "-e",
            r#"{"CommandLine":"cmd /c whoami"}"#,
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rule_id\":\"r-windows\""))
        .stdout(predicate::str::contains("r-linux").not());
}

#[test]
fn fails_open_without_an_event_logsource() {
    let rule = temp_file(".yml", RULES);
    // Routing is on but the event has no product field and there is no static
    // override (the ambiguous-format case): pruning fails open, both fire.
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "--logsource-routing",
            "-e",
            r#"{"CommandLine":"cmd /c whoami"}"#,
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rule_id\":\"r-windows\""))
        .stdout(predicate::str::contains("\"rule_id\":\"r-linux\""));
}

#[test]
fn rejects_unknown_field_map_key() {
    let rule = temp_file(".yml", RULES);
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "--logsource-routing",
            "--logsource-field-map",
            "platform=os",
            "-e",
            r#"{"CommandLine":"whoami"}"#,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown logsource key 'platform'"));
}

/// EVTX is a Windows-only format, so `-e @file.evtx` implies `product: windows`
/// when no explicit or static product is configured.
#[cfg(feature = "evtx")]
const EVTX_RULES: &str = r#"
title: EVTX Windows Logon
id: r-evtx-windows
logsource:
    product: windows
detection:
    selection:
        Event.System.EventID: 4624
    condition: selection
level: medium
---
title: EVTX Linux Logon
id: r-evtx-linux
logsource:
    product: linux
detection:
    selection:
        Event.System.EventID: 4624
    condition: selection
level: medium
"#;

#[cfg(feature = "evtx")]
#[test]
fn evtx_input_defaults_product_to_windows() {
    let rule = temp_file(".yml", EVTX_RULES);
    let evtx = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../rsigma-runtime/tests/fixtures/security.evtx"
    );
    let evtx_arg = format!("@{evtx}");

    // Control: without routing both rules match the 4624 events on content.
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "-e",
            &evtx_arg,
            "--output-format",
            "ndjson",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("r-evtx-linux"))
        .stdout(predicate::str::contains("r-evtx-windows"));

    // With routing the EVTX default tags events product: windows, so the linux
    // rule is pruned while the windows rule still fires.
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "--logsource-routing",
            "-e",
            &evtx_arg,
            "--output-format",
            "ndjson",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("r-evtx-windows"))
        .stdout(predicate::str::contains("r-evtx-linux").not());
}

#[test]
fn config_file_enables_routing() {
    let rule = temp_file(".yml", RULES);
    let config = temp_file(".yml", "eval:\n  logsource_routing:\n    enabled: true\n");
    rsigma()
        .args([
            "engine",
            "eval",
            "--config",
            config.path().to_str().unwrap(),
            "-r",
            rule.path().to_str().unwrap(),
            "-e",
            r#"{"CommandLine":"cmd /c whoami","product":"windows"}"#,
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rule_id\":\"r-windows\""))
        .stdout(predicate::str::contains("r-linux").not());
}
