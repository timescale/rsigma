//! Schema-derived logsource pruning must fail open when the classification
//! cannot tell platforms apart: an event whose winning schema ties with a
//! schema that implies a different logsource is evaluated against every rule.

use rsigma_eval::schema::{RoutingPlan, SchemaClassifier, parse_schema_config};
use rsigma_eval::{
    CorrelationConfig, JsonEvent, LogSourceExtractor, MatchDetailLevel, SchemaRouter,
};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

const RULES: &str = r#"
title: Windows whoami
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
---
title: Linux whoami
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
---
title: Any whoami
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#;

fn router_from_config(config_yaml: &str) -> SchemaRouter {
    let (signatures, routing) = parse_schema_config(config_yaml).expect("schema config parses");
    let plan = RoutingPlan::from_config(&routing.unwrap_or_default());
    let sets = plan.pipeline_sets().len();
    let collection = parse_sigma_yaml(RULES).unwrap();
    assert!(
        collection.diagnostics.is_empty(),
        "{:?}",
        collection.diagnostics
    );
    SchemaRouter::build(
        &collection,
        SchemaClassifier::with_user_signatures(signatures),
        plan,
        vec![vec![]; sets],
        CorrelationConfig::default(),
        false,
        MatchDetailLevel::Off,
        Some(LogSourceExtractor::new()),
        false,
    )
    .expect("router builds")
}

fn builtin_router() -> SchemaRouter {
    router_from_config("schemas: []\n")
}

fn titles(router: &mut SchemaRouter, event: &Value) -> (Option<String>, Vec<String>) {
    let routed = router.route(&JsonEvent::borrow(event));
    let mut titles: Vec<String> = routed
        .results
        .iter()
        .map(|r| r.header.rule_title.clone())
        .collect();
    titles.sort();
    (routed.schema, titles)
}

fn owned(titles: &[&str]) -> Vec<String> {
    titles.iter().map(|t| t.to_string()).collect()
}

/// Windows ECS events carry `host.os.kernel` too. That field used to make
/// them tie between `ecs_windows` and `ecs_linux`, and the name tie-break
/// picked Linux, pruning every Windows rule.
#[test]
fn windows_ecs_event_with_kernel_version_evaluates_windows_rules() {
    let mut router = builtin_router();
    let event = json!({
        "ecs": {"version": "8.11.0"},
        "winlog": {"channel": "Security"},
        "host": {"os": {"kernel": "10.0.19045.3803", "type": "windows"}},
        "CommandLine": "cmd /c whoami",
    });
    let (schema, matched) = titles(&mut router, &event);
    assert_eq!(schema.as_deref(), Some("ecs_windows"));
    assert_eq!(matched, owned(&["Any whoami", "Windows whoami"]));
}

/// macOS ECS events carry `host.os.kernel` but are neither Windows nor Linux,
/// so they imply no product and keep every rule.
#[test]
fn macos_ecs_event_implies_no_product() {
    let mut router = builtin_router();
    let event = json!({
        "ecs": {"version": "8.11.0"},
        "host": {"os": {"kernel": "23.1.0", "type": "macos", "family": "darwin"}},
        "CommandLine": "whoami",
    });
    let (schema, matched) = titles(&mut router, &event);
    assert_eq!(schema.as_deref(), Some("ecs"));
    assert_eq!(
        matched,
        owned(&["Any whoami", "Linux whoami", "Windows whoami"])
    );
}

/// An ECS event with markers for both platforms is not attributed to either.
#[test]
fn ecs_event_with_markers_for_two_platforms_implies_no_product() {
    let mut router = builtin_router();
    let event = json!({
        "ecs": {"version": "8.11.0"},
        "winlog": {"channel": "Security"},
        "host": {"os": {"type": "linux"}},
        "CommandLine": "whoami",
    });
    let (schema, matched) = titles(&mut router, &event);
    assert_eq!(schema.as_deref(), Some("ecs"));
    assert_eq!(
        matched,
        owned(&["Any whoami", "Linux whoami", "Windows whoami"])
    );
}

/// Two user signatures that tie at the same specificity and imply different
/// products: the name tie-break must not decide which platform's rules run.
#[test]
fn tied_schemas_with_different_logsources_evaluate_every_rule() {
    let config = r#"
schemas:
  - name: vendor_a
    specificity: 70
    match:
      - field_present: vendor.marker
  - name: vendor_b
    specificity: 70
    match:
      - field_present: vendor.marker
routing:
  bindings:
    - schema: vendor_a
      pipelines: []
      logsource:
        product: windows
    - schema: vendor_b
      pipelines: []
      logsource:
        product: linux
"#;
    let mut router = router_from_config(config);
    let event = json!({"vendor": {"marker": true}, "CommandLine": "whoami"});
    let (schema, matched) = titles(&mut router, &event);
    assert_eq!(schema.as_deref(), Some("vendor_a"));
    assert_eq!(
        matched,
        owned(&["Any whoami", "Linux whoami", "Windows whoami"])
    );
    assert_eq!(router.logsource_ambiguous_total(), 1);
    assert_eq!(router.logsource_pruned_total(), 0);

    // An explicit product on the event is the event's own assertion, so it
    // still prunes.
    let explicit =
        json!({"vendor": {"marker": true}, "CommandLine": "whoami", "product": "windows"});
    let (_, matched) = titles(&mut router, &explicit);
    assert_eq!(matched, owned(&["Any whoami", "Windows whoami"]));
    assert_eq!(router.logsource_ambiguous_total(), 2);

    // Batch routing takes the same path.
    let events = [JsonEvent::borrow(&event)];
    let refs: Vec<&JsonEvent> = events.iter().collect();
    let batch = router.process_batch(&refs);
    assert_eq!(batch[0].len(), 3);
    assert_eq!(router.logsource_ambiguous_total(), 3);
}

/// A tie between schemas that imply the same logsource is harmless, so it
/// prunes as usual and is not counted.
#[test]
fn tied_schemas_with_the_same_logsource_still_prune() {
    let config = r#"
schemas:
  - name: vendor_a
    specificity: 70
    match:
      - field_present: vendor.marker
  - name: vendor_b
    specificity: 70
    match:
      - field_present: vendor.marker
routing:
  bindings:
    - schema: vendor_a
      pipelines: []
      logsource:
        product: windows
    - schema: vendor_b
      pipelines: []
      logsource:
        product: windows
"#;
    let mut router = router_from_config(config);
    let event = json!({"vendor": {"marker": true}, "CommandLine": "whoami"});
    let (_, matched) = titles(&mut router, &event);
    assert_eq!(matched, owned(&["Any whoami", "Windows whoami"]));
    assert_eq!(router.logsource_ambiguous_total(), 0);
    assert_eq!(router.logsource_pruned_total(), 1);
}
