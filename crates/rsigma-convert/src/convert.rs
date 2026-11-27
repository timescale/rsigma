use std::collections::HashMap;

use rsigma_eval::pipeline::{Pipeline, apply_pipelines_to_correlation, apply_pipelines_with_state};
use rsigma_parser::{CorrelationRule, SigmaCollection};

use crate::backend::Backend;
use crate::error::{ConvertError, Result};
use crate::output::{ConversionOutput, ConversionResult};

/// Convert a collection of Sigma rules using the given backend and pipelines.
///
/// Merges the collection's filters into the rules they target (see
/// [`rsigma_eval::apply_filters`]), applies each pipeline to every rule, then
/// delegates to the backend for conversion. Errors from individual rules are
/// collected rather than aborting the entire batch.
///
/// For backends that support correlation, a rule-to-table mapping is built from
/// each detection rule's pipeline state and `postgres.table` custom attribute.
/// This mapping is injected into the correlation pipeline state under
/// `_rule_tables` so that temporal correlations can generate multi-table
/// `UNION ALL` queries when referenced rules target different tables.
pub fn convert_collection(
    backend: &dyn Backend,
    collection: &SigmaCollection,
    pipelines: &[Pipeline],
    output_format: &str,
) -> Result<ConversionOutput> {
    if backend.requires_pipeline() && pipelines.is_empty() {
        return Err(ConvertError::PipelineRequired);
    }

    let mut output = ConversionOutput::new();
    let mut rule_table_map: HashMap<String, String> = HashMap::new();
    let mut rule_schema_map: HashMap<String, String> = HashMap::new();
    let mut rule_query_map: HashMap<String, String> = HashMap::new();

    for mut rule in rsigma_eval::apply_filters(collection) {
        let emit_standalone = !backend.supports_correlation()
            || should_emit_standalone(
                rule.id.as_deref(),
                rule.name.as_deref(),
                &collection.correlations,
            );
        let pipeline_state = if !pipelines.is_empty() {
            apply_pipelines_with_state(pipelines, &mut rule)?
        } else {
            Default::default()
        };

        // Record rule → table/schema for multi-table correlation support.
        // custom_attributes["postgres.*"] takes precedence over pipeline state.
        let resolved_table = rule
            .custom_attributes
            .get("postgres.table")
            .and_then(|v| v.as_str())
            .or_else(|| pipeline_state.state.get("table").and_then(|v| v.as_str()));

        if let Some(table) = resolved_table {
            if let Some(id) = &rule.id {
                rule_table_map.insert(id.clone(), table.to_string());
            }
            if let Some(name) = &rule.name {
                rule_table_map.insert(name.clone(), table.to_string());
            }
            rule_table_map.insert(rule.title.clone(), table.to_string());
        }

        let resolved_schema = rule
            .custom_attributes
            .get("postgres.schema")
            .and_then(|v| v.as_str())
            .or_else(|| pipeline_state.state.get("schema").and_then(|v| v.as_str()));

        if let Some(schema) = resolved_schema {
            if let Some(id) = &rule.id {
                rule_schema_map.insert(id.clone(), schema.to_string());
            }
            if let Some(name) = &rule.name {
                rule_schema_map.insert(name.clone(), schema.to_string());
            }
            rule_schema_map.insert(rule.title.clone(), schema.to_string());
        }

        match backend.convert_rule(&rule, output_format, &pipeline_state) {
            Ok(queries) => {
                if let Some(q) = queries.first() {
                    if let Some(id) = &rule.id {
                        rule_query_map.insert(id.clone(), q.clone());
                    }
                    if let Some(name) = &rule.name {
                        rule_query_map.insert(name.clone(), q.clone());
                    }
                    rule_query_map.insert(rule.title.clone(), q.clone());
                }
                if emit_standalone {
                    output.queries.push(ConversionResult {
                        rule_title: rule.title.clone(),
                        rule_id: rule.id.clone(),
                        queries,
                        warnings: Vec::new(),
                    });
                }
            }
            Err(e) => {
                output.errors.push((rule.title.clone(), e));
            }
        }
    }

    if backend.supports_correlation() {
        for corr in &collection.correlations {
            let emit_standalone = should_emit_standalone(
                corr.id.as_deref(),
                corr.name.as_deref(),
                &collection.correlations,
            );
            let mut corr = corr.clone();
            let mut pipeline_state = if !pipelines.is_empty() {
                apply_pipelines_to_correlation(pipelines, &mut corr)?
            } else {
                Default::default()
            };

            if !rule_table_map.is_empty() {
                let map_value = serde_json::to_value(&rule_table_map)
                    .unwrap_or(serde_json::Value::Object(Default::default()));
                pipeline_state.set_state("_rule_tables".to_string(), map_value);
            }
            if !rule_schema_map.is_empty() {
                let map_value = serde_json::to_value(&rule_schema_map)
                    .unwrap_or(serde_json::Value::Object(Default::default()));
                pipeline_state.set_state("_rule_schemas".to_string(), map_value);
            }
            let map_value = serde_json::to_value(&rule_query_map)
                .unwrap_or(serde_json::Value::Object(Default::default()));
            pipeline_state.set_state("_rule_queries".to_string(), map_value);

            let mut warnings = Vec::new();
            match backend.convert_correlation_rule_with_warnings(
                &corr,
                output_format,
                &pipeline_state,
                &mut warnings,
            ) {
                Ok(queries) => {
                    if emit_standalone {
                        output.queries.push(ConversionResult {
                            rule_title: corr.title.clone(),
                            rule_id: corr.id.clone(),
                            queries,
                            warnings,
                        });
                    }
                }
                Err(e) => {
                    output.errors.push((corr.title.clone(), e));
                }
            }
        }
    } else {
        for corr in &collection.correlations {
            output.errors.push((
                corr.title.clone(),
                ConvertError::UnsupportedCorrelation(corr.correlation_type.as_str().into()),
            ));
        }
    }

    Ok(output)
}

/// Whether a detection or correlation rule with this `id` and `name` gets
/// its own query: it is referenced by no correlation, or by at least one
/// correlation with `generate: true`.
fn should_emit_standalone(
    id: Option<&str>,
    name: Option<&str>,
    correlations: &[CorrelationRule],
) -> bool {
    let mut referenced = false;
    for correlation in correlations {
        let matches = correlation
            .rules
            .iter()
            .any(|rule_ref| id == Some(rule_ref.as_str()) || name == Some(rule_ref.as_str()));
        if matches {
            referenced = true;
            if correlation.generate {
                return true;
            }
        }
    }
    !referenced
}

/// True if any dot-segment of a field path is a positional array index
/// (`name[N]`, including a negative `name[-N]`). The quantifier selectors never
/// reach field names (the parser desugars them into `Detection::ArrayMatch`),
/// so a bracketed integer is the positional-index signal.
pub(crate) fn field_has_positional_index(field: &str) -> bool {
    field.split('.').any(|seg| {
        // Only an unescaped trailing `[...]` is a selector; `\[` / `\]` are a
        // literal bracket in the field name, not a positional index.
        let Some(open) = rsigma_parser::fieldpath::first_unescaped(seg, b'[') else {
            return false;
        };
        if !rsigma_parser::fieldpath::ends_with_unescaped(seg, b']') {
            return false;
        }
        let inner = &seg[open + 1..seg.len() - 1];
        let digits = inner.strip_prefix('-').unwrap_or(inner);
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::{convert_collection, field_has_positional_index, should_emit_standalone};
    use crate::backends::postgres::PostgresBackend;
    use crate::backends::test::TextQueryTestBackend;
    use rsigma_eval::pipeline::parse_pipeline;
    use rsigma_parser::parse_sigma_yaml;

    const FILTERED: &str = r#"
title: Whoami
name: whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
---
title: Ping
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ping.exe'
    condition: selection
---
title: Exclude admins
logsource:
    category: process_creation
    product: windows
filter:
    rules: [whoami]
    selection:
        User: admin
    condition: not selection
"#;

    fn test_queries(yaml: &str, pipelines: &[rsigma_eval::Pipeline]) -> Vec<String> {
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert!(
            collection.diagnostics.is_empty(),
            "{:?}",
            collection.diagnostics
        );
        let output = convert_collection(
            &TextQueryTestBackend::new(),
            &collection,
            pipelines,
            "default",
        )
        .unwrap();
        assert!(output.errors.is_empty(), "{:?}", output.errors);
        output
            .queries
            .into_iter()
            .flat_map(|result| result.queries)
            .collect()
    }

    #[test]
    fn filters_apply_to_the_rules_they_reference() {
        assert_eq!(
            test_queries(FILTERED, &[]),
            [
                r#"Image endswith "\whoami.exe" and not User="admin""#,
                r#"Image endswith "\ping.exe""#,
            ]
        );
    }

    #[test]
    fn pipelines_transform_filter_detections() {
        let pipeline = parse_pipeline(
            r#"
name: map user
transformations:
    - type: field_name_mapping
      mapping:
          User: user_name
"#,
        )
        .unwrap();
        assert_eq!(
            test_queries(FILTERED, &[pipeline])[0],
            r#"Image endswith "\whoami.exe" and not user_name="admin""#
        );
    }

    #[test]
    fn correlations_fail_on_a_backend_without_correlation_support() {
        let yaml = r#"
title: Base
name: base
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Count
correlation:
    type: event_count
    rules: [base]
    group-by: [User]
    timespan: 1m
    condition:
        gte: 2
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let output =
            convert_collection(&TextQueryTestBackend::new(), &collection, &[], "default").unwrap();
        assert_eq!(output.queries.len(), 1);
        assert_eq!(output.errors.len(), 1);
        let (title, err) = &output.errors[0];
        assert_eq!(title, "Count");
        assert!(
            matches!(err, crate::ConvertError::UnsupportedCorrelation(t) if t == "event_count"),
            "{err}"
        );
    }

    #[test]
    fn filter_logsource_must_be_contained_in_the_rule() {
        let yaml = FILTERED
            .replace("    rules: [whoami]", "    rules: any")
            .replace(
                "title: Exclude admins\nlogsource:\n    category: process_creation\n    product: windows\n",
                "title: Exclude admins\nlogsource:\n    category: process_creation\n    product: linux\n",
            );
        assert!(yaml.contains("product: linux"));
        assert_eq!(
            test_queries(&yaml, &[]),
            [
                r#"Image endswith "\whoami.exe""#,
                r#"Image endswith "\ping.exe""#,
            ]
        );
    }

    #[test]
    fn positional_index_detection_respects_escaping() {
        assert!(field_has_positional_index("args[0]"));
        assert!(field_has_positional_index("args[-1]"));
        assert!(field_has_positional_index("connections[0].ip"));
        // Escaped brackets are a literal field name, not a positional index.
        assert!(!field_has_positional_index("args\\[0\\]"));
        assert!(!field_has_positional_index("weird\\[x\\]"));
        // Quantifier selectors never reach field names, and plain fields have
        // no index.
        assert!(!field_has_positional_index("process.args"));
    }

    #[test]
    fn referenced_rules_are_standalone_only_when_generate_is_true() {
        let yaml = r#"
title: Base
name: base
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Count
correlation:
    type: event_count
    rules: [base]
    group-by: [User]
    timespan: 1m
    condition:
        gte: 2
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert!(!should_emit_standalone(
            None,
            Some("base"),
            &collection.correlations
        ));

        let mut generated = collection.correlations.clone();
        generated[0].generate = true;
        assert!(should_emit_standalone(None, Some("base"), &generated));
    }

    #[test]
    fn collection_conversion_omits_referenced_rule_by_default() {
        let yaml = r#"
title: Base
name: base
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Count
correlation:
    type: event_count
    rules: [base]
    group-by: [User]
    timespan: 1m
    condition:
        gte: 2
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let output =
            convert_collection(&PostgresBackend::new(), &collection, &[], "default").unwrap();
        let titles: Vec<_> = output
            .queries
            .iter()
            .map(|result| result.rule_title.as_str())
            .collect();
        assert_eq!(titles, ["Count"]);

        let mut generated = collection;
        generated.correlations[0].generate = true;
        let output =
            convert_collection(&PostgresBackend::new(), &generated, &[], "default").unwrap();
        let titles: Vec<_> = output
            .queries
            .iter()
            .map(|result| result.rule_title.as_str())
            .collect();
        assert_eq!(titles, ["Base", "Count"]);
    }

    #[test]
    fn aggregate_correlation_over_a_correlation_is_an_error() {
        let yaml = r#"
title: Base
name: base
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Count
name: count
correlation:
    type: event_count
    rules: [base]
    group-by: [User]
    timespan: 1m
    condition:
        gte: 2
---
title: Bursts
correlation:
    type: event_count
    rules: [count]
    group-by: [User]
    timespan: 1h
    condition:
        gte: 3
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let output =
            convert_collection(&PostgresBackend::new(), &collection, &[], "default").unwrap();
        assert!(output.queries.is_empty(), "{:?}", output.queries);
        let [(title, error)] = output.errors.as_slice() else {
            panic!("expected one error: {:?}", output.errors);
        };
        assert_eq!(title, "Bursts");
        assert!(
            error.to_string().contains("rule reference 'count'"),
            "{error}"
        );
    }
}
