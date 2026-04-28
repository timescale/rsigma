use std::collections::HashMap;

use rsigma_eval::pipeline::{Pipeline, apply_pipelines_to_correlation, apply_pipelines_with_state};
use rsigma_parser::SigmaCollection;

use crate::backend::Backend;
use crate::error::{ConvertError, Result};
use crate::output::{ConversionOutput, ConversionResult};
use crate::state::ConversionState;

/// Convert a collection of Sigma rules using the given backend and pipelines.
///
/// Applies each pipeline to every rule, then delegates to the backend for
/// conversion. Errors from individual rules are collected rather than aborting
/// the entire batch.
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

    for rule in &collection.rules {
        let mut rule = rule.clone();
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
            rule_schema_map.insert(rule.title.clone(), schema.to_string());
        }

        match backend.convert_rule(&rule, output_format, &pipeline_state) {
            Ok(queries) => {
                if let Some(q) = queries.first() {
                    if let Some(id) = &rule.id {
                        rule_query_map.insert(id.clone(), q.clone());
                    }
                    rule_query_map.insert(rule.title.clone(), q.clone());
                }
                output.queries.push(ConversionResult {
                    rule_title: rule.title.clone(),
                    rule_id: rule.id.clone(),
                    queries,
                });
            }
            Err(e) => {
                output.errors.push((rule.title.clone(), e));
            }
        }
    }

    if backend.supports_correlation() {
        for corr in &collection.correlations {
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
            if !rule_query_map.is_empty() {
                let map_value = serde_json::to_value(&rule_query_map)
                    .unwrap_or(serde_json::Value::Object(Default::default()));
                pipeline_state.set_state("_rule_queries".to_string(), map_value);
            }

            match backend.convert_correlation_rule(&corr, output_format, &pipeline_state) {
                Ok(queries) => {
                    output.queries.push(ConversionResult {
                        rule_title: corr.title.clone(),
                        rule_id: corr.id.clone(),
                        queries,
                    });
                }
                Err(e) => {
                    output.errors.push((corr.title.clone(), e));
                }
            }
        }
    }

    Ok(output)
}

/// Default detection-item dispatch logic.
///
/// Used by backends that don't need custom item-level handling.
pub fn default_convert_detection_item(
    backend: &dyn Backend,
    item: &rsigma_parser::DetectionItem,
    state: &mut ConversionState,
) -> Result<String> {
    let field_name = item
        .field
        .name
        .as_deref()
        .ok_or(ConvertError::MissingFieldName)?;
    let modifiers = &item.field.modifiers;

    if item.field.has_modifier(rsigma_parser::Modifier::Exists) {
        let expect = match item.values.first() {
            Some(rsigma_parser::SigmaValue::Bool(b)) => *b,
            _ => true,
        };
        return backend.convert_field_exists(field_name, expect, state);
    }

    if item.field.has_modifier(rsigma_parser::Modifier::FieldRef) {
        let ref_field = match item.values.first() {
            Some(rsigma_parser::SigmaValue::String(s)) => {
                s.as_plain().unwrap_or_else(|| s.original.clone())
            }
            _ => {
                return Err(ConvertError::UnsupportedValue(
                    "fieldref requires string".into(),
                ));
            }
        };
        return match backend.convert_field_ref(field_name, &ref_field, state)? {
            crate::state::ConvertResult::Query(q) => Ok(q),
            crate::state::ConvertResult::Deferred(d) => {
                state.add_deferred(d);
                Ok(String::new())
            }
        };
    }

    if item.field.has_modifier(rsigma_parser::Modifier::Re) {
        let pattern = match item.values.first() {
            Some(rsigma_parser::SigmaValue::String(s)) => s.original.clone(),
            _ => return Err(ConvertError::UnsupportedValue("re requires string".into())),
        };
        return match backend.convert_field_eq_re(field_name, &pattern, modifiers, state)? {
            crate::state::ConvertResult::Query(q) => Ok(q),
            crate::state::ConvertResult::Deferred(d) => {
                state.add_deferred(d);
                Ok(String::new())
            }
        };
    }

    if item.field.has_modifier(rsigma_parser::Modifier::Cidr) {
        let cidr_str = match item.values.first() {
            Some(rsigma_parser::SigmaValue::String(s)) => s.original.clone(),
            _ => {
                return Err(ConvertError::UnsupportedValue(
                    "cidr requires string".into(),
                ));
            }
        };
        return match backend.convert_field_eq_cidr(field_name, &cidr_str, state)? {
            crate::state::ConvertResult::Query(q) => Ok(q),
            crate::state::ConvertResult::Deferred(d) => {
                state.add_deferred(d);
                Ok(String::new())
            }
        };
    }

    for m in [
        rsigma_parser::Modifier::Gt,
        rsigma_parser::Modifier::Gte,
        rsigma_parser::Modifier::Lt,
        rsigma_parser::Modifier::Lte,
    ] {
        if item.field.has_modifier(m) {
            let num = match item.values.first() {
                Some(rsigma_parser::SigmaValue::Integer(n)) => *n as f64,
                Some(rsigma_parser::SigmaValue::Float(f)) => *f,
                _ => {
                    return Err(ConvertError::UnsupportedValue(
                        "comparison requires number".into(),
                    ));
                }
            };
            return backend.convert_field_compare(field_name, &m, num, state);
        }
    }

    let use_all = item.field.has_modifier(rsigma_parser::Modifier::All);

    let value_parts: Vec<String> = item
        .values
        .iter()
        .map(|v| match v {
            rsigma_parser::SigmaValue::String(s) => {
                match backend.convert_field_eq_str(field_name, s, modifiers, state)? {
                    crate::state::ConvertResult::Query(q) => Ok(q),
                    crate::state::ConvertResult::Deferred(d) => {
                        state.add_deferred(d);
                        Ok(String::new())
                    }
                }
            }
            rsigma_parser::SigmaValue::Integer(n) => {
                backend.convert_field_eq_num(field_name, *n as f64, state)
            }
            rsigma_parser::SigmaValue::Float(f) => {
                backend.convert_field_eq_num(field_name, *f, state)
            }
            rsigma_parser::SigmaValue::Bool(b) => {
                backend.convert_field_eq_bool(field_name, *b, state)
            }
            rsigma_parser::SigmaValue::Null => backend.convert_field_eq_null(field_name, state),
        })
        .collect::<Result<Vec<_>>>()?;

    // Filter out empty strings from deferred results
    let value_parts: Vec<String> = value_parts.into_iter().filter(|s| !s.is_empty()).collect();

    if value_parts.is_empty() {
        return Ok(String::new());
    }

    if value_parts.len() == 1 {
        Ok(value_parts.into_iter().next().unwrap())
    } else if use_all {
        backend.convert_condition_and(&value_parts)
    } else {
        backend.convert_condition_or(&value_parts)
    }
}

/// Default detection dispatch logic.
///
/// Used by backends that don't need custom detection-level handling.
pub fn default_convert_detection(
    backend: &dyn Backend,
    det: &rsigma_parser::Detection,
    state: &mut ConversionState,
) -> Result<String> {
    match det {
        rsigma_parser::Detection::AllOf(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|item| backend.convert_detection_item(item, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_and(&parts)
        }
        rsigma_parser::Detection::AnyOf(dets) => {
            let parts: Vec<String> = dets
                .iter()
                .map(|d| backend.convert_detection(d, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_or(&parts)
        }
        rsigma_parser::Detection::Keywords(values) => {
            let parts: Vec<String> = values
                .iter()
                .map(|v| backend.convert_keyword(v, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_or(&parts)
        }
    }
}
