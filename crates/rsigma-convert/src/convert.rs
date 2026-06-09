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

/// True if any dot-segment of a field path is a positional array index
/// (`name[N]`, including a negative `name[-N]`). The quantifier selectors never
/// reach field names (the parser desugars them into `Detection::ArrayMatch`),
/// so a bracketed integer is the positional-index signal.
fn field_has_positional_index(field: &str) -> bool {
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

/// Modifiers whose semantics cannot be expressed by the generic
/// [`default_convert_detection_item`] dispatch.
///
/// The default path emits string or number equality. Any modifier that
/// changes the comparison operator (`neq` → `!=`), transforms the value
/// before comparison (`base64`, `base64offset`, `wide`, `utf16`, `utf16be`,
/// `windash`, `expand`), or needs a backend-specific extraction such as
/// `date_part` (timestamp parts) or a regex flag without `re` (`m`, `s`)
/// would be silently dropped by the generic dispatch, producing a query
/// with different semantics than the rule. Backends that handle these
/// modifiers natively should override [`Backend::convert_detection_item`]
/// and bypass the default dispatch.
const DEFAULT_PATH_UNSUPPORTED_MODIFIERS: &[rsigma_parser::Modifier] = &[
    rsigma_parser::Modifier::Neq,
    rsigma_parser::Modifier::Base64,
    rsigma_parser::Modifier::Base64Offset,
    rsigma_parser::Modifier::Wide,
    rsigma_parser::Modifier::Utf16,
    rsigma_parser::Modifier::Utf16be,
    rsigma_parser::Modifier::WindAsh,
    rsigma_parser::Modifier::Expand,
    rsigma_parser::Modifier::Multiline,
    rsigma_parser::Modifier::DotAll,
    rsigma_parser::Modifier::Minute,
    rsigma_parser::Modifier::Hour,
    rsigma_parser::Modifier::Day,
    rsigma_parser::Modifier::Week,
    rsigma_parser::Modifier::Month,
    rsigma_parser::Modifier::Year,
];

fn first_unsupported_default_modifier(
    modifiers: &[rsigma_parser::Modifier],
) -> Option<rsigma_parser::Modifier> {
    DEFAULT_PATH_UNSUPPORTED_MODIFIERS
        .iter()
        .copied()
        .find(|m| modifiers.contains(m))
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

    // A positional array index (`field[N]`) reaches conversion as part of the
    // field path. Backends that cannot lower it must fail loudly rather than
    // emit a literal field reference that diverges from the evaluator's
    // element-N semantics.
    if field_has_positional_index(field_name) && !backend.supports_field_index() {
        return Err(ConvertError::UnsupportedArrayMatching);
    }

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
        return convert_multi_value_re(backend, item, field_name, modifiers, state);
    }

    if item.field.has_modifier(rsigma_parser::Modifier::Cidr) {
        return convert_multi_value_cidr(backend, item, field_name, state);
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

    // The fall-through dispatch below emits string/number equality through
    // `convert_field_eq_str` / `convert_field_eq_num`. Any modifier that
    // changes the operator (`neq`), transforms the value (encoding,
    // `windash`), or requires backend-specific extraction (timestamp parts,
    // `expand`) cannot be expressed by that path. Reaching this point with
    // such a modifier means the generic path would silently produce a query
    // with different semantics than the rule. Reject those modifiers loudly
    // so backends without explicit support do not ship semantically wrong
    // SQL/SPL. Backends that handle these modifiers natively can override
    // `Backend::convert_detection_item` and bypass the default dispatch.
    if let Some(unsupported) = first_unsupported_default_modifier(modifiers) {
        return Err(ConvertError::UnsupportedModifier(format!(
            "{unsupported:?}"
        )));
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

/// Handle `field|re: [<pat1>, <pat2>, ...]` by lowering each pattern
/// through the backend's `convert_field_eq_re` hook and combining the
/// results with `or` (`|all`: `and`). The single-value case keeps the
/// original semantics (one direct call). All values must be strings;
/// non-string values produce `UnsupportedValue`. Deferred results are
/// queued in the conversion state and contribute an empty
/// placeholder, matching the equality fall-through's contract.
fn convert_multi_value_re(
    backend: &dyn Backend,
    item: &rsigma_parser::DetectionItem,
    field_name: &str,
    modifiers: &[rsigma_parser::Modifier],
    state: &mut ConversionState,
) -> Result<String> {
    let use_all = item.field.has_modifier(rsigma_parser::Modifier::All);
    let mut parts: Vec<String> = Vec::with_capacity(item.values.len());
    for value in &item.values {
        let pattern = match value {
            rsigma_parser::SigmaValue::String(s) => s.original.clone(),
            _ => return Err(ConvertError::UnsupportedValue("re requires string".into())),
        };
        match backend.convert_field_eq_re(field_name, &pattern, modifiers, state)? {
            crate::state::ConvertResult::Query(q) => {
                if !q.is_empty() {
                    parts.push(q);
                }
            }
            crate::state::ConvertResult::Deferred(d) => {
                state.add_deferred(d);
            }
        }
    }
    if parts.is_empty() {
        return Ok(String::new());
    }
    if parts.len() == 1 {
        return Ok(parts.into_iter().next().unwrap());
    }
    if use_all {
        backend.convert_condition_and(&parts)
    } else {
        backend.convert_condition_or(&parts)
    }
}

/// Handle `field|cidr: [<a/n>, <b/m>, ...]` analogously to
/// `convert_multi_value_re`: each CIDR is lowered through the
/// backend's `convert_field_eq_cidr` hook and the resulting predicates
/// are OR-joined (`|all`: AND-joined). Single-value input keeps the
/// existing one-call semantics so backends with custom rendering for
/// a single CIDR (`field::inet <<= 'value'::cidr` for PostgreSQL,
/// `cidr_contains(field, '...')` for Fibratus) emit the same string
/// they did before this generalization.
fn convert_multi_value_cidr(
    backend: &dyn Backend,
    item: &rsigma_parser::DetectionItem,
    field_name: &str,
    state: &mut ConversionState,
) -> Result<String> {
    let use_all = item.field.has_modifier(rsigma_parser::Modifier::All);
    let mut parts: Vec<String> = Vec::with_capacity(item.values.len());
    for value in &item.values {
        let cidr_str = match value {
            rsigma_parser::SigmaValue::String(s) => s.original.clone(),
            _ => {
                return Err(ConvertError::UnsupportedValue(
                    "cidr requires string".into(),
                ));
            }
        };
        match backend.convert_field_eq_cidr(field_name, &cidr_str, state)? {
            crate::state::ConvertResult::Query(q) => {
                if !q.is_empty() {
                    parts.push(q);
                }
            }
            crate::state::ConvertResult::Deferred(d) => {
                state.add_deferred(d);
            }
        }
    }
    if parts.is_empty() {
        return Ok(String::new());
    }
    if parts.len() == 1 {
        return Ok(parts.into_iter().next().unwrap());
    }
    if use_all {
        backend.convert_condition_and(&parts)
    } else {
        backend.convert_condition_or(&parts)
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
        // Array object-scope matching: dispatch to the backend hook (which
        // fails loudly by default and is overridden by backends that can
        // express member quantification, e.g. PostgreSQL JSONB).
        rsigma_parser::Detection::ArrayMatch {
            field,
            quantifier,
            body,
        } => backend.convert_array_match(field, *quantifier, body, state),
        // AND of heterogeneous sub-detections (a mapping mixing plain items
        // with array object-scope blocks).
        rsigma_parser::Detection::And(dets) => {
            let parts: Vec<String> = dets
                .iter()
                .map(|d| backend.convert_detection(d, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_and(&parts)
        }
        // Extended array block body: lower each named sub-selection, then fold
        // them per the `condition` (and/or/not). Reached when a backend's
        // `convert_array_match` recurses into a `condition:` block body
        // relative to the per-element binding.
        rsigma_parser::Detection::Conditional { named, condition } => {
            convert_block_condition(backend, condition, named, state)
        }
    }
}

/// Lower an extended array block-body `condition` into a single boolean
/// expression by converting each referenced named sub-selection and combining
/// them with the backend's `and`/`or`/`not` (and selector expansion).
fn convert_block_condition(
    backend: &dyn Backend,
    expr: &rsigma_parser::ConditionExpr,
    named: &std::collections::HashMap<String, rsigma_parser::Detection>,
    state: &mut ConversionState,
) -> Result<String> {
    use rsigma_parser::{ConditionExpr, Quantifier};
    match expr {
        ConditionExpr::Identifier(name) => {
            let det = named
                .get(name)
                .ok_or_else(|| ConvertError::InvalidIdentifier(name.clone()))?;
            backend.convert_detection(det, state)
        }
        ConditionExpr::And(exprs) => {
            // Parenthesize OR sub-expressions: SQL `AND` binds tighter than
            // `OR`, so `a AND (b OR c)` must keep the OR grouped.
            let parts = exprs
                .iter()
                .map(|e| {
                    let sql = convert_block_condition(backend, e, named, state)?;
                    Ok(if matches!(e, ConditionExpr::Or(_)) {
                        format!("({sql})")
                    } else {
                        sql
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_and(&parts)
        }
        ConditionExpr::Or(exprs) => {
            let parts = exprs
                .iter()
                .map(|e| convert_block_condition(backend, e, named, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_or(&parts)
        }
        ConditionExpr::Not(inner) => {
            let part = convert_block_condition(backend, inner, named, state)?;
            // Parenthesize: SQL `NOT` binds looser than the inner comparison
            // operators, so a bare multi-token operand would mis-associate.
            backend.convert_condition_not(&format!("({part})"))
        }
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let mut names: Vec<&String> = named
                .keys()
                .filter(|n| pattern.matches_detection_name(n))
                .collect();
            names.sort();
            let parts = names
                .iter()
                .map(|n| backend.convert_detection(&named[*n], state))
                .collect::<Result<Vec<_>>>()?;
            match quantifier {
                Quantifier::Any => backend.convert_condition_or(&parts),
                Quantifier::All => backend.convert_condition_and(&parts),
                Quantifier::Count(_) => Err(ConvertError::UnsupportedArrayMatching),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::field_has_positional_index;

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
}
