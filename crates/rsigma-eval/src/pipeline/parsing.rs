use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use regex::Regex;
use rsigma_parser::{SigmaString, SigmaValue};

use crate::error::{EvalError, Result};

use super::conditions::{
    DetectionItemCondition, FieldMatcher, FieldNameCondition, NamedRuleCondition, RuleCondition,
};
use super::finalizers::Finalizer;
use super::sources::{
    DataFormat, DynamicSource, ErrorPolicy, RefLocation, RefreshPolicy, SourceRef, SourceType,
};
use super::transformations::Transformation;
use super::{Pipeline, TransformationItem};

// =============================================================================
// YAML parsing
// =============================================================================

/// Parse a pipeline from a YAML string.
pub fn parse_pipeline(yaml: &str) -> Result<Pipeline> {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml)
        .map_err(|e| EvalError::InvalidModifiers(format!("pipeline YAML parse error: {e}")))?;
    parse_pipeline_value(&value)
}

/// Parse a pipeline from a YAML file.
pub fn parse_pipeline_file(path: &Path) -> Result<Pipeline> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| EvalError::InvalidModifiers(format!("cannot read pipeline file: {e}")))?;
    parse_pipeline(&content)
}

/// Parse a pipeline from a `serde_yaml::Value`.
fn parse_pipeline_value(value: &serde_yaml::Value) -> Result<Pipeline> {
    let obj = value.as_mapping().ok_or_else(|| {
        EvalError::InvalidModifiers("pipeline YAML must be a mapping".to_string())
    })?;

    let name = obj
        .get(ykey("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed")
        .to_string();

    let priority = obj
        .get(ykey("priority"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as i32;

    let vars = parse_vars(obj.get(ykey("vars")));

    let transformations = if let Some(items) = obj.get(ykey("transformations")) {
        parse_transformation_items(items)?
    } else {
        Vec::new()
    };

    let finalizers = if let Some(items) = obj.get(ykey("finalizers")) {
        parse_finalizers(items)
    } else {
        Vec::new()
    };

    let sources = if let Some(items) = obj.get(ykey("sources")) {
        parse_sources(items)?
    } else {
        Vec::new()
    };

    let source_refs = scan_source_refs(obj);

    validate_source_refs(&sources, &source_refs)?;

    Ok(Pipeline {
        name,
        priority,
        vars,
        transformations,
        finalizers,
        sources,
        source_refs,
    })
}

fn ykey(s: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(s.to_string())
}

fn parse_vars(value: Option<&serde_yaml::Value>) -> HashMap<String, Vec<String>> {
    let mut vars = HashMap::new();
    if let Some(serde_yaml::Value::Mapping(m)) = value {
        for (k, v) in m {
            if let Some(key) = k.as_str() {
                let values = match v {
                    serde_yaml::Value::Sequence(seq) => seq
                        .iter()
                        .filter_map(|item| item.as_str().map(String::from))
                        .collect(),
                    serde_yaml::Value::String(s) => vec![s.clone()],
                    _ => Vec::new(),
                };
                vars.insert(key.to_string(), values);
            }
        }
    }
    vars
}

fn parse_transformation_items(value: &serde_yaml::Value) -> Result<Vec<TransformationItem>> {
    let items = value.as_sequence().ok_or_else(|| {
        EvalError::InvalidModifiers("transformations must be a sequence".to_string())
    })?;

    items.iter().map(parse_transformation_item).collect()
}

fn parse_transformation_item(value: &serde_yaml::Value) -> Result<TransformationItem> {
    let obj = value.as_mapping().ok_or_else(|| {
        EvalError::InvalidModifiers("transformation item must be a mapping".to_string())
    })?;

    let id = obj
        .get(ykey("id"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Handle `include` directives as a special transformation type
    let transformation = if let Some(include_val) = obj.get(ykey("include")) {
        let template = include_val.as_str().unwrap_or("").to_string();
        Transformation::Include { template }
    } else {
        parse_transformation(obj)?
    };

    let rule_conditions = if let Some(conds) = obj.get(ykey("rule_conditions")) {
        parse_rule_conditions(conds)?
    } else {
        Vec::new()
    };

    let rule_cond_expr = obj
        .get(ykey("rule_cond_expression"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let detection_item_conditions = if let Some(conds) = obj.get(ykey("detection_item_conditions"))
    {
        parse_detection_item_conditions(conds)?
    } else {
        Vec::new()
    };

    let field_name_conditions = if let Some(conds) = obj.get(ykey("field_name_conditions")) {
        parse_field_name_conditions(conds)?
    } else {
        Vec::new()
    };

    let field_name_cond_not = obj
        .get(ykey("field_name_cond_not"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(TransformationItem {
        id,
        transformation,
        rule_conditions,
        rule_cond_expr,
        detection_item_conditions,
        field_name_conditions,
        field_name_cond_not,
    })
}

fn parse_transformation(obj: &serde_yaml::Mapping) -> Result<Transformation> {
    let type_str = obj
        .get(ykey("type"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            EvalError::InvalidModifiers("transformation must have a 'type' field".to_string())
        })?;

    match type_str {
        "field_name_mapping" => {
            let mapping = parse_string_or_list_mapping(obj.get(ykey("mapping")))?;
            Ok(Transformation::FieldNameMapping { mapping })
        }

        "field_name_prefix_mapping" => {
            let mapping = parse_string_mapping(obj.get(ykey("mapping")))?;
            Ok(Transformation::FieldNamePrefixMapping { mapping })
        }

        "field_name_prefix" => {
            let prefix = obj
                .get(ykey("prefix"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Transformation::FieldNamePrefix { prefix })
        }

        "field_name_suffix" => {
            let suffix = obj
                .get(ykey("suffix"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Transformation::FieldNameSuffix { suffix })
        }

        "drop_detection_item" => Ok(Transformation::DropDetectionItem),

        "add_condition" => {
            let conditions = parse_value_mapping(obj.get(ykey("conditions")))?;
            let negated = obj
                .get(ykey("negated"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(Transformation::AddCondition {
                conditions,
                negated,
            })
        }

        "change_logsource" => {
            let category = obj
                .get(ykey("category"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let product = obj
                .get(ykey("product"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let service = obj
                .get(ykey("service"))
                .and_then(|v| v.as_str())
                .map(String::from);
            Ok(Transformation::ChangeLogsource {
                category,
                product,
                service,
            })
        }

        "replace_string" => {
            let regex = obj
                .get(ykey("regex"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let replacement = obj
                .get(ykey("replacement"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let skip_special = obj
                .get(ykey("skip_special"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(Transformation::ReplaceString {
                regex,
                replacement,
                skip_special,
            })
        }

        "value_placeholders" => Ok(Transformation::ValuePlaceholders),

        "wildcard_placeholders" => Ok(Transformation::WildcardPlaceholders),

        "query_expression_placeholders" => {
            let expression = obj
                .get(ykey("expression"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Transformation::QueryExpressionPlaceholders { expression })
        }

        "set_state" => {
            let key = obj
                .get(ykey("key"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let value = obj
                .get(ykey("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Transformation::SetState { key, value })
        }

        "rule_failure" => {
            let message = obj
                .get(ykey("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("rule failure")
                .to_string();
            Ok(Transformation::RuleFailure { message })
        }

        "detection_item_failure" => {
            let message = obj
                .get(ykey("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("detection item failure")
                .to_string();
            Ok(Transformation::DetectionItemFailure { message })
        }

        "field_name_transform" => {
            let transform_func = obj
                .get(ykey("transform_func"))
                .and_then(|v| v.as_str())
                .unwrap_or("lower")
                .to_string();
            let mapping = parse_string_mapping(obj.get(ykey("mapping"))).unwrap_or_default();
            Ok(Transformation::FieldNameTransform {
                transform_func,
                mapping,
            })
        }

        "hashes_fields" => {
            let valid_hash_algos = parse_string_list(obj.get(ykey("valid_hash_algos")));
            let field_prefix = obj
                .get(ykey("field_prefix"))
                .and_then(|v| v.as_str())
                .unwrap_or("File")
                .to_string();
            let drop_algo_prefix = obj
                .get(ykey("drop_algo_prefix"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(Transformation::HashesFields {
                valid_hash_algos,
                field_prefix,
                drop_algo_prefix,
            })
        }

        "map_string" => {
            let mapping = parse_string_or_list_mapping(obj.get(ykey("mapping")))?;
            Ok(Transformation::MapString { mapping })
        }

        "set_value" => {
            let value = obj
                .get(ykey("value"))
                .map(SigmaValue::from_yaml)
                .unwrap_or(SigmaValue::Null);
            Ok(Transformation::SetValue { value })
        }

        "convert_type" => {
            let target_type = obj
                .get(ykey("target_type"))
                .and_then(|v| v.as_str())
                .unwrap_or("str")
                .to_string();
            Ok(Transformation::ConvertType { target_type })
        }

        "regex" => Ok(Transformation::Regex),

        "add_field" => {
            let field = obj
                .get(ykey("field"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Transformation::AddField { field })
        }

        "remove_field" => {
            let field = obj
                .get(ykey("field"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Transformation::RemoveField { field })
        }

        "set_field" => {
            let fields = parse_string_list(obj.get(ykey("fields")));
            Ok(Transformation::SetField { fields })
        }

        "set_custom_attribute" => {
            let attribute = obj
                .get(ykey("attribute"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let value = obj
                .get(ykey("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Transformation::SetCustomAttribute { attribute, value })
        }

        "case_transformation" | "case" => {
            let case_type = obj
                .get(ykey("case_type"))
                .or_else(|| obj.get(ykey("case")))
                .and_then(|v| v.as_str())
                .unwrap_or("lower")
                .to_string();
            Ok(Transformation::CaseTransformation { case_type })
        }

        "nest" => {
            let items_yaml = obj
                .get(ykey("items"))
                .or_else(|| obj.get(ykey("transformations")));
            let items = if let Some(serde_yaml::Value::Sequence(seq)) = items_yaml {
                let mut parsed = Vec::new();
                for entry in seq {
                    parsed.push(parse_transformation_item(entry)?);
                }
                parsed
            } else {
                Vec::new()
            };
            Ok(Transformation::Nest { items })
        }

        other => Err(EvalError::InvalidModifiers(format!(
            "unknown transformation type: {other}"
        ))),
    }
}

// =============================================================================
// Condition YAML parsing
// =============================================================================

fn parse_rule_conditions(value: &serde_yaml::Value) -> Result<Vec<NamedRuleCondition>> {
    let items = value.as_sequence().ok_or_else(|| {
        EvalError::InvalidModifiers("rule_conditions must be a sequence".to_string())
    })?;

    items.iter().map(parse_rule_condition).collect()
}

fn parse_rule_condition(value: &serde_yaml::Value) -> Result<NamedRuleCondition> {
    let obj = value.as_mapping().ok_or_else(|| {
        EvalError::InvalidModifiers("rule condition must be a mapping".to_string())
    })?;

    let cond_id = obj
        .get(ykey("id"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let type_str = obj
        .get(ykey("type"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            EvalError::InvalidModifiers("rule condition must have a 'type' field".to_string())
        })?;

    let condition = match type_str {
        "logsource" => {
            let category = obj
                .get(ykey("category"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let product = obj
                .get(ykey("product"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let service = obj
                .get(ykey("service"))
                .and_then(|v| v.as_str())
                .map(String::from);
            Ok(RuleCondition::Logsource {
                category,
                product,
                service,
            })
        }

        "contains_detection_item" => {
            let field = obj
                .get(ykey("field"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let value = obj
                .get(ykey("value"))
                .and_then(|v| v.as_str())
                .map(String::from);
            Ok(RuleCondition::ContainsDetectionItem { field, value })
        }

        "processing_item_applied" => {
            let id = obj
                .get(ykey("processing_item_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(RuleCondition::ProcessingItemApplied {
                processing_item_id: id,
            })
        }

        "processing_state" => {
            let key = obj
                .get(ykey("key"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let val = obj
                .get(ykey("val"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(RuleCondition::ProcessingState { key, val })
        }

        "is_sigma_rule" => Ok(RuleCondition::IsSigmaRule),
        "is_sigma_correlation_rule" => Ok(RuleCondition::IsSigmaCorrelationRule),

        "rule_attribute" => {
            let attribute = obj
                .get(ykey("attribute"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let value = obj
                .get(ykey("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(RuleCondition::RuleAttribute { attribute, value })
        }

        "tag" => {
            let tag = obj
                .get(ykey("tag"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(RuleCondition::Tag { tag })
        }

        other => Err(EvalError::InvalidModifiers(format!(
            "unknown rule condition type: {other}"
        ))),
    }?;

    Ok(NamedRuleCondition {
        id: cond_id,
        condition,
    })
}

fn parse_detection_item_conditions(
    value: &serde_yaml::Value,
) -> Result<Vec<DetectionItemCondition>> {
    let items = value.as_sequence().ok_or_else(|| {
        EvalError::InvalidModifiers("detection_item_conditions must be a sequence".to_string())
    })?;

    items.iter().map(parse_detection_item_condition).collect()
}

fn parse_detection_item_condition(value: &serde_yaml::Value) -> Result<DetectionItemCondition> {
    let obj = value.as_mapping().ok_or_else(|| {
        EvalError::InvalidModifiers("detection item condition must be a mapping".to_string())
    })?;

    let type_str = obj
        .get(ykey("type"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            EvalError::InvalidModifiers(
                "detection item condition must have a 'type' field".to_string(),
            )
        })?;

    match type_str {
        "match_string" => {
            let pattern = obj
                .get(ykey("pattern"))
                .and_then(|v| v.as_str())
                .unwrap_or(".*")
                .to_string();
            let negate = obj
                .get(ykey("negate"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let regex = Regex::new(&pattern).map_err(|e| {
                EvalError::InvalidModifiers(format!("invalid match_string regex '{pattern}': {e}"))
            })?;
            Ok(DetectionItemCondition::MatchString { regex, negate })
        }

        "is_null" => {
            let negate = obj
                .get(ykey("negate"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(DetectionItemCondition::IsNull { negate })
        }

        "processing_item_applied" => {
            let id = obj
                .get(ykey("processing_item_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(DetectionItemCondition::ProcessingItemApplied {
                processing_item_id: id,
            })
        }

        "processing_state" => {
            let key = obj
                .get(ykey("key"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let val = obj
                .get(ykey("val"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(DetectionItemCondition::ProcessingState { key, val })
        }

        other => Err(EvalError::InvalidModifiers(format!(
            "unknown detection item condition type: {other}"
        ))),
    }
}

fn parse_field_name_conditions(value: &serde_yaml::Value) -> Result<Vec<FieldNameCondition>> {
    let items = value.as_sequence().ok_or_else(|| {
        EvalError::InvalidModifiers("field_name_conditions must be a sequence".to_string())
    })?;

    items.iter().map(parse_field_name_condition).collect()
}

fn parse_field_name_condition(value: &serde_yaml::Value) -> Result<FieldNameCondition> {
    let obj = value.as_mapping().ok_or_else(|| {
        EvalError::InvalidModifiers("field name condition must be a mapping".to_string())
    })?;

    let type_str = obj
        .get(ykey("type"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            EvalError::InvalidModifiers("field name condition must have a 'type' field".to_string())
        })?;

    let match_type_str = obj
        .get(ykey("match_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("plain");

    let is_regex = matches!(match_type_str, "regex" | "re");

    match type_str {
        "include_fields" => {
            let fields = parse_string_list(obj.get(ykey("fields")));
            let matcher = build_field_matcher(fields, is_regex)?;
            Ok(FieldNameCondition::IncludeFields { matcher })
        }

        "exclude_fields" => {
            let fields = parse_string_list(obj.get(ykey("fields")));
            let matcher = build_field_matcher(fields, is_regex)?;
            Ok(FieldNameCondition::ExcludeFields { matcher })
        }

        "processing_item_applied" => {
            let id = obj
                .get(ykey("processing_item_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(FieldNameCondition::ProcessingItemApplied {
                processing_item_id: id,
            })
        }

        "processing_state" => {
            let key = obj
                .get(ykey("key"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let val = obj
                .get(ykey("val"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(FieldNameCondition::ProcessingState { key, val })
        }

        other => Err(EvalError::InvalidModifiers(format!(
            "unknown field name condition type: {other}"
        ))),
    }
}

// =============================================================================
// YAML parsing helpers
// =============================================================================

fn parse_string_mapping(value: Option<&serde_yaml::Value>) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    if let Some(serde_yaml::Value::Mapping(m)) = value {
        for (k, v) in m {
            if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
                map.insert(key.to_string(), val.to_string());
            }
        }
    }
    Ok(map)
}

/// Parse a mapping where values can be either a single string or a list of strings.
///
/// Supports pySigma-compatible one-to-many mapping:
/// ```yaml
/// mapping:
///   foo: bar          # 1:1
///   baz:              # 1:many
///     - qux
///     - quux
/// ```
fn parse_string_or_list_mapping(
    value: Option<&serde_yaml::Value>,
) -> Result<HashMap<String, Vec<String>>> {
    let mut map = HashMap::new();
    if let Some(serde_yaml::Value::Mapping(m)) = value {
        for (k, v) in m {
            if let Some(key) = k.as_str() {
                let values = match v {
                    serde_yaml::Value::String(s) => vec![s.clone()],
                    serde_yaml::Value::Sequence(seq) => {
                        let mut strings = Vec::with_capacity(seq.len());
                        for item in seq {
                            if let Some(s) = item.as_str() {
                                strings.push(s.to_string());
                            } else {
                                log::warn!(
                                    "non-string item in mapping list for key '{}': {:?}; skipping",
                                    key,
                                    item,
                                );
                            }
                        }
                        strings
                    }
                    _ => continue,
                };
                if !values.is_empty() {
                    map.insert(key.to_string(), values);
                }
            }
        }
    }
    Ok(map)
}

fn parse_value_mapping(value: Option<&serde_yaml::Value>) -> Result<HashMap<String, SigmaValue>> {
    let mut map = HashMap::new();
    if let Some(serde_yaml::Value::Mapping(m)) = value {
        for (k, v) in m {
            if let Some(key) = k.as_str() {
                let sv = match v {
                    serde_yaml::Value::String(s) => SigmaValue::String(SigmaString::new(s)),
                    serde_yaml::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            SigmaValue::Integer(i)
                        } else if let Some(f) = n.as_f64() {
                            SigmaValue::Float(f)
                        } else {
                            SigmaValue::Null
                        }
                    }
                    serde_yaml::Value::Bool(b) => SigmaValue::Bool(*b),
                    serde_yaml::Value::Null => SigmaValue::Null,
                    _ => SigmaValue::Null,
                };
                map.insert(key.to_string(), sv);
            }
        }
    }
    Ok(map)
}

fn build_field_matcher(fields: Vec<String>, is_regex: bool) -> Result<FieldMatcher> {
    if is_regex {
        let regexes = fields
            .iter()
            .map(|p| {
                Regex::new(p).map_err(|e| {
                    EvalError::InvalidModifiers(format!("invalid field regex '{p}': {e}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(FieldMatcher::Regex(regexes))
    } else {
        Ok(FieldMatcher::Plain(fields))
    }
}

fn parse_string_list(value: Option<&serde_yaml::Value>) -> Vec<String> {
    match value {
        Some(serde_yaml::Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|item| item.as_str().map(String::from))
            .collect(),
        Some(serde_yaml::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn parse_finalizers(value: &serde_yaml::Value) -> Vec<Finalizer> {
    if let Some(seq) = value.as_sequence() {
        seq.iter().filter_map(Finalizer::from_yaml).collect()
    } else {
        Vec::new()
    }
}

// =============================================================================
// Dynamic source parsing
// =============================================================================

/// Parse the `sources` section of a pipeline YAML.
fn parse_sources(value: &serde_yaml::Value) -> Result<Vec<DynamicSource>> {
    let items = value
        .as_sequence()
        .ok_or_else(|| EvalError::InvalidModifiers("sources must be a sequence".to_string()))?;

    items.iter().map(parse_dynamic_source).collect()
}

/// Parse a single dynamic source declaration.
fn parse_dynamic_source(value: &serde_yaml::Value) -> Result<DynamicSource> {
    let obj = value
        .as_mapping()
        .ok_or_else(|| EvalError::InvalidModifiers("source must be a mapping".to_string()))?;

    let id = obj
        .get(ykey("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| EvalError::InvalidModifiers("source must have an 'id' field".to_string()))?
        .to_string();

    let type_str = obj
        .get(ykey("type"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            EvalError::InvalidModifiers(format!("source '{id}' must have a 'type' field"))
        })?;

    let format = parse_data_format(obj.get(ykey("format")));
    let extract = obj
        .get(ykey("extract"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let source_type = match type_str {
        "http" => {
            let url = obj
                .get(ykey("url"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    EvalError::InvalidModifiers(format!(
                        "source '{id}' of type 'http' must have a 'url' field"
                    ))
                })?
                .to_string();
            let method = obj
                .get(ykey("method"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let headers = parse_string_headers(obj.get(ykey("headers")));
            SourceType::Http {
                url,
                method,
                headers,
                format,
                extract,
            }
        }
        "command" => {
            let command = parse_command_field(obj.get(ykey("command")))?;
            if command.is_empty() {
                return Err(EvalError::InvalidModifiers(format!(
                    "source '{id}' of type 'command' must have a non-empty 'command' field"
                )));
            }
            SourceType::Command {
                command,
                format,
                extract,
            }
        }
        "file" => {
            let path = obj
                .get(ykey("path"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    EvalError::InvalidModifiers(format!(
                        "source '{id}' of type 'file' must have a 'path' field"
                    ))
                })?;
            SourceType::File {
                path: PathBuf::from(path),
                format,
            }
        }
        "nats" => {
            let url = obj
                .get(ykey("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let subject = obj
                .get(ykey("subject"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    EvalError::InvalidModifiers(format!(
                        "source '{id}' of type 'nats' must have a 'subject' field"
                    ))
                })?
                .to_string();
            SourceType::Nats {
                url,
                subject,
                format,
                extract,
            }
        }
        other => {
            return Err(EvalError::InvalidModifiers(format!(
                "source '{id}' has unknown type: '{other}'"
            )));
        }
    };

    let refresh = parse_refresh_policy(obj.get(ykey("refresh")));
    let timeout = parse_duration_field(obj.get(ykey("timeout")));
    let on_error = parse_error_policy(obj.get(ykey("on_error")));
    let required = obj
        .get(ykey("required"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let default = obj.get(ykey("default")).cloned();

    Ok(DynamicSource {
        id,
        source_type,
        refresh,
        timeout,
        on_error,
        required,
        default,
    })
}

fn parse_data_format(value: Option<&serde_yaml::Value>) -> DataFormat {
    match value.and_then(|v| v.as_str()) {
        Some("json") => DataFormat::Json,
        Some("yaml" | "yml") => DataFormat::Yaml,
        Some("lines") => DataFormat::Lines,
        Some("csv") => DataFormat::Csv,
        _ => DataFormat::Json,
    }
}

fn parse_refresh_policy(value: Option<&serde_yaml::Value>) -> RefreshPolicy {
    match value.and_then(|v| v.as_str()) {
        Some("once") => RefreshPolicy::Once,
        Some("watch") => RefreshPolicy::Watch,
        Some("push") => RefreshPolicy::Push,
        Some("on_demand") => RefreshPolicy::OnDemand,
        Some(s) => {
            if let Some(dur) = parse_duration_str(s) {
                RefreshPolicy::Interval(dur)
            } else {
                RefreshPolicy::Once
            }
        }
        None => RefreshPolicy::Once,
    }
}

fn parse_error_policy(value: Option<&serde_yaml::Value>) -> ErrorPolicy {
    match value.and_then(|v| v.as_str()) {
        Some("use_cached") => ErrorPolicy::UseCached,
        Some("fail") => ErrorPolicy::Fail,
        Some("use_default") => ErrorPolicy::UseDefault,
        _ => ErrorPolicy::UseCached,
    }
}

fn parse_duration_field(value: Option<&serde_yaml::Value>) -> Option<Duration> {
    value.and_then(|v| v.as_str()).and_then(parse_duration_str)
}

/// Parse a duration string like "5m", "30s", "1h", "24h", "500ms".
fn parse_duration_str(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(ms) = s.strip_suffix("ms") {
        ms.parse::<u64>().ok().map(Duration::from_millis)
    } else if let Some(secs) = s.strip_suffix('s') {
        secs.parse::<u64>().ok().map(Duration::from_secs)
    } else if let Some(mins) = s.strip_suffix('m') {
        mins.parse::<u64>()
            .ok()
            .map(|m| Duration::from_secs(m * 60))
    } else if let Some(hours) = s.strip_suffix('h') {
        hours
            .parse::<u64>()
            .ok()
            .map(|h| Duration::from_secs(h * 3600))
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

fn parse_string_headers(value: Option<&serde_yaml::Value>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(serde_yaml::Value::Mapping(m)) = value {
        for (k, v) in m {
            if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
                map.insert(key.to_string(), val.to_string());
            }
        }
    }
    map
}

fn parse_command_field(value: Option<&serde_yaml::Value>) -> Result<Vec<String>> {
    match value {
        Some(serde_yaml::Value::Sequence(seq)) => Ok(seq
            .iter()
            .filter_map(|item| item.as_str().map(String::from))
            .collect()),
        Some(serde_yaml::Value::String(s)) => Ok(vec![s.clone()]),
        _ => Ok(Vec::new()),
    }
}

// =============================================================================
// Cross-validation
// =============================================================================

/// Validate that every `${source.*}` reference and `include` target names a
/// declared source. Returns an error listing all undeclared source IDs.
fn validate_source_refs(sources: &[DynamicSource], refs: &[SourceRef]) -> Result<()> {
    if refs.is_empty() {
        return Ok(());
    }

    let declared: std::collections::HashSet<&str> = sources.iter().map(|s| s.id.as_str()).collect();

    let undeclared: Vec<&str> = refs
        .iter()
        .filter(|r| !declared.contains(r.source_id.as_str()))
        .map(|r| r.source_id.as_str())
        .collect::<std::collections::HashSet<&str>>()
        .into_iter()
        .collect();

    if undeclared.is_empty() {
        Ok(())
    } else {
        Err(EvalError::InvalidModifiers(format!(
            "pipeline references undeclared source(s): {}",
            undeclared.join(", ")
        )))
    }
}

// =============================================================================
// Template reference scanning
// =============================================================================

/// Regex matching `${source.<id>}` or `${source.<id>.<sub_path>}` templates.
fn source_ref_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\$\{source\.([a-zA-Z_][a-zA-Z0-9_]*)(?:\.([a-zA-Z0-9_.]+))?\}")
            .expect("source ref regex is valid")
    })
}

/// Scan the entire pipeline YAML for `${source.*}` template references and
/// `include` directives, returning all found references.
fn scan_source_refs(obj: &serde_yaml::Mapping) -> Vec<SourceRef> {
    let mut refs = Vec::new();

    // Scan vars
    if let Some(serde_yaml::Value::Mapping(vars)) = obj.get(ykey("vars")) {
        for (k, v) in vars {
            if let (Some(var_name), Some(s)) = (k.as_str(), yaml_value_as_str(v)) {
                for cap in source_ref_regex().captures_iter(s) {
                    refs.push(SourceRef {
                        source_id: cap[1].to_string(),
                        sub_path: cap.get(2).map(|m| m.as_str().to_string()),
                        location: RefLocation::Var {
                            var_name: var_name.to_string(),
                        },
                        raw_template: cap[0].to_string(),
                    });
                }
            }
        }
    }

    // Scan transformations
    if let Some(serde_yaml::Value::Sequence(transforms)) = obj.get(ykey("transformations")) {
        for (idx, item) in transforms.iter().enumerate() {
            if let Some(mapping) = item.as_mapping() {
                // Check for `include` directive
                if let Some(include_val) = mapping.get(ykey("include"))
                    && let Some(s) = yaml_value_as_str(include_val)
                {
                    for cap in source_ref_regex().captures_iter(s) {
                        refs.push(SourceRef {
                            source_id: cap[1].to_string(),
                            sub_path: cap.get(2).map(|m| m.as_str().to_string()),
                            location: RefLocation::Include {
                                transform_index: idx,
                            },
                            raw_template: cap[0].to_string(),
                        });
                    }
                }

                // Scan all other string values in the mapping
                for (field_key, field_val) in mapping {
                    let field_name = match field_key.as_str() {
                        Some(name) if name != "include" => name,
                        _ => continue,
                    };
                    scan_yaml_value_for_refs(field_val, idx, field_name, &mut refs);
                }
            }
        }
    }

    // Scan finalizers
    if let Some(serde_yaml::Value::Sequence(finalizers)) = obj.get(ykey("finalizers")) {
        for (idx, item) in finalizers.iter().enumerate() {
            if let Some(mapping) = item.as_mapping() {
                for (field_key, field_val) in mapping {
                    if let Some(field_name) = field_key.as_str() {
                        scan_yaml_value_for_refs(field_val, idx, field_name, &mut refs);
                    }
                }
            }
        }
    }

    refs
}

/// Recursively scan a YAML value for `${source.*}` references.
fn scan_yaml_value_for_refs(
    value: &serde_yaml::Value,
    transform_index: usize,
    field_name: &str,
    refs: &mut Vec<SourceRef>,
) {
    match value {
        serde_yaml::Value::String(s) => {
            for cap in source_ref_regex().captures_iter(s) {
                refs.push(SourceRef {
                    source_id: cap[1].to_string(),
                    sub_path: cap.get(2).map(|m| m.as_str().to_string()),
                    location: RefLocation::TransformationField {
                        transform_index,
                        field_name: field_name.to_string(),
                    },
                    raw_template: cap[0].to_string(),
                });
            }
        }
        serde_yaml::Value::Mapping(m) => {
            for (k, v) in m {
                let nested_field = if let Some(key) = k.as_str() {
                    format!("{field_name}.{key}")
                } else {
                    field_name.to_string()
                };
                scan_yaml_value_for_refs(v, transform_index, &nested_field, refs);
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                scan_yaml_value_for_refs(item, transform_index, field_name, refs);
            }
        }
        _ => {}
    }
}

/// Helper to get a string from a YAML value (including tagged strings).
fn yaml_value_as_str(value: &serde_yaml::Value) -> Option<&str> {
    value.as_str()
}
