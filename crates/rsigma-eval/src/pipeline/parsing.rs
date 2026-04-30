use std::collections::HashMap;
use std::path::Path;

use regex::Regex;
use rsigma_parser::{SigmaString, SigmaValue};

use crate::error::{EvalError, Result};

use super::conditions::{
    DetectionItemCondition, FieldMatcher, FieldNameCondition, NamedRuleCondition, RuleCondition,
};
use super::finalizers::Finalizer;
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

    Ok(Pipeline {
        name,
        priority,
        vars,
        transformations,
        finalizers,
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

    let transformation = parse_transformation(obj)?;

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
