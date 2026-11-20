use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use regex::Regex;
use rsigma_parser::{SigmaString, SigmaValue};

use crate::error::{EvalError, Result};

use super::conditions::{
    ConditionOp, ConditionSet, DetectionItemCondition, FieldMatcher, FieldNameCondition,
    NamedCondition, RuleCondition, StateOperator, ValueMatch, validate_condition_expr,
};
use super::finalizers::Finalizer;
use super::sources::{
    DataFormat, DynamicSource, ErrorPolicy, ExtractExpr, RefLocation, RefreshPolicy,
    STIX_OBSERVABLE_KEYS, SourceRef, SourceType, StixOptions, TaxiiAuthConfig, is_valid_source_id,
    scan_source_templates,
};
use super::transformations::Transformation;
use super::{Pipeline, TransformationItem};

// =============================================================================
// YAML parsing
// =============================================================================

/// Parse a pipeline from a YAML string.
pub fn parse_pipeline(yaml: &str) -> Result<Pipeline> {
    let value: yaml_serde::Value = yaml_serde::from_str(yaml)
        .map_err(|e| EvalError::Pipeline(format!("YAML parse error: {e}")))?;
    parse_pipeline_value(&value)
}

/// Parse a pipeline from a YAML file.
pub fn parse_pipeline_file(path: &Path) -> Result<Pipeline> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| EvalError::Pipeline(format!("cannot read file: {e}")))?;
    parse_pipeline(&content)
}

/// Parse a pipeline from a `yaml_serde::Value`.
fn parse_pipeline_value(value: &yaml_serde::Value) -> Result<Pipeline> {
    let obj = value
        .as_mapping()
        .ok_or_else(|| EvalError::Pipeline("top level must be a mapping".to_string()))?;

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

    // Pipeline-embedded `sources:` blocks were deprecated in v0.12.0 and
    // removed in v0.19.0. Source declarations now live in standalone source
    // files loaded via `--source`; a pipeline only references them with
    // `${source.<id>}`. Reject the inline form with a migration hint.
    if obj.get(ykey("sources")).is_some() {
        return Err(EvalError::Pipeline(
            "pipeline declares an inline 'sources:' block, which was removed in v0.19.0. \
             Extract it into a standalone source file with \
             `rsigma rule migrate-sources -p <pipeline> -o sources.yml` and load it via \
             `--source sources.yml`."
                .to_string(),
        ));
    }

    let source_refs = scan_source_refs(obj);

    validate_source_refs(&source_refs, None)?;

    Ok(Pipeline {
        name,
        priority,
        vars,
        transformations,
        finalizers,
        source_refs,
    })
}

fn ykey(s: &str) -> yaml_serde::Value {
    yaml_serde::Value::String(s.to_string())
}

fn parse_vars(value: Option<&yaml_serde::Value>) -> HashMap<String, Vec<String>> {
    let mut vars = HashMap::new();
    if let Some(yaml_serde::Value::Mapping(m)) = value {
        for (k, v) in m {
            if let Some(key) = k.as_str() {
                let values = match v {
                    yaml_serde::Value::Sequence(seq) => {
                        seq.iter().filter_map(yaml_scalar_to_string).collect()
                    }
                    scalar => yaml_scalar_to_string(scalar).into_iter().collect(),
                };
                vars.insert(key.to_string(), values);
            }
        }
    }
    vars
}

fn yaml_scalar_to_string(value: &yaml_serde::Value) -> Option<String> {
    match value {
        yaml_serde::Value::String(value) => Some(value.clone()),
        yaml_serde::Value::Number(value) => Some(value.to_string()),
        yaml_serde::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

/// Parse a YAML value as a sequence of transformation items.
pub fn parse_transformation_items(value: &yaml_serde::Value) -> Result<Vec<TransformationItem>> {
    let items = value
        .as_sequence()
        .ok_or_else(|| EvalError::Pipeline("transformations must be a sequence".to_string()))?;

    items.iter().map(parse_transformation_item).collect()
}

fn parse_transformation_item(value: &yaml_serde::Value) -> Result<TransformationItem> {
    let obj = value
        .as_mapping()
        .ok_or_else(|| EvalError::Pipeline("transformation item must be a mapping".to_string()))?;

    validate_transformation_item_keys(obj)?;

    let id = obj
        .get(ykey("id"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Handle `include` directives as a special transformation type
    let transformation = if obj.get(ykey("type")).is_none()
        && let Some(include_val) = obj.get(ykey("include"))
    {
        let template = include_val.as_str().unwrap_or("").to_string();
        Transformation::Include { template }
    } else {
        parse_transformation(obj)?
    };

    let rule_condition_items = if let Some(conds) = obj.get(ykey("rule_conditions")) {
        parse_rule_conditions(conds)?
    } else {
        Vec::new()
    };
    let rule_conditions = parse_condition_set(
        obj,
        "rule",
        rule_condition_items,
        Some("rule_cond_expression"),
    )?;

    let detection_item_condition_items =
        if let Some(conds) = obj.get(ykey("detection_item_conditions")) {
            parse_detection_item_conditions(conds)?
        } else {
            Vec::new()
        };
    let detection_item_conditions =
        parse_condition_set(obj, "detection_item", detection_item_condition_items, None)?;

    let field_name_condition_items = if let Some(conds) = obj.get(ykey("field_name_conditions")) {
        parse_field_name_conditions(conds)?
    } else {
        Vec::new()
    };
    let field_name_conditions =
        parse_condition_set(obj, "field_name", field_name_condition_items, None)?;

    Ok(TransformationItem {
        id,
        transformation,
        rule_conditions,
        detection_item_conditions,
        field_name_conditions,
    })
}

fn validate_transformation_item_keys(obj: &yaml_serde::Mapping) -> Result<()> {
    const COMMON: &[&str] = &[
        "id",
        "type",
        "rule_conditions",
        "rule_cond_expr",
        "rule_cond_expression",
        "rule_cond_op",
        "rule_cond_not",
        "detection_item_conditions",
        "detection_item_cond_expr",
        "detection_item_cond_op",
        "detection_item_cond_not",
        "field_name_conditions",
        "field_name_cond_expr",
        "field_name_cond_op",
        "field_name_cond_not",
        "allow_template_vars",
        "vars_allowed_paths",
        "allow_external_sources",
    ];

    let transformation_type = obj.get(ykey("type")).and_then(|value| value.as_str());
    let specific: &[&str] = if transformation_type.is_none() && obj.get(ykey("include")).is_some() {
        &["include"]
    } else {
        match transformation_type {
            Some("field_name_mapping" | "field_name_prefix_mapping" | "map_string") => &["mapping"],
            Some("field_name_prefix") => &["prefix"],
            Some("field_name_suffix") => &["suffix"],
            Some("drop_detection_item") => &[],
            Some("value_placeholders") => &["allow_unresolved", "include", "exclude"],
            Some("wildcard_placeholders") => &["include", "exclude"],
            Some("add_condition") => &[
                "conditions",
                "field_refs",
                "negated",
                "prepend",
                "name",
                "template",
            ],
            Some("change_logsource") => &["category", "product", "service"],
            Some("replace_string") => {
                &["regex", "replacement", "skip_special", "interpret_special"]
            }
            Some("query_expression_placeholders") => {
                &["expression", "mapping", "include", "exclude"]
            }
            Some("set_state") => &["key", "val", "value"],
            Some("rule_failure" | "detection_item_failure") => &["message"],
            Some("field_name_transform") => &["transform_func", "mapping", "apply_keyword"],
            Some("hashes_fields") => &[
                "valid_hash_algos",
                "field_prefix",
                "drop_algo_prefix",
                "field_to_parse",
            ],
            Some("set_value") => &["value", "force_type"],
            Some("convert_type") => &["target_type"],
            Some("regex") => &["method"],
            Some("add_field" | "remove_field") => &["field"],
            Some("set_field") => &["fields"],
            Some("set_custom_attribute") => &["attribute", "value"],
            Some("case_transformation" | "case") => &["case_type", "case", "method"],
            Some("nest") => &["items", "transformations"],
            Some("include") => &["include"],
            Some(_) | None => &[],
        }
    };

    for key in obj.keys() {
        let key = key.as_str().ok_or_else(|| {
            EvalError::Pipeline("transformation item keys must be strings".to_string())
        })?;
        if !COMMON.contains(&key) && !specific.contains(&key) {
            return Err(EvalError::Pipeline(format!(
                "unknown key '{key}' in transformation item"
            )));
        }
    }
    Ok(())
}

fn parse_transformation(obj: &yaml_serde::Mapping) -> Result<Transformation> {
    let type_str = obj
        .get(ykey("type"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            EvalError::Pipeline("transformation must have a 'type' field".to_string())
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
            let field_refs = parse_string_mapping(obj.get(ykey("field_refs")))?;
            let negated = obj
                .get(ykey("negated"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let prepend = obj
                .get(ykey("prepend"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let name = obj
                .get(ykey("name"))
                .map(|value| {
                    value.as_str().map(str::to_string).ok_or_else(|| {
                        EvalError::Pipeline("add_condition 'name' must be a string".into())
                    })
                })
                .transpose()?;
            let template = obj
                .get(ykey("template"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(Transformation::AddCondition {
                conditions,
                field_refs,
                negated,
                prepend,
                name,
                template,
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
            let interpret_special = obj
                .get(ykey("interpret_special"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(Transformation::ReplaceString {
                regex,
                replacement,
                skip_special,
                interpret_special,
            })
        }

        "value_placeholders" => {
            let allow_unresolved = obj
                .get(ykey("allow_unresolved"))
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            let (include, exclude) = parse_placeholder_filter(obj)?;
            Ok(Transformation::ValuePlaceholders {
                allow_unresolved,
                include,
                exclude,
            })
        }

        "wildcard_placeholders" => {
            let (include, exclude) = parse_placeholder_filter(obj)?;
            Ok(Transformation::WildcardPlaceholders { include, exclude })
        }

        "query_expression_placeholders" => {
            if let Some(key) = ["mapping", "include", "exclude"]
                .into_iter()
                .find(|key| obj.contains_key(ykey(key)))
            {
                return Err(EvalError::Pipeline(format!(
                    "query_expression_placeholders '{key}' is not supported: placeholders are \
                     not rendered as query expressions"
                )));
            }
            let expression = obj
                .get(ykey("expression"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Transformation::QueryExpressionPlaceholders { expression })
        }

        "include" => {
            let template = obj
                .get(ykey("include"))
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Transformation::Include { template })
        }

        "set_state" => {
            let key = obj
                .get(ykey("key"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let value = obj
                .get(ykey("val"))
                .or_else(|| obj.get(ykey("value")))
                .map(yaml_to_json)
                .transpose()?
                .unwrap_or(serde_json::Value::Null);
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
            if obj
                .get(ykey("apply_keyword"))
                .is_some_and(|value| value.as_bool() != Some(false))
            {
                return Err(EvalError::Pipeline(
                    "field_name_transform 'apply_keyword' is not supported: keyword detections \
                     have no field name to transform"
                        .to_string(),
                ));
            }
            Ok(Transformation::FieldNameTransform {
                transform_func,
                mapping,
            })
        }

        "hashes_fields" => {
            let valid_hash_algos = obj
                .get(ykey("valid_hash_algos"))
                .map(|value| parse_string_list(Some(value)))
                .ok_or_else(|| {
                    EvalError::Pipeline("hashes_fields requires 'valid_hash_algos'".to_string())
                })?;
            let field_prefix = obj
                .get(ykey("field_prefix"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let drop_algo_prefix = obj
                .get(ykey("drop_algo_prefix"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let field_to_parse = obj
                .get(ykey("field_to_parse"))
                .map(|value| parse_string_list(Some(value)))
                .unwrap_or_else(|| vec!["Hashes".to_string(), "Hash".to_string()]);
            Ok(Transformation::HashesFields {
                valid_hash_algos,
                field_prefix,
                drop_algo_prefix,
                field_to_parse,
            })
        }

        "map_string" => {
            let mapping = parse_string_or_list_mapping(obj.get(ykey("mapping")))?;
            Ok(Transformation::MapString { mapping })
        }

        "set_value" => {
            let raw = obj.get(ykey("value"));
            let value = match obj.get(ykey("force_type")) {
                None => raw.map(SigmaValue::from_yaml).unwrap_or(SigmaValue::Null),
                Some(force_type) => force_set_value_type(raw, force_type)?,
            };
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

        "regex" => {
            match obj.get(ykey("method")).map(|method| method.as_str()) {
                None | Some(Some("ignore_case_brackets" | "ignore_case_flag")) => {}
                Some(Some("plain")) => {
                    return Err(EvalError::Pipeline(
                        "regex method 'plain' is not supported: rsigma matches strings \
                         case-insensitively"
                            .to_string(),
                    ));
                }
                Some(_) => {
                    return Err(EvalError::Pipeline(
                        "invalid regex 'method'; expected 'plain', 'ignore_case_flag', or \
                         'ignore_case_brackets'"
                            .to_string(),
                    ));
                }
            }
            Ok(Transformation::Regex)
        }

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
                .or_else(|| obj.get(ykey("method")))
                .and_then(|v| v.as_str())
                .unwrap_or("lower")
                .to_string();
            Ok(Transformation::CaseTransformation { case_type })
        }

        "nest" => {
            let items_yaml = obj
                .get(ykey("items"))
                .or_else(|| obj.get(ykey("transformations")));
            let items = if let Some(yaml_serde::Value::Sequence(seq)) = items_yaml {
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

        other => Err(EvalError::Pipeline(format!(
            "unknown transformation type: {other}"
        ))),
    }
}

// =============================================================================
// Condition YAML parsing
// =============================================================================

fn parse_rule_conditions(value: &yaml_serde::Value) -> Result<Vec<NamedCondition<RuleCondition>>> {
    parse_named_conditions(value, "rule_conditions", parse_rule_condition)
}

fn parse_rule_condition(value: &yaml_serde::Value) -> Result<RuleCondition> {
    let obj = value
        .as_mapping()
        .ok_or_else(|| EvalError::Pipeline("rule condition must be a mapping".to_string()))?;

    let type_str = obj
        .get(ykey("type"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            EvalError::Pipeline("rule condition must have a 'type' field".to_string())
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
                .map(yaml_to_json)
                .transpose()?
                .unwrap_or(serde_json::Value::Null);
            let op = parse_state_operator(obj.get(ykey("op")))?;
            Ok(RuleCondition::ProcessingState { key, val, op })
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

        other => Err(EvalError::Pipeline(format!(
            "unknown rule condition type: {other}"
        ))),
    }?;

    Ok(condition)
}

fn parse_detection_item_conditions(
    value: &yaml_serde::Value,
) -> Result<Vec<NamedCondition<DetectionItemCondition>>> {
    parse_named_conditions(
        value,
        "detection_item_conditions",
        parse_detection_item_condition,
    )
}

fn parse_detection_item_condition(value: &yaml_serde::Value) -> Result<DetectionItemCondition> {
    let obj = value.as_mapping().ok_or_else(|| {
        EvalError::Pipeline("detection item condition must be a mapping".to_string())
    })?;

    let type_str = obj
        .get(ykey("type"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            EvalError::Pipeline("detection item condition must have a 'type' field".to_string())
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
                EvalError::Pipeline(format!("invalid match_string regex '{pattern}': {e}"))
            })?;
            let cond = parse_value_match(obj)?;
            Ok(DetectionItemCondition::MatchString {
                regex,
                negate,
                cond,
            })
        }

        "is_null" => {
            let negate = obj
                .get(ykey("negate"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let cond = parse_value_match(obj)?;
            Ok(DetectionItemCondition::IsNull { negate, cond })
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
                .map(yaml_to_json)
                .transpose()?
                .unwrap_or(serde_json::Value::Null);
            let op = parse_state_operator(obj.get(ykey("op")))?;
            Ok(DetectionItemCondition::ProcessingState { key, val, op })
        }

        other => Err(EvalError::Pipeline(format!(
            "unknown detection item condition type: {other}"
        ))),
    }
}

fn parse_field_name_conditions(
    value: &yaml_serde::Value,
) -> Result<Vec<NamedCondition<FieldNameCondition>>> {
    parse_named_conditions(value, "field_name_conditions", parse_field_name_condition)
}

fn parse_field_name_condition(value: &yaml_serde::Value) -> Result<FieldNameCondition> {
    let obj = value
        .as_mapping()
        .ok_or_else(|| EvalError::Pipeline("field name condition must be a mapping".to_string()))?;

    let type_str = obj
        .get(ykey("type"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            EvalError::Pipeline("field name condition must have a 'type' field".to_string())
        })?;

    let is_regex = match obj
        .get(ykey("mode"))
        .or_else(|| obj.get(ykey("match_type")))
    {
        None => false,
        Some(mode) => match mode.as_str() {
            Some("plain") => false,
            Some("re" | "regex") => true,
            _ => {
                return Err(EvalError::Pipeline(format!(
                    "invalid field name matching mode {mode:?}; expected 'plain' or 're'"
                )));
            }
        },
    };

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
                .map(yaml_to_json)
                .transpose()?
                .unwrap_or(serde_json::Value::Null);
            let op = parse_state_operator(obj.get(ykey("op")))?;
            Ok(FieldNameCondition::ProcessingState { key, val, op })
        }

        other => Err(EvalError::Pipeline(format!(
            "unknown field name condition type: {other}"
        ))),
    }
}

fn parse_named_conditions<T>(
    value: &yaml_serde::Value,
    label: &str,
    parse: impl Fn(&yaml_serde::Value) -> Result<T>,
) -> Result<Vec<NamedCondition<T>>> {
    match value {
        yaml_serde::Value::Sequence(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let id = item
                    .as_mapping()
                    .and_then(|mapping| mapping.get(ykey("id")))
                    .and_then(|value| value.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| (index + 1).to_string());
                Ok(NamedCondition {
                    id,
                    condition: parse(item)?,
                })
            })
            .collect(),
        yaml_serde::Value::Mapping(items) => items
            .iter()
            .map(|(id, item)| {
                let id = id.as_str().ok_or_else(|| {
                    EvalError::Pipeline(format!("{label} identifiers must be strings"))
                })?;
                Ok(NamedCondition {
                    id: id.to_string(),
                    condition: parse(item)?,
                })
            })
            .collect(),
        _ => Err(EvalError::Pipeline(format!(
            "{label} must be a sequence or mapping"
        ))),
    }
}

fn parse_condition_set<T>(
    obj: &yaml_serde::Mapping,
    prefix: &str,
    conditions: Vec<NamedCondition<T>>,
    expression_alias: Option<&str>,
) -> Result<ConditionSet<T>> {
    let op_key = format!("{prefix}_cond_op");
    let not_key = format!("{prefix}_cond_not");
    let expression_key = format!("{prefix}_cond_expr");

    let op = parse_condition_op(obj.get(ykey(&op_key)))?;
    let negated = match obj.get(ykey(&not_key)) {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| EvalError::Pipeline(format!("{not_key} must be a boolean")))?,
        None => false,
    };

    let expression =
        match obj.get(ykey(&expression_key)) {
            Some(value) => Some(value.as_str().ok_or_else(|| {
                EvalError::Pipeline(format!("{expression_key} must be a string"))
            })?),
            None => None,
        };
    let alias_expression = expression_alias
        .map(|alias| {
            obj.get(ykey(alias))
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| EvalError::Pipeline(format!("{alias} must be a string")))
                })
                .transpose()
        })
        .transpose()?
        .flatten();
    if expression.is_some() && alias_expression.is_some() {
        return Err(EvalError::Pipeline(format!(
            "{expression_key} and {} cannot both be set",
            expression_alias.unwrap_or_default()
        )));
    }
    let expression = expression.or(alias_expression).map(String::from);

    if expression.is_some() && obj.get(ykey(&op_key)).is_some() {
        return Err(EvalError::Pipeline(format!(
            "{expression_key} is mutually exclusive with {op_key}"
        )));
    }

    if let Some(expression) = &expression {
        let ids: Vec<String> = conditions
            .iter()
            .map(|condition| condition.id.clone())
            .collect();
        validate_condition_expr(expression, &ids, &format!("{prefix} condition"))?;
    }

    Ok(ConditionSet {
        conditions,
        op,
        negated,
        expression,
    })
}

fn parse_condition_op(value: Option<&yaml_serde::Value>) -> Result<ConditionOp> {
    match value {
        None => Ok(ConditionOp::And),
        Some(value) if value.as_str() == Some("and") => Ok(ConditionOp::And),
        Some(value) if value.as_str() == Some("or") => Ok(ConditionOp::Or),
        Some(yaml_serde::Value::String(other)) => Err(EvalError::Pipeline(format!(
            "condition operator must be 'and' or 'or', got '{other}'"
        ))),
        Some(_) => Err(EvalError::Pipeline(
            "condition operator must be a string".to_string(),
        )),
    }
}

fn parse_state_operator(value: Option<&yaml_serde::Value>) -> Result<StateOperator> {
    match value {
        None => Ok(StateOperator::Eq),
        Some(value) if value.as_str() == Some("eq") => Ok(StateOperator::Eq),
        Some(value) if value.as_str() == Some("ne") => Ok(StateOperator::Ne),
        Some(value) if value.as_str() == Some("gte") => Ok(StateOperator::Gte),
        Some(value) if value.as_str() == Some("gt") => Ok(StateOperator::Gt),
        Some(value) if value.as_str() == Some("lte") => Ok(StateOperator::Lte),
        Some(value) if value.as_str() == Some("lt") => Ok(StateOperator::Lt),
        Some(yaml_serde::Value::String(other)) => Err(EvalError::Pipeline(format!(
            "processing_state op must be eq, ne, gte, gt, lte, or lt; got '{other}'"
        ))),
        Some(_) => Err(EvalError::Pipeline(
            "processing_state op must be a string".to_string(),
        )),
    }
}

fn yaml_to_json(value: &yaml_serde::Value) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|error| {
        EvalError::Pipeline(format!("value cannot be represented as JSON: {error}"))
    })
}

// =============================================================================
// YAML parsing helpers
// =============================================================================

fn parse_string_mapping(value: Option<&yaml_serde::Value>) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    if let Some(yaml_serde::Value::Mapping(m)) = value {
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
    value: Option<&yaml_serde::Value>,
) -> Result<HashMap<String, Vec<String>>> {
    let mut map = HashMap::new();
    if let Some(yaml_serde::Value::Mapping(m)) = value {
        for (k, v) in m {
            if let Some(key) = k.as_str() {
                let values = match v {
                    yaml_serde::Value::String(s) => vec![s.clone()],
                    yaml_serde::Value::Sequence(seq) => {
                        let mut strings = Vec::with_capacity(seq.len());
                        for item in seq {
                            if let Some(s) = item.as_str() {
                                strings.push(s.to_string());
                            } else {
                                log::warn!(
                                    "non-string item in mapping list for key '{key}': {item:?}; skipping",
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

fn parse_value_mapping(
    value: Option<&yaml_serde::Value>,
) -> Result<HashMap<String, Vec<SigmaValue>>> {
    let mut map = HashMap::new();
    if let Some(yaml_serde::Value::Mapping(m)) = value {
        for (k, v) in m {
            if let Some(key) = k.as_str() {
                let values = match v {
                    // An empty sequence would drop the condition and widen the
                    // rule, so it is rejected rather than skipped.
                    yaml_serde::Value::Sequence(seq) if seq.is_empty() => {
                        return Err(EvalError::Pipeline(format!(
                            "add_condition: empty sequence for field '{key}'"
                        )));
                    }
                    // YAML sequence → Vec<SigmaValue> (OR semantics, like pySigma)
                    yaml_serde::Value::Sequence(seq) => seq
                        .iter()
                        .map(|item| scalar_condition_value(key, item))
                        .collect::<Result<Vec<_>>>()?,
                    // Scalar → single-element Vec
                    other => vec![scalar_condition_value(key, other)?],
                };
                map.insert(key.to_string(), values);
            }
        }
    }
    Ok(map)
}

/// Convert one `add_condition` value, rejecting anything that is not a scalar.
///
/// `SigmaValue::from_yaml` renders an unsupported node as its debug
/// representation, which would load as a literal string that can never match.
fn scalar_condition_value(field: &str, value: &yaml_serde::Value) -> Result<SigmaValue> {
    match value {
        yaml_serde::Value::String(_)
        | yaml_serde::Value::Number(_)
        | yaml_serde::Value::Bool(_)
        | yaml_serde::Value::Null => Ok(SigmaValue::from_yaml(value)),
        _ => Err(EvalError::Pipeline(format!(
            "add_condition: non-scalar value for field '{field}'"
        ))),
    }
}

fn build_field_matcher(fields: Vec<String>, is_regex: bool) -> Result<FieldMatcher> {
    if is_regex {
        let regexes = fields
            .iter()
            .map(|p| {
                Regex::new(p)
                    .map_err(|e| EvalError::Pipeline(format!("invalid field regex '{p}': {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(FieldMatcher::Regex(regexes))
    } else {
        Ok(FieldMatcher::Plain(fields))
    }
}

/// pySigma's `SetValueTransformation` with `force_type`: `str` turns a string
/// or number into a string, `num` parses it as a number.
fn force_set_value_type(
    raw: Option<&yaml_serde::Value>,
    force_type: &yaml_serde::Value,
) -> Result<SigmaValue> {
    let text = match raw {
        Some(yaml_serde::Value::String(s)) => s.clone(),
        Some(yaml_serde::Value::Number(n)) => n.to_string(),
        _ => {
            return Err(EvalError::Pipeline(
                "set_value 'force_type' is only allowed for string and numeric values".to_string(),
            ));
        }
    };
    match force_type.as_str() {
        Some("str") => Ok(SigmaValue::String(SigmaString::new(&text))),
        Some("num") => {
            let trimmed = text.trim();
            if let Ok(int) = trimmed.parse::<i64>() {
                Ok(SigmaValue::Integer(int))
            } else if let Ok(float) = trimmed.parse::<f64>()
                && float.is_finite()
            {
                Ok(SigmaValue::Float(float))
            } else {
                Err(EvalError::Pipeline(format!(
                    "set_value value '{text}' can't be converted to a number"
                )))
            }
        }
        _ => Err(EvalError::Pipeline(format!(
            "invalid set_value 'force_type' {force_type:?}; expected 'str' or 'num'"
        ))),
    }
}

fn parse_value_match(obj: &yaml_serde::Mapping) -> Result<ValueMatch> {
    match obj.get(ykey("cond")) {
        None => Ok(ValueMatch::Any),
        Some(value) => match value.as_str() {
            Some("any") => Ok(ValueMatch::Any),
            Some("all") => Ok(ValueMatch::All),
            _ => Err(EvalError::Pipeline(format!(
                "invalid detection item condition 'cond' value {value:?}; expected 'any' or 'all'"
            ))),
        },
    }
}

fn parse_string_list(value: Option<&yaml_serde::Value>) -> Vec<String> {
    match value {
        Some(yaml_serde::Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|item| item.as_str().map(String::from))
            .collect(),
        Some(yaml_serde::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

type PlaceholderFilter = (Option<Vec<String>>, Option<Vec<String>>);

fn parse_placeholder_filter(obj: &yaml_serde::Mapping) -> Result<PlaceholderFilter> {
    let include = obj
        .get(ykey("include"))
        .map(|value| parse_string_list(Some(value)));
    let exclude = obj
        .get(ykey("exclude"))
        .map(|value| parse_string_list(Some(value)));
    if include.is_some() && exclude.is_some() {
        return Err(EvalError::Pipeline(
            "placeholder transformations cannot set both include and exclude".to_string(),
        ));
    }
    Ok((include, exclude))
}

fn parse_finalizers(value: &yaml_serde::Value) -> Vec<Finalizer> {
    if let Some(seq) = value.as_sequence() {
        seq.iter().filter_map(Finalizer::from_yaml).collect()
    } else {
        Vec::new()
    }
}

// =============================================================================
// Dynamic source parsing
// =============================================================================

/// Parse a `sources` sequence into dynamic source declarations.
///
/// Used by [`parse_sources_file`] for standalone `--source` files and by the
/// `rsigma rule migrate-sources` tool to read a legacy pipeline's inline
/// `sources:` block. Pipelines themselves no longer accept an inline block.
pub fn parse_sources(value: &yaml_serde::Value) -> Result<Vec<DynamicSource>> {
    let items = value
        .as_sequence()
        .ok_or_else(|| EvalError::Pipeline("sources must be a sequence".to_string()))?;

    items.iter().map(parse_dynamic_source).collect()
}

/// Parse a single dynamic source declaration.
pub fn parse_dynamic_source(value: &yaml_serde::Value) -> Result<DynamicSource> {
    let obj = value
        .as_mapping()
        .ok_or_else(|| EvalError::Pipeline("source must be a mapping".to_string()))?;

    let id = obj
        .get(ykey("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| EvalError::Pipeline("source must have an 'id' field".to_string()))?
        .to_string();
    if !is_valid_source_id(&id) {
        return Err(EvalError::Pipeline(format!(
            "source id '{id}' is invalid: use only ASCII letters, digits, '_', and '-' so ${{source.<id>}} can reference it"
        )));
    }

    let type_str = obj
        .get(ykey("type"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| EvalError::Pipeline(format!("source '{id}' must have a 'type' field")))?;

    let format = parse_data_format(obj.get(ykey("format")));
    let extract = parse_extract_expr(obj.get(ykey("extract")), &id)?;

    let source_type = match type_str {
        "http" => {
            let (format, extract, stix) =
                bind_stix_format(&id, "http", format, extract, obj.get(ykey("stix")))?;
            let url = obj
                .get(ykey("url"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    EvalError::Pipeline(format!(
                        "source '{id}' of type 'http' must have a 'url' field"
                    ))
                })?
                .to_string();
            let method = obj
                .get(ykey("method"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let headers = parse_string_headers(obj.get(ykey("headers")));
            let body = obj
                .get(ykey("body"))
                .and_then(|v| v.as_str())
                .map(String::from);
            SourceType::Http {
                url,
                method,
                headers,
                body,
                format,
                extract,
                stix,
            }
        }
        "command" => {
            let (format, extract, _) =
                bind_stix_format(&id, "command", format, extract, obj.get(ykey("stix")))?;
            let command = parse_command_field(obj.get(ykey("command")))?;
            if command.is_empty() {
                return Err(EvalError::Pipeline(format!(
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
            let (format, extract, stix) =
                bind_stix_format(&id, "file", format, extract, obj.get(ykey("stix")))?;
            let path = obj
                .get(ykey("path"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    EvalError::Pipeline(format!(
                        "source '{id}' of type 'file' must have a 'path' field"
                    ))
                })?;
            SourceType::File {
                path: PathBuf::from(path),
                format,
                extract,
                stix,
            }
        }
        "nats" => {
            let (format, extract, _) =
                bind_stix_format(&id, "nats", format, extract, obj.get(ykey("stix")))?;
            let url = obj
                .get(ykey("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let subject = obj
                .get(ykey("subject"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    EvalError::Pipeline(format!(
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
        "watchlist" => {
            for key in ["refresh", "format", "extract", "timeout"] {
                if obj.get(ykey(key)).is_some() {
                    return Err(EvalError::Pipeline(format!(
                        "source '{id}' of type 'watchlist' does not accept '{key}'"
                    )));
                }
            }
            if id == "resolve" || id == "cache" {
                return Err(EvalError::Pipeline(format!(
                    "source id '{id}' is reserved and cannot be a watchlist"
                )));
            }
            let max_indicators = match obj.get(ykey("max_indicators")) {
                None => 100_000,
                Some(value) => match value.as_u64() {
                    Some(0) => {
                        return Err(EvalError::Pipeline(format!(
                            "source '{id}' max_indicators must be greater than 0"
                        )));
                    }
                    Some(n) => usize::try_from(n).unwrap_or(usize::MAX),
                    None => {
                        return Err(EvalError::Pipeline(format!(
                            "source '{id}' max_indicators must be a positive integer"
                        )));
                    }
                },
            };
            let max_value_length = match obj.get(ykey("max_value_length")) {
                None => 2048,
                Some(value) => match value.as_u64() {
                    Some(0) => {
                        return Err(EvalError::Pipeline(format!(
                            "source '{id}' max_value_length must be greater than 0"
                        )));
                    }
                    Some(n) => usize::try_from(n).unwrap_or(usize::MAX),
                    None => {
                        return Err(EvalError::Pipeline(format!(
                            "source '{id}' max_value_length must be a positive integer"
                        )));
                    }
                },
            };
            let default_ttl = match obj.get(ykey("default_ttl")) {
                None => None,
                Some(value) => {
                    Some(value.as_str().and_then(parse_duration_str).ok_or_else(|| {
                        EvalError::Pipeline(format!(
                            "source '{id}' default_ttl must be a duration such as 30d"
                        ))
                    })?)
                }
            };
            SourceType::Watchlist {
                max_indicators,
                max_value_length,
                default_ttl,
            }
        }
        "taxii" => {
            if extract.is_some() {
                return Err(EvalError::Pipeline(format!(
                    "source '{id}' of type 'taxii' does not accept 'extract'"
                )));
            }
            if obj.get(ykey("format")).is_some() {
                return Err(EvalError::Pipeline(format!(
                    "source '{id}' of type 'taxii' does not accept 'format'"
                )));
            }
            let url = obj
                .get(ykey("url"))
                .and_then(|v| v.as_str())
                .filter(|url| !url.is_empty())
                .ok_or_else(|| {
                    EvalError::Pipeline(format!(
                        "source '{id}' of type 'taxii' must have a 'url' field"
                    ))
                })?
                .to_string();
            let collection = obj
                .get(ykey("collection"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    EvalError::Pipeline(format!(
                        "source '{id}' of type 'taxii' must have a 'collection' field"
                    ))
                })?;
            if !is_collection_uuid(collection) {
                return Err(EvalError::Pipeline(format!(
                    "source '{id}' collection must be a UUID"
                )));
            }
            let page_size = match obj.get(ykey("page_size")) {
                None => 500,
                Some(value) => match value.as_u64() {
                    Some(0) => {
                        return Err(EvalError::Pipeline(format!(
                            "source '{id}' page_size must be greater than 0"
                        )));
                    }
                    Some(n) => usize::try_from(n).unwrap_or(usize::MAX),
                    None => {
                        return Err(EvalError::Pipeline(format!(
                            "source '{id}' page_size must be a positive integer"
                        )));
                    }
                },
            };
            let auth = parse_taxii_auth(&id, obj.get(ykey("auth")))?;
            let stix = parse_stix_options(&id, obj.get(ykey("stix")))?;
            SourceType::Taxii {
                url,
                collection: collection.to_string(),
                auth,
                page_size,
                stix,
            }
        }
        other => {
            return Err(EvalError::Pipeline(format!(
                "source '{id}' has unknown type: '{other}'"
            )));
        }
    };

    let refresh = parse_refresh_policy(obj.get(ykey("refresh")));
    if matches!(source_type, SourceType::Taxii { .. }) {
        let mode = match refresh {
            RefreshPolicy::Watch => Some("watch"),
            RefreshPolicy::Push => Some("push"),
            _ => None,
        };
        if let Some(mode) = mode {
            return Err(EvalError::Pipeline(format!(
                "source '{id}' of type 'taxii' does not accept refresh '{mode}'"
            )));
        }
    }
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

/// Parse a standalone sources YAML file (top-level `sources:` block).
///
/// The file shape is:
/// ```yaml
/// sources:
///   - id: employee_directory
///     type: file
///     path: ./data/employees.json
///     format: json
/// ```
pub fn parse_sources_file(path: &Path) -> Result<Vec<DynamicSource>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| EvalError::Pipeline(format!("cannot read sources file: {e}")))?;
    let value: yaml_serde::Value = yaml_serde::from_str(&content)
        .map_err(|e| EvalError::Pipeline(format!("sources file YAML parse error: {e}")))?;
    let obj = value
        .as_mapping()
        .ok_or_else(|| EvalError::Pipeline("sources file must be a YAML mapping".to_string()))?;
    match obj.get(ykey("sources")) {
        Some(items) => parse_sources(items),
        None => Err(EvalError::Pipeline(
            "sources file must contain a top-level 'sources:' key".to_string(),
        )),
    }
}

/// Load all `*.yml` and `*.yaml` files from a directory as source files,
/// sorted alphabetically. Each file must contain a top-level `sources:` block.
pub fn parse_sources_dir(dir: &Path) -> Result<Vec<DynamicSource>> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| EvalError::Pipeline(format!("cannot read sources directory: {e}")))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let path = entry.path();
            matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yml" | "yaml")
            )
        })
        .collect();
    entries.sort_by_key(|e| e.path());

    let mut all_sources = Vec::new();
    for entry in entries {
        let path = entry.path();
        let sources = parse_sources_file(&path)?;
        all_sources.extend(sources);
    }
    Ok(all_sources)
}

/// Parse an `extract` field which can be either:
/// - A plain string (always treated as jq): `extract: ".emails[]"`
/// - A structured mapping: `extract: { expr: "$.emails[*]", type: jsonpath }`
fn parse_extract_expr(
    value: Option<&yaml_serde::Value>,
    source_id: &str,
) -> Result<Option<ExtractExpr>> {
    let Some(val) = value else {
        return Ok(None);
    };

    if let Some(s) = val.as_str() {
        return Ok(Some(ExtractExpr::Jq(s.to_string())));
    }

    if let Some(map) = val.as_mapping() {
        let expr = map
            .get(ykey("expr"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                EvalError::Pipeline(format!(
                    "source '{source_id}': extract object must have an 'expr' field"
                ))
            })?
            .to_string();

        let extract_type = map
            .get(ykey("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("jq");

        let extract_expr = match extract_type {
            "jq" => ExtractExpr::Jq(expr),
            "jsonpath" => ExtractExpr::JsonPath(expr),
            "cel" => ExtractExpr::Cel(expr),
            other => {
                return Err(EvalError::Pipeline(format!(
                    "source '{source_id}': unknown extract type '{other}' (expected: jq, jsonpath, cel)"
                )));
            }
        };

        return Ok(Some(extract_expr));
    }

    Err(EvalError::Pipeline(format!(
        "source '{source_id}': 'extract' must be a string or mapping"
    )))
}

fn parse_data_format(value: Option<&yaml_serde::Value>) -> DataFormat {
    match value.and_then(|v| v.as_str()) {
        Some("json") => DataFormat::Json,
        Some("yaml" | "yml") => DataFormat::Yaml,
        Some("lines") => DataFormat::Lines,
        Some("csv") => DataFormat::Csv,
        Some("stix") => DataFormat::Stix,
        _ => DataFormat::Json,
    }
}

fn bind_stix_format(
    id: &str,
    source_type: &str,
    format: DataFormat,
    extract: Option<ExtractExpr>,
    stix: Option<&yaml_serde::Value>,
) -> Result<(DataFormat, Option<ExtractExpr>, Option<StixOptions>)> {
    if matches!(format, DataFormat::Stix) && matches!(source_type, "command" | "nats") {
        return Err(EvalError::Pipeline(format!(
            "source '{id}' of type '{source_type}' does not accept format 'stix'"
        )));
    }
    if stix.is_some() && !matches!(format, DataFormat::Stix) {
        return Err(EvalError::Pipeline(format!(
            "source '{id}' stix block requires format: stix"
        )));
    }
    if matches!(format, DataFormat::Stix) && extract.is_some() {
        return Err(EvalError::Pipeline(format!(
            "source '{id}' with format 'stix' does not accept 'extract'"
        )));
    }
    let options = if matches!(format, DataFormat::Stix) {
        Some(parse_stix_options(id, stix)?)
    } else {
        None
    };
    Ok((format, extract, options))
}

fn parse_stix_options(id: &str, value: Option<&yaml_serde::Value>) -> Result<StixOptions> {
    let Some(value) = value else {
        return Ok(StixOptions::all());
    };
    let obj = value.as_mapping().ok_or_else(|| {
        EvalError::Pipeline(format!("source '{id}' stix block must be a mapping"))
    })?;
    for key in obj.keys() {
        let Some(name) = key.as_str() else {
            return Err(EvalError::Pipeline(format!(
                "source '{id}' stix block keys must be strings"
            )));
        };
        if !matches!(name, "min_confidence" | "observables" | "max_indicators") {
            return Err(EvalError::Pipeline(format!(
                "source '{id}' stix block does not accept '{name}'"
            )));
        }
    }
    let min_confidence = match obj.get(ykey("min_confidence")) {
        None => None,
        Some(value) => match value.as_u64() {
            Some(n) if n <= 100 => Some(u8::try_from(n).unwrap_or(100)),
            _ => {
                return Err(EvalError::Pipeline(format!(
                    "source '{id}' min_confidence must be an integer from 0 to 100"
                )));
            }
        },
    };
    let observables = match obj.get(ykey("observables")) {
        None => StixOptions::all().observables,
        Some(value) => {
            let items = value.as_sequence().ok_or_else(|| {
                EvalError::Pipeline(format!(
                    "source '{id}' observables must be a list of strings"
                ))
            })?;
            let mut keys = Vec::with_capacity(items.len());
            for item in items {
                let Some(key) = item.as_str() else {
                    return Err(EvalError::Pipeline(format!(
                        "source '{id}' observables must be a list of strings"
                    )));
                };
                if !STIX_OBSERVABLE_KEYS.contains(&key) {
                    return Err(EvalError::Pipeline(format!(
                        "source '{id}' unknown observable '{key}'; valid keys: {}",
                        STIX_OBSERVABLE_KEYS.join(", ")
                    )));
                }
                keys.push(key.to_owned());
            }
            keys
        }
    };
    let max_indicators = match obj.get(ykey("max_indicators")) {
        None => 100_000,
        Some(value) => match value.as_u64() {
            Some(0) => {
                return Err(EvalError::Pipeline(format!(
                    "source '{id}' max_indicators must be greater than 0"
                )));
            }
            Some(n) => usize::try_from(n).unwrap_or(usize::MAX),
            None => {
                return Err(EvalError::Pipeline(format!(
                    "source '{id}' max_indicators must be a positive integer"
                )));
            }
        },
    };
    Ok(StixOptions {
        min_confidence,
        observables,
        max_indicators,
    })
}

fn parse_taxii_auth(id: &str, value: Option<&yaml_serde::Value>) -> Result<TaxiiAuthConfig> {
    let Some(value) = value else {
        return Ok(TaxiiAuthConfig::default());
    };
    let obj = value
        .as_mapping()
        .ok_or_else(|| EvalError::Pipeline(format!("source '{id}' auth must be a mapping")))?;
    for key in obj.keys() {
        let Some(name) = key.as_str() else {
            return Err(EvalError::Pipeline(format!(
                "source '{id}' auth keys must be strings"
            )));
        };
        if !matches!(
            name,
            "bearer_token_env"
                | "basic_user_env"
                | "basic_password_env"
                | "api_key_env"
                | "api_key_header"
        ) {
            return Err(EvalError::Pipeline(format!(
                "source '{id}' auth does not accept '{name}'"
            )));
        }
    }
    let bearer = env_name(id, obj, "bearer_token_env")?;
    let user = env_name(id, obj, "basic_user_env")?;
    let password = env_name(id, obj, "basic_password_env")?;
    let api_key = env_name(id, obj, "api_key_env")?;
    let api_key_header = env_name(id, obj, "api_key_header")?;
    if api_key_header.is_some() && api_key.is_none() {
        return Err(EvalError::Pipeline(format!(
            "source '{id}' api_key_header requires api_key_env"
        )));
    }
    if user.is_some() != password.is_some() {
        return Err(EvalError::Pipeline(format!(
            "source '{id}' basic auth requires basic_user_env and basic_password_env"
        )));
    }
    let methods = [
        bearer.is_some(),
        user.is_some() || password.is_some(),
        api_key.is_some(),
    ]
    .into_iter()
    .filter(|set| *set)
    .count();
    if methods != 1 {
        return Err(EvalError::Pipeline(format!(
            "source '{id}' must set exactly one TAXII auth method"
        )));
    }
    Ok(TaxiiAuthConfig {
        bearer_token_env: bearer,
        basic_user_env: user,
        basic_password_env: password,
        api_key_env: api_key,
        api_key_header,
    })
}

fn env_name(id: &str, obj: &yaml_serde::Mapping, key: &str) -> Result<Option<String>> {
    match obj.get(ykey(key)) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|name| !name.is_empty())
            .map(|name| Some(name.to_owned()))
            .ok_or_else(|| {
                EvalError::Pipeline(format!(
                    "source '{id}' {key} must be an environment variable name"
                ))
            }),
    }
}

fn is_collection_uuid(value: &str) -> bool {
    let mut parts = value.split('-');
    let widths = [8, 4, 4, 4, 12];
    widths.into_iter().all(|width| {
        parts.next().is_some_and(|part| {
            part.len() == width && part.chars().all(|ch| ch.is_ascii_hexdigit())
        })
    }) && parts.next().is_none()
}

fn parse_refresh_policy(value: Option<&yaml_serde::Value>) -> RefreshPolicy {
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

fn parse_error_policy(value: Option<&yaml_serde::Value>) -> ErrorPolicy {
    match value.and_then(|v| v.as_str()) {
        Some("use_cached") => ErrorPolicy::UseCached,
        Some("fail") => ErrorPolicy::Fail,
        Some("use_default") => ErrorPolicy::UseDefault,
        _ => ErrorPolicy::UseCached,
    }
}

fn parse_duration_field(value: Option<&yaml_serde::Value>) -> Option<Duration> {
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
    } else if let Some(days) = s.strip_suffix('d') {
        days.parse::<u64>()
            .ok()
            .map(|d| Duration::from_secs(d.saturating_mul(86_400)))
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

fn parse_string_headers(value: Option<&yaml_serde::Value>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(yaml_serde::Value::Mapping(m)) = value {
        for (k, v) in m {
            if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
                map.insert(key.to_string(), val.to_string());
            }
        }
    }
    map
}

fn parse_command_field(value: Option<&yaml_serde::Value>) -> Result<Vec<String>> {
    match value {
        Some(yaml_serde::Value::Sequence(seq)) => Ok(seq
            .iter()
            .filter_map(|item| item.as_str().map(String::from))
            .collect()),
        Some(yaml_serde::Value::String(s)) => Ok(vec![s.clone()]),
        _ => Ok(Vec::new()),
    }
}

// =============================================================================
// Cross-validation
// =============================================================================

/// Validate that every `${source.*}` reference and `include` target names a
/// source declared in an external source file. Returns an error listing all
/// undeclared source IDs.
///
/// `external_ids` is the set of source IDs declared outside the pipeline (via
/// `--source` files). When `None`, no external declarations are known yet, so
/// references cannot be resolved at parse time and validation is deferred (the
/// caller re-runs it once external sources are loaded).
pub fn validate_source_refs(
    refs: &[SourceRef],
    external_ids: Option<&std::collections::HashSet<String>>,
) -> Result<()> {
    if refs.is_empty() {
        return Ok(());
    }

    // Without a known external ID set (parse time), references are validated
    // later against the loaded `--source` files.
    let Some(external_ids) = external_ids else {
        return Ok(());
    };

    let undeclared: Vec<&str> = refs
        .iter()
        .filter(|r| !external_ids.contains(r.source_id.as_str()))
        .map(|r| r.source_id.as_str())
        .collect::<std::collections::HashSet<&str>>()
        .into_iter()
        .collect();

    if undeclared.is_empty() {
        Ok(())
    } else {
        Err(EvalError::Pipeline(format!(
            "pipeline references undeclared source(s): {}",
            undeclared.join(", ")
        )))
    }
}

// =============================================================================
// Template reference scanning
// =============================================================================

/// Record every `${source.*}` template in `text`, each at `location`.
fn push_source_refs(text: &str, location: impl Fn() -> RefLocation, refs: &mut Vec<SourceRef>) {
    for template in scan_source_templates(text) {
        refs.push(SourceRef {
            source_id: template.source_id.to_string(),
            sub_path: template.sub_path.map(str::to_string),
            location: location(),
            raw_template: template.raw.to_string(),
        });
    }
}

/// Scan the entire pipeline YAML for `${source.*}` template references and
/// `include` directives, returning all found references.
pub(crate) fn scan_source_refs(obj: &yaml_serde::Mapping) -> Vec<SourceRef> {
    let mut refs = Vec::new();

    // Scan vars. A var value can be a scalar string, a list of strings, or a
    // nested structure, so recurse rather than only matching scalar strings.
    if let Some(yaml_serde::Value::Mapping(vars)) = obj.get(ykey("vars")) {
        for (k, v) in vars {
            if let Some(var_name) = k.as_str() {
                scan_var_value_for_refs(v, var_name, &mut refs);
            }
        }
    }

    // Scan transformations
    if let Some(yaml_serde::Value::Sequence(transforms)) = obj.get(ykey("transformations")) {
        for (idx, item) in transforms.iter().enumerate() {
            if let Some(mapping) = item.as_mapping() {
                // Check for `include` directive
                if let Some(include_val) = mapping.get(ykey("include"))
                    && let Some(s) = yaml_value_as_str(include_val)
                {
                    push_source_refs(
                        s,
                        || RefLocation::Include {
                            transform_index: idx,
                        },
                        &mut refs,
                    );
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
    if let Some(yaml_serde::Value::Sequence(finalizers)) = obj.get(ykey("finalizers")) {
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

/// Recursively scan a `vars` value (scalar, list, or nested) for
/// `${source.*}` references, attributing each to the named variable.
fn scan_var_value_for_refs(value: &yaml_serde::Value, var_name: &str, refs: &mut Vec<SourceRef>) {
    match value {
        yaml_serde::Value::String(s) => {
            push_source_refs(
                s,
                || RefLocation::Var {
                    var_name: var_name.to_string(),
                },
                refs,
            );
        }
        yaml_serde::Value::Sequence(seq) => {
            for item in seq {
                scan_var_value_for_refs(item, var_name, refs);
            }
        }
        yaml_serde::Value::Mapping(m) => {
            for (_, v) in m {
                scan_var_value_for_refs(v, var_name, refs);
            }
        }
        _ => {}
    }
}

/// Recursively scan a YAML value for `${source.*}` references.
fn scan_yaml_value_for_refs(
    value: &yaml_serde::Value,
    transform_index: usize,
    field_name: &str,
    refs: &mut Vec<SourceRef>,
) {
    match value {
        yaml_serde::Value::String(s) => {
            push_source_refs(
                s,
                || RefLocation::TransformationField {
                    transform_index,
                    field_name: field_name.to_string(),
                },
                refs,
            );
        }
        yaml_serde::Value::Mapping(m) => {
            for (k, v) in m {
                let nested_field = if let Some(key) = k.as_str() {
                    format!("{field_name}.{key}")
                } else {
                    field_name.to_string()
                };
                scan_yaml_value_for_refs(v, transform_index, &nested_field, refs);
            }
        }
        yaml_serde::Value::Sequence(seq) => {
            for item in seq {
                scan_yaml_value_for_refs(item, transform_index, field_name, refs);
            }
        }
        _ => {}
    }
}

/// Helper to get a string from a YAML value (including tagged strings).
fn yaml_value_as_str(value: &yaml_serde::Value) -> Option<&str> {
    value.as_str()
}
