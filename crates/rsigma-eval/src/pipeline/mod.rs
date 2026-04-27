//! Processing pipeline system for transforming Sigma rules before evaluation.
//!
//! Pipelines are parsed from YAML and applied to `SigmaRule` AST nodes before
//! compilation, transforming field names, logsources, values, and detection
//! structure.
//!
//! # Architecture
//!
//! 1. Parse pipeline(s) from YAML
//! 2. Sort by priority (lower = first)
//! 3. For each rule: apply all pipeline transformations in order
//! 4. Compile the transformed rule
//! 5. Evaluate against events
//!
//! # Example
//!
//! ```rust
//! use rsigma_eval::pipeline::{Pipeline, parse_pipeline};
//!
//! let yaml = r#"
//! name: Sysmon Field Mapping
//! priority: 10
//! transformations:
//!   - id: sysmon_field_mapping
//!     type: field_name_mapping
//!     mapping:
//!       CommandLine: process.command_line
//!       ParentImage: process.parent.executable
//!     rule_conditions:
//!       - type: logsource
//!         product: windows
//! "#;
//!
//! let pipeline = parse_pipeline(yaml).unwrap();
//! assert_eq!(pipeline.name, "Sysmon Field Mapping");
//! ```

pub mod conditions;
pub mod finalizers;
pub mod state;
pub mod transformations;

use std::collections::HashMap;
use std::path::Path;

use rsigma_parser::{CorrelationRule, SigmaCollection, SigmaRule, SigmaString, SigmaValue};

use regex::Regex;

use crate::error::{EvalError, Result};

pub use conditions::{
    DetectionItemCondition, FieldNameCondition, NamedRuleCondition, RuleCondition,
    eval_condition_expr,
};
pub use finalizers::Finalizer;
pub use state::PipelineState;
pub use transformations::Transformation;

// =============================================================================
// Pipeline types
// =============================================================================

/// A processing pipeline consisting of ordered transformations with conditions.
#[derive(Debug, Clone)]
pub struct Pipeline {
    /// Pipeline name.
    pub name: String,
    /// Priority (lower runs first). Default: 0.
    pub priority: i32,
    /// Pipeline variables used for placeholder expansion.
    pub vars: HashMap<String, Vec<String>>,
    /// Ordered list of transformations with their conditions.
    pub transformations: Vec<TransformationItem>,
    /// Finalizers (stored for YAML compat; eval-mode ignores them).
    pub finalizers: Vec<Finalizer>,
}

/// A single transformation with its gating conditions.
#[derive(Debug, Clone)]
pub struct TransformationItem {
    /// Optional ID for tracking in pipeline state.
    pub id: Option<String>,
    /// The transformation to apply.
    pub transformation: Transformation,
    /// Rule-level conditions (all must match for the transformation to fire).
    pub rule_conditions: Vec<NamedRuleCondition>,
    /// Optional logical expression over condition IDs.
    pub rule_cond_expr: Option<String>,
    /// Detection-item-level conditions.
    pub detection_item_conditions: Vec<DetectionItemCondition>,
    /// Field-name-level conditions.
    pub field_name_conditions: Vec<FieldNameCondition>,
    /// If true, negate the field name conditions.
    pub field_name_cond_not: bool,
}

// =============================================================================
// Pipeline application
// =============================================================================

impl Pipeline {
    /// Apply this pipeline to a single `SigmaRule`, mutating it in place.
    pub fn apply(&self, rule: &mut SigmaRule, state: &mut PipelineState) -> Result<()> {
        state.reset_rule();

        for item in &self.transformations {
            // Check rule-level conditions
            if !self.check_rule_conditions(rule, state, item) {
                continue;
            }

            state.reset_detection_item();

            // Apply the transformation
            let applied = item.transformation.apply(
                rule,
                state,
                &item.detection_item_conditions,
                &item.field_name_conditions,
                item.field_name_cond_not,
            )?;

            // Track application in state
            if applied && let Some(ref id) = item.id {
                state.mark_applied(id);
            }
        }

        Ok(())
    }

    /// Apply this pipeline to all rules in a collection.
    ///
    /// Returns cloned, transformed rules (originals are not modified).
    pub fn apply_to_collection(&self, collection: &SigmaCollection) -> Result<Vec<SigmaRule>> {
        let mut state = PipelineState::new(self.vars.clone());
        let mut transformed = Vec::with_capacity(collection.rules.len());

        for rule in &collection.rules {
            let mut cloned = rule.clone();
            self.apply(&mut cloned, &mut state)?;
            transformed.push(cloned);
        }

        Ok(transformed)
    }

    fn check_rule_conditions(
        &self,
        rule: &SigmaRule,
        state: &PipelineState,
        item: &TransformationItem,
    ) -> bool {
        if item.rule_conditions.is_empty() {
            return true;
        }

        if let Some(ref expr) = item.rule_cond_expr {
            let mut results = HashMap::new();
            for (i, named) in item.rule_conditions.iter().enumerate() {
                let id = named.id.clone().unwrap_or_else(|| format!("cond_{i}"));
                results.insert(id, named.condition.matches_rule(rule, state));
            }
            return eval_condition_expr(expr, &results);
        }

        // Default: all conditions must match (AND)
        item.rule_conditions
            .iter()
            .all(|c| c.condition.matches_rule(rule, state))
    }

    /// Apply this pipeline to a correlation rule, mutating it in place.
    ///
    /// Only correlation-applicable transformations fire:
    /// - `FieldNameMapping` / `FieldNamePrefixMapping` — remap `group_by` and
    ///   `aliases` mapping values
    /// - `FieldNamePrefix` / `FieldNameSuffix` — modify `group_by` and alias values
    /// - `SetCustomAttribute` — set key-value on `custom_attributes`
    /// - `SetState` — update pipeline state
    /// - `RuleFailure` — error if conditions match
    ///
    /// Detection-specific transforms (value replacements, detection item
    /// manipulation, etc.) are silently skipped.
    pub fn apply_to_correlation(
        &self,
        corr: &mut CorrelationRule,
        state: &mut PipelineState,
    ) -> Result<()> {
        state.reset_rule();

        for item in &self.transformations {
            if !self.check_correlation_conditions(corr, state, item) {
                continue;
            }

            state.reset_detection_item();

            let applied = apply_correlation_transformation(corr, &item.transformation, state)?;

            if applied && let Some(ref id) = item.id {
                state.mark_applied(id);
            }
        }

        Ok(())
    }

    fn check_correlation_conditions(
        &self,
        corr: &CorrelationRule,
        state: &PipelineState,
        item: &TransformationItem,
    ) -> bool {
        if item.rule_conditions.is_empty() {
            return true;
        }

        if let Some(ref expr) = item.rule_cond_expr {
            let mut results = HashMap::new();
            for (i, named) in item.rule_conditions.iter().enumerate() {
                let id = named.id.clone().unwrap_or_else(|| format!("cond_{i}"));
                results.insert(id, named.condition.matches_correlation(corr, state));
            }
            return eval_condition_expr(expr, &results);
        }

        item.rule_conditions
            .iter()
            .all(|c| c.condition.matches_correlation(corr, state))
    }
}

/// Apply a single transformation to a correlation rule.
///
/// Returns `true` if the transformation was meaningfully applied.
fn apply_correlation_transformation(
    corr: &mut CorrelationRule,
    transformation: &Transformation,
    state: &mut PipelineState,
) -> Result<bool> {
    match transformation {
        Transformation::FieldNameMapping { mapping } => {
            // Match pySigma's FieldMappingTransformationBase.apply() for
            // correlation rules: group_by expands all alternatives, while
            // aliases and threshold field reject one-to-many mappings.
            let alias_names: std::collections::HashSet<String> =
                corr.aliases.iter().map(|a| a.alias.clone()).collect();

            // aliases: error if any mapping value has multiple alternatives
            for alias in &mut corr.aliases {
                for (rule_ref, field_name) in &mut alias.mapping {
                    if let Some(alts) = mapping.get(field_name.as_str())
                        && alts.len() > 1
                    {
                        return Err(EvalError::InvalidModifiers(format!(
                            "field_name_mapping one-to-many cannot be applied to \
                             correlation alias mapping (alias '{}', rule '{}', \
                             field '{}' maps to {} alternatives)",
                            alias.alias,
                            rule_ref,
                            field_name,
                            alts.len(),
                        )));
                    } else if let Some(alts) = mapping.get(field_name.as_str()) {
                        *field_name = alts[0].clone();
                    }
                }
            }

            // group_by: expand all alternatives (skip alias names)
            corr.group_by = corr
                .group_by
                .iter()
                .flat_map(|field_name| {
                    if alias_names.contains(field_name.as_str()) {
                        vec![field_name.clone()]
                    } else if let Some(alts) = mapping.get(field_name.as_str()) {
                        alts.clone()
                    } else {
                        vec![field_name.clone()]
                    }
                })
                .collect();

            // threshold field: error if multiple alternatives
            if let rsigma_parser::CorrelationCondition::Threshold { ref mut field, .. } =
                corr.condition
                && let Some(fields) = field.as_mut()
            {
                for f in fields.iter_mut() {
                    if let Some(alts) = mapping.get(f.as_str()) {
                        if alts.len() > 1 {
                            return Err(EvalError::InvalidModifiers(format!(
                                "field_name_mapping one-to-many cannot be applied to \
                                 correlation condition field reference ('{}' maps to \
                                 {} alternatives)",
                                f,
                                alts.len(),
                            )));
                        }
                        *f = alts[0].clone();
                    }
                }
            }

            Ok(true)
        }

        Transformation::FieldNamePrefixMapping { mapping } => {
            remap_correlation_fields(corr, |name| {
                for (prefix, replacement) in mapping {
                    if let Some(rest) = name.strip_prefix(prefix.as_str()) {
                        return Some(format!("{replacement}{rest}"));
                    }
                }
                None
            });
            Ok(true)
        }

        Transformation::FieldNamePrefix { prefix } => {
            remap_correlation_fields(corr, |name| Some(format!("{prefix}{name}")));
            Ok(true)
        }

        Transformation::FieldNameSuffix { suffix } => {
            remap_correlation_fields(corr, |name| Some(format!("{name}{suffix}")));
            Ok(true)
        }

        Transformation::SetCustomAttribute { attribute, value } => {
            corr.custom_attributes
                .insert(attribute.clone(), serde_yaml::Value::String(value.clone()));
            Ok(true)
        }

        Transformation::SetState { key, value } => {
            state.set_state(key.clone(), serde_json::Value::String(value.clone()));
            Ok(true)
        }

        Transformation::RuleFailure { message } => Err(EvalError::InvalidModifiers(format!(
            "Pipeline rule failure: {message} (correlation: {})",
            corr.title
        ))),

        // Detection-specific transforms are no-ops for correlations
        _ => Ok(false),
    }
}

/// Apply a field name mapping function to all field references in a correlation rule:
/// `group_by` entries, `aliases` mapping values, and the `condition` field.
fn remap_correlation_fields(corr: &mut CorrelationRule, mapper: impl Fn(&str) -> Option<String>) {
    for field in &mut corr.group_by {
        if let Some(new_name) = mapper(field) {
            *field = new_name;
        }
    }

    for alias in &mut corr.aliases {
        let remapped: HashMap<String, String> = alias
            .mapping
            .iter()
            .map(|(rule_ref, field_name)| {
                let new_name = mapper(field_name).unwrap_or_else(|| field_name.clone());
                (rule_ref.clone(), new_name)
            })
            .collect();
        alias.mapping = remapped;
    }

    if let rsigma_parser::CorrelationCondition::Threshold { ref mut field, .. } = corr.condition
        && let Some(fields) = field.as_mut()
    {
        for f in fields.iter_mut() {
            if let Some(new_name) = mapper(f) {
                *f = new_name;
            }
        }
    }
}

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

fn build_field_matcher(fields: Vec<String>, is_regex: bool) -> Result<conditions::FieldMatcher> {
    if is_regex {
        let regexes = fields
            .iter()
            .map(|p| {
                Regex::new(p).map_err(|e| {
                    EvalError::InvalidModifiers(format!("invalid field regex '{p}': {e}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(conditions::FieldMatcher::Regex(regexes))
    } else {
        Ok(conditions::FieldMatcher::Plain(fields))
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
// Multi-pipeline support
// =============================================================================

/// Sort pipelines by priority (lower = first) and apply them in order.
pub fn merge_pipelines(pipelines: &mut [Pipeline]) {
    pipelines.sort_by_key(|p| p.priority);
}

/// Apply multiple pipelines to a rule in priority order.
///
/// Each pipeline gets its own `PipelineState`, but the state is carried across
/// transformations within a single pipeline.
pub fn apply_pipelines(pipelines: &[Pipeline], rule: &mut SigmaRule) -> Result<()> {
    for pipeline in pipelines {
        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply(rule, &mut state)?;
    }
    Ok(())
}

/// Apply multiple pipelines to a rule, returning the merged [`PipelineState`].
///
/// Unlike [`apply_pipelines`], this function accumulates state from all pipelines
/// into a single `PipelineState` so that conversion backends can read values set
/// by `SetState` and `QueryExpressionPlaceholders` transformations.
pub fn apply_pipelines_with_state(
    pipelines: &[Pipeline],
    rule: &mut SigmaRule,
) -> Result<PipelineState> {
    let mut merged = PipelineState::default();
    for pipeline in pipelines {
        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply(rule, &mut state)?;
        for (k, v) in state.state {
            merged.state.insert(k, v);
        }
        merged.applied_items.extend(state.applied_items);
        merged.vars.extend(state.vars);
    }
    Ok(merged)
}

/// Apply multiple pipelines to a correlation rule in priority order,
/// returning the merged pipeline state.
pub fn apply_pipelines_to_correlation(
    pipelines: &[Pipeline],
    corr: &mut CorrelationRule,
) -> Result<PipelineState> {
    let mut merged = PipelineState::default();
    for pipeline in pipelines {
        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply_to_correlation(corr, &mut state)?;
        for (k, v) in state.state {
            merged.state.insert(k, v);
        }
        merged.applied_items.extend(state.applied_items);
        merged.vars.extend(state.vars);
    }
    Ok(merged)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_pipeline() {
        let yaml = r#"
name: Test Pipeline
priority: 10
transformations:
  - id: map_fields
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      ParentImage: process.parent.executable
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        assert_eq!(pipeline.name, "Test Pipeline");
        assert_eq!(pipeline.priority, 10);
        assert_eq!(pipeline.transformations.len(), 1);
        assert_eq!(
            pipeline.transformations[0].id,
            Some("map_fields".to_string())
        );
    }

    #[test]
    fn test_parse_pipeline_with_conditions() {
        let yaml = r#"
name: Windows Pipeline
priority: 20
transformations:
  - id: sysmon_fields
    type: field_name_mapping
    mapping:
      CommandLine: winlog.event_data.CommandLine
    rule_conditions:
      - type: logsource
        product: windows
        category: process_creation
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        assert_eq!(pipeline.transformations.len(), 1);
        assert_eq!(pipeline.transformations[0].rule_conditions.len(), 1);
    }

    #[test]
    fn test_parse_pipeline_with_vars() {
        let yaml = r#"
name: Vars Pipeline
vars:
  admin_users:
    - root
    - admin
  log_index: windows-*
transformations: []
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        assert_eq!(pipeline.vars.len(), 2);
        assert_eq!(
            pipeline.vars["admin_users"],
            vec!["root".to_string(), "admin".to_string()]
        );
        assert_eq!(pipeline.vars["log_index"], vec!["windows-*".to_string()]);
    }

    #[test]
    fn test_parse_pipeline_with_finalizers() {
        let yaml = r#"
name: Output Pipeline
transformations: []
finalizers:
  - type: concat
    separator: " OR "
  - type: json
    indent: 2
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        assert_eq!(pipeline.finalizers.len(), 2);
    }

    #[test]
    fn test_apply_field_mapping_pipeline() {
        let yaml = r#"
name: Sysmon
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
    rule_conditions:
      - type: logsource
        product: windows
"#;
        let pipeline = parse_pipeline(yaml).unwrap();

        // Create a rule that matches the condition
        let mut rule = rsigma_parser::SigmaRule {
            title: "Test".to_string(),
            logsource: rsigma_parser::LogSource {
                product: Some("windows".to_string()),
                category: Some("process_creation".to_string()),
                ..Default::default()
            },
            detection: rsigma_parser::Detections {
                named: {
                    let mut m = HashMap::new();
                    m.insert(
                        "selection".to_string(),
                        rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                            field: rsigma_parser::FieldSpec::new(
                                Some("CommandLine".to_string()),
                                vec![rsigma_parser::Modifier::Contains],
                            ),
                            values: vec![SigmaValue::String(SigmaString::new("whoami"))],
                        }]),
                    );
                    m
                },
                conditions: vec![rsigma_parser::ConditionExpr::Identifier(
                    "selection".to_string(),
                )],
                condition_strings: vec!["selection".to_string()],
                timeframe: None,
            },
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec![],
            scope: vec![],
            custom_attributes: std::collections::HashMap::new(),
        };

        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply(&mut rule, &mut state).unwrap();

        // Check that field was renamed
        let det = &rule.detection.named["selection"];
        if let rsigma_parser::Detection::AllOf(items) = det {
            assert_eq!(
                items[0].field.name,
                Some("process.command_line".to_string())
            );
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_pipeline_skips_non_matching_rules() {
        let yaml = r#"
name: Windows Only
transformations:
  - type: field_name_prefix
    prefix: "win."
    rule_conditions:
      - type: logsource
        product: windows
"#;
        let pipeline = parse_pipeline(yaml).unwrap();

        // Create a Linux rule — should NOT be modified
        let mut rule = rsigma_parser::SigmaRule {
            title: "Linux Rule".to_string(),
            logsource: rsigma_parser::LogSource {
                product: Some("linux".to_string()),
                ..Default::default()
            },
            detection: rsigma_parser::Detections {
                named: {
                    let mut m = HashMap::new();
                    m.insert(
                        "sel".to_string(),
                        rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                            field: rsigma_parser::FieldSpec::new(
                                Some("CommandLine".to_string()),
                                vec![],
                            ),
                            values: vec![SigmaValue::String(SigmaString::new("test"))],
                        }]),
                    );
                    m
                },
                conditions: vec![rsigma_parser::ConditionExpr::Identifier("sel".to_string())],
                condition_strings: vec!["sel".to_string()],
                timeframe: None,
            },
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec![],
            scope: vec![],
            custom_attributes: std::collections::HashMap::new(),
        };

        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply(&mut rule, &mut state).unwrap();

        // Field should NOT have been prefixed
        let det = &rule.detection.named["sel"];
        if let rsigma_parser::Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_merge_pipelines_sorts_by_priority() {
        let mut pipelines = vec![
            Pipeline {
                name: "C".to_string(),
                priority: 30,
                vars: HashMap::new(),
                transformations: vec![],
                finalizers: vec![],
            },
            Pipeline {
                name: "A".to_string(),
                priority: 10,
                vars: HashMap::new(),
                transformations: vec![],
                finalizers: vec![],
            },
            Pipeline {
                name: "B".to_string(),
                priority: 20,
                vars: HashMap::new(),
                transformations: vec![],
                finalizers: vec![],
            },
        ];

        merge_pipelines(&mut pipelines);

        assert_eq!(pipelines[0].name, "A");
        assert_eq!(pipelines[1].name, "B");
        assert_eq!(pipelines[2].name, "C");
    }

    #[test]
    fn test_parse_all_transformation_types() {
        let yaml = r#"
name: All Types
transformations:
  - type: field_name_mapping
    mapping:
      a: b
  - type: field_name_prefix_mapping
    mapping:
      old_: new_
  - type: field_name_prefix
    prefix: "pfx."
  - type: field_name_suffix
    suffix: ".sfx"
  - type: drop_detection_item
  - type: add_condition
    conditions:
      index: test
  - type: change_logsource
    category: new_cat
  - type: replace_string
    regex: "old"
    replacement: "new"
  - type: value_placeholders
  - type: wildcard_placeholders
  - type: query_expression_placeholders
    expression: "{field}={value}"
  - type: set_state
    key: k
    value: v
  - type: rule_failure
    message: fail
  - type: detection_item_failure
    message: fail
  - type: field_name_transform
    transform_func: lower
  - type: hashes_fields
    valid_hash_algos:
      - MD5
      - SHA1
    field_prefix: File
  - type: map_string
    mapping:
      old_val: new_val
  - type: set_value
    value: fixed
  - type: convert_type
    target_type: int
  - type: regex
  - type: add_field
    field: EventID
  - type: remove_field
    field: OldField
  - type: set_field
    fields:
      - field1
      - field2
  - type: set_custom_attribute
    attribute: backend
    value: splunk
  - type: case_transformation
    case_type: lower
  - type: nest
    items:
      - type: field_name_prefix
        prefix: "inner."
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        assert_eq!(pipeline.transformations.len(), 26);
    }

    #[test]
    fn test_parse_all_condition_types() {
        let yaml = r#"
name: Conditions
transformations:
  - type: field_name_prefix
    prefix: "x."
    rule_conditions:
      - type: logsource
        product: windows
      - type: contains_detection_item
        field: EventID
        value: "1"
      - type: processing_item_applied
        processing_item_id: prev_step
      - type: processing_state
        key: k
        val: v
      - type: is_sigma_rule
      - type: is_sigma_correlation_rule
      - type: rule_attribute
        attribute: level
        value: high
      - type: tag
        tag: attack.execution
    detection_item_conditions:
      - type: match_string
        pattern: "^test"
        negate: false
      - type: is_null
        negate: true
      - type: processing_item_applied
        processing_item_id: x
      - type: processing_state
        key: k
        val: v
    field_name_conditions:
      - type: include_fields
        fields:
          - CommandLine
      - type: exclude_fields
        fields:
          - Hostname
        match_type: regex
      - type: processing_item_applied
        processing_item_id: y
      - type: processing_state
        key: a
        val: b
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        let item = &pipeline.transformations[0];
        assert_eq!(item.rule_conditions.len(), 8);
        assert_eq!(item.detection_item_conditions.len(), 4);
        assert_eq!(item.field_name_conditions.len(), 4);
    }

    #[test]
    fn test_named_condition_ids_in_rule_cond_expression() {
        let yaml = r#"
name: Named Conditions
transformations:
  - type: field_name_prefix
    prefix: "win."
    rule_conditions:
      - id: is_windows
        type: logsource
        product: windows
      - id: is_process
        type: logsource
        category: process_creation
    rule_cond_expression: "is_windows or is_process"
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        let item = &pipeline.transformations[0];
        assert_eq!(item.rule_conditions[0].id, Some("is_windows".to_string()));
        assert_eq!(item.rule_conditions[1].id, Some("is_process".to_string()));

        // Windows + process_creation => both match, OR is true => prefix applied
        let mut rule = rsigma_parser::SigmaRule {
            title: "Test".to_string(),
            logsource: rsigma_parser::LogSource {
                product: Some("windows".to_string()),
                category: Some("process_creation".to_string()),
                ..Default::default()
            },
            detection: rsigma_parser::Detections {
                named: {
                    let mut m = HashMap::new();
                    m.insert(
                        "sel".to_string(),
                        rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                            field: rsigma_parser::FieldSpec::new(
                                Some("CommandLine".to_string()),
                                vec![],
                            ),
                            values: vec![SigmaValue::String(SigmaString::new("test"))],
                        }]),
                    );
                    m
                },
                conditions: vec![rsigma_parser::ConditionExpr::Identifier("sel".to_string())],
                condition_strings: vec!["sel".to_string()],
                timeframe: None,
            },
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec![],
            scope: vec![],
            custom_attributes: HashMap::new(),
        };

        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply(&mut rule, &mut state).unwrap();

        let det = &rule.detection.named["sel"];
        if let rsigma_parser::Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("win.CommandLine".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_named_cond_expression_or_logic() {
        // Only is_process matches (linux, not windows), but OR means it still applies
        let yaml = r#"
name: OR Logic
transformations:
  - type: field_name_prefix
    prefix: "mapped."
    rule_conditions:
      - id: is_windows
        type: logsource
        product: windows
      - id: is_process
        type: logsource
        category: process_creation
    rule_cond_expression: "is_windows or is_process"
"#;
        let pipeline = parse_pipeline(yaml).unwrap();

        let mut rule = rsigma_parser::SigmaRule {
            title: "Linux Process".to_string(),
            logsource: rsigma_parser::LogSource {
                product: Some("linux".to_string()),
                category: Some("process_creation".to_string()),
                ..Default::default()
            },
            detection: rsigma_parser::Detections {
                named: {
                    let mut m = HashMap::new();
                    m.insert(
                        "sel".to_string(),
                        rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                            field: rsigma_parser::FieldSpec::new(Some("Image".to_string()), vec![]),
                            values: vec![SigmaValue::String(SigmaString::new("/bin/sh"))],
                        }]),
                    );
                    m
                },
                conditions: vec![rsigma_parser::ConditionExpr::Identifier("sel".to_string())],
                condition_strings: vec!["sel".to_string()],
                timeframe: None,
            },
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec![],
            scope: vec![],
            custom_attributes: HashMap::new(),
        };

        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply(&mut rule, &mut state).unwrap();

        // is_windows=false, is_process=true => OR => applied
        let det = &rule.detection.named["sel"];
        if let rsigma_parser::Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("mapped.Image".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_named_cond_expression_and_logic() {
        // AND: both must match
        let yaml = r#"
name: AND Logic
transformations:
  - type: field_name_prefix
    prefix: "win."
    rule_conditions:
      - id: is_windows
        type: logsource
        product: windows
      - id: is_process
        type: logsource
        category: process_creation
    rule_cond_expression: "is_windows and is_process"
"#;
        let pipeline = parse_pipeline(yaml).unwrap();

        // Linux + process_creation => is_windows=false => AND fails => no prefix
        let mut rule = rsigma_parser::SigmaRule {
            title: "Linux Rule".to_string(),
            logsource: rsigma_parser::LogSource {
                product: Some("linux".to_string()),
                category: Some("process_creation".to_string()),
                ..Default::default()
            },
            detection: rsigma_parser::Detections {
                named: {
                    let mut m = HashMap::new();
                    m.insert(
                        "sel".to_string(),
                        rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                            field: rsigma_parser::FieldSpec::new(Some("Image".to_string()), vec![]),
                            values: vec![SigmaValue::String(SigmaString::new("/bin/sh"))],
                        }]),
                    );
                    m
                },
                conditions: vec![rsigma_parser::ConditionExpr::Identifier("sel".to_string())],
                condition_strings: vec!["sel".to_string()],
                timeframe: None,
            },
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec![],
            scope: vec![],
            custom_attributes: HashMap::new(),
        };

        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply(&mut rule, &mut state).unwrap();

        // is_windows=false => AND => not applied
        let det = &rule.detection.named["sel"];
        if let rsigma_parser::Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("Image".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_unnamed_conditions_fallback_to_cond_n() {
        let yaml = r#"
name: Fallback IDs
transformations:
  - type: field_name_prefix
    prefix: "x."
    rule_conditions:
      - type: logsource
        product: windows
      - type: logsource
        category: process_creation
    rule_cond_expression: "cond_0 or cond_1"
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        assert!(pipeline.transformations[0].rule_conditions[0].id.is_none());
        assert!(pipeline.transformations[0].rule_conditions[1].id.is_none());

        let mut rule = rsigma_parser::SigmaRule {
            title: "Test".to_string(),
            logsource: rsigma_parser::LogSource {
                product: Some("linux".to_string()),
                category: Some("process_creation".to_string()),
                ..Default::default()
            },
            detection: rsigma_parser::Detections {
                named: {
                    let mut m = HashMap::new();
                    m.insert(
                        "sel".to_string(),
                        rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                            field: rsigma_parser::FieldSpec::new(Some("Field".to_string()), vec![]),
                            values: vec![SigmaValue::String(SigmaString::new("val"))],
                        }]),
                    );
                    m
                },
                conditions: vec![rsigma_parser::ConditionExpr::Identifier("sel".to_string())],
                condition_strings: vec!["sel".to_string()],
                timeframe: None,
            },
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec![],
            scope: vec![],
            custom_attributes: HashMap::new(),
        };

        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply(&mut rule, &mut state).unwrap();

        // cond_0 (windows)=false, cond_1 (process_creation)=true => OR => applied
        let det = &rule.detection.named["sel"];
        if let rsigma_parser::Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("x.Field".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    // =========================================================================
    // Correlation pipeline tests
    // =========================================================================

    fn make_test_correlation() -> CorrelationRule {
        CorrelationRule {
            title: "Test Correlation".to_string(),
            id: Some("corr-1".to_string()),
            name: Some("test_corr".to_string()),
            status: None,
            description: None,
            author: None,
            date: None,
            modified: None,
            related: vec![],
            references: vec![],
            taxonomy: None,
            license: None,
            tags: vec![],
            fields: vec![],
            falsepositives: vec![],
            level: None,
            scope: vec![],
            correlation_type: rsigma_parser::CorrelationType::EventCount,
            rules: vec!["rule_a".to_string()],
            group_by: vec!["SourceIP".to_string(), "DestinationIP".to_string()],
            timespan: rsigma_parser::Timespan::parse("5m").unwrap(),
            condition: rsigma_parser::CorrelationCondition::Threshold {
                predicates: vec![(rsigma_parser::ConditionOperator::Gte, 10)],
                field: None,
                percentile: None,
            },
            aliases: vec![rsigma_parser::FieldAlias {
                alias: "src_ip".to_string(),
                mapping: {
                    let mut m = HashMap::new();
                    m.insert("rule_a".to_string(), "SourceIP".to_string());
                    m
                },
            }],
            generate: true,
            custom_attributes: HashMap::new(),
        }
    }

    #[test]
    fn test_correlation_pipeline_field_name_mapping() {
        let yaml = r#"
name: ECS Field Mapping
transformations:
  - type: field_name_mapping
    mapping:
      SourceIP: source.ip
      DestinationIP: destination.ip
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        let mut corr = make_test_correlation();

        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline
            .apply_to_correlation(&mut corr, &mut state)
            .unwrap();

        assert_eq!(corr.group_by, vec!["source.ip", "destination.ip"]);
        assert_eq!(corr.aliases[0].mapping["rule_a"], "source.ip");
    }

    #[test]
    fn test_correlation_field_mapping_group_by_expands_all_alternatives() {
        let yaml = r#"
name: Multi-field
transformations:
  - type: field_name_mapping
    mapping:
      DestinationIP:
        - dst.ip
        - dest.address
      SourceIP: src.ip
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        let mut corr = make_test_correlation();
        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline
            .apply_to_correlation(&mut corr, &mut state)
            .unwrap();

        // SourceIP is 1:1 (and also in an alias), DestinationIP expands
        assert_eq!(
            corr.group_by,
            vec!["src.ip", "dst.ip", "dest.address"],
            "group_by should expand all alternatives for DestinationIP"
        );
        // alias SourceIP should be remapped 1:1
        assert_eq!(corr.aliases[0].mapping["rule_a"], "src.ip");
    }

    #[test]
    fn test_correlation_field_mapping_alias_rejects_one_to_many() {
        let yaml = r#"
name: Alias conflict
transformations:
  - type: field_name_mapping
    mapping:
      SourceIP:
        - src.ip
        - source.address
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        let mut corr = make_test_correlation();
        let mut state = PipelineState::new(pipeline.vars.clone());
        let err = pipeline
            .apply_to_correlation(&mut corr, &mut state)
            .expect_err("alias with one-to-many must error");
        let msg = format!("{err}");
        assert!(msg.contains("alias"), "error should mention alias: {msg}");
    }

    #[test]
    fn test_correlation_field_mapping_threshold_field_rejects_one_to_many() {
        let yaml = r#"
name: Threshold conflict
transformations:
  - type: field_name_mapping
    mapping:
      UserName:
        - user.name
        - user.id
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        let mut corr = make_test_correlation();
        corr.condition = rsigma_parser::CorrelationCondition::Threshold {
            predicates: vec![(rsigma_parser::ConditionOperator::Gte, 5)],
            field: Some(vec!["UserName".to_string()]),
            percentile: None,
        };
        let mut state = PipelineState::new(pipeline.vars.clone());
        let err = pipeline
            .apply_to_correlation(&mut corr, &mut state)
            .expect_err("threshold field with one-to-many must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("condition field reference"),
            "error should mention condition field: {msg}"
        );
    }

    #[test]
    fn test_correlation_pipeline_field_prefix() {
        let yaml = r#"
name: Prefix
transformations:
  - type: field_name_prefix
    prefix: "event."
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        let mut corr = make_test_correlation();

        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline
            .apply_to_correlation(&mut corr, &mut state)
            .unwrap();

        assert_eq!(corr.group_by, vec!["event.SourceIP", "event.DestinationIP"]);
    }

    #[test]
    fn test_correlation_pipeline_set_custom_attribute() {
        let yaml = r#"
name: Custom Attr
transformations:
  - type: set_custom_attribute
    attribute: rsigma.action
    value: reset
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        let mut corr = make_test_correlation();

        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline
            .apply_to_correlation(&mut corr, &mut state)
            .unwrap();

        assert_eq!(
            corr.custom_attributes["rsigma.action"],
            serde_yaml::Value::String("reset".to_string())
        );
    }

    #[test]
    fn test_correlation_pipeline_skips_detection_rules() {
        let yaml = r#"
name: Detection Only
transformations:
  - type: field_name_prefix
    prefix: "x."
    rule_conditions:
      - type: is_sigma_rule
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        let mut corr = make_test_correlation();

        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline
            .apply_to_correlation(&mut corr, &mut state)
            .unwrap();

        // is_sigma_rule => false for correlations => not applied
        assert_eq!(corr.group_by, vec!["SourceIP", "DestinationIP"]);
    }

    #[test]
    fn test_correlation_pipeline_rule_failure() {
        let yaml = r#"
name: Block Correlations
transformations:
  - type: rule_failure
    message: "correlations not supported by this backend"
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        let mut corr = make_test_correlation();

        let mut state = PipelineState::new(pipeline.vars.clone());
        let result = pipeline.apply_to_correlation(&mut corr, &mut state);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("correlations not supported"));
    }

    #[test]
    fn test_correlation_pipeline_condition_field_mapping() {
        let yaml = r#"
name: Condition Field Mapping
transformations:
  - type: field_name_mapping
    mapping:
      UserName: user.name
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
        let pipeline = parse_pipeline(yaml).unwrap();

        let mut corr = make_test_correlation();
        corr.condition = rsigma_parser::CorrelationCondition::Threshold {
            predicates: vec![(rsigma_parser::ConditionOperator::Gte, 5)],
            field: Some(vec!["UserName".to_string()]),
            percentile: None,
        };

        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline
            .apply_to_correlation(&mut corr, &mut state)
            .unwrap();

        if let rsigma_parser::CorrelationCondition::Threshold { field, .. } = &corr.condition {
            assert_eq!(field.as_deref(), Some(["user.name".to_string()].as_slice()));
        } else {
            panic!("Expected Threshold");
        }
    }

    #[test]
    fn test_apply_pipelines_to_correlation_fn() {
        let yaml = r#"
name: ECS Mapping
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
      SourceIP: source.ip
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
        let pipeline = parse_pipeline(yaml).unwrap();
        let mut corr = make_test_correlation();

        apply_pipelines_to_correlation(&[pipeline], &mut corr).unwrap();

        assert_eq!(corr.group_by[0], "source.ip");
    }
}
