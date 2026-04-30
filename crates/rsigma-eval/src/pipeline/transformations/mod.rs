//! Pipeline transformations that mutate `SigmaRule` AST nodes.
//!
//! All 26 pySigma transformation types are implemented as variants of the
//! [`Transformation`] enum. Each variant carries its configuration parameters
//! and is applied via the [`Transformation::apply`] method.

mod helpers;
#[cfg(test)]
mod tests;

use std::collections::HashMap;

use regex::Regex;

use rsigma_parser::{SigmaRule, SigmaValue};

use super::conditions::{DetectionItemCondition, FieldNameCondition};
use super::state::PipelineState;
use crate::error::{EvalError, Result};

// =============================================================================
// Transformation enum
// =============================================================================

/// All supported pipeline transformation types.
#[derive(Debug, Clone)]
pub enum Transformation {
    /// Map field names via a lookup table.
    ///
    /// Supports pySigma-compatible one-to-many mapping: a single source name
    /// can map to a list of alternative field names. When more than one
    /// alternative is present, the matched detection item is replaced with
    /// an OR-conjunction (`AnyOf`) of items, one per alternative — preserving
    /// the rule's original AND structure across the rest of the items in the
    /// same selection via a Cartesian expansion.
    ///
    /// For correlation rules, `group_by` fields are expanded to include all
    /// alternatives (alias names are left untouched). `aliases` mapping values
    /// and threshold `field` reject one-to-many mappings with an error since
    /// those positions are inherently scalar.
    FieldNameMapping {
        mapping: HashMap<String, Vec<String>>,
    },

    /// Map field name prefixes.
    FieldNamePrefixMapping { mapping: HashMap<String, String> },

    /// Add a prefix to all matched field names.
    FieldNamePrefix { prefix: String },

    /// Add a suffix to all matched field names.
    FieldNameSuffix { suffix: String },

    /// Remove matching detection items.
    DropDetectionItem,

    /// Add field=value conditions to the rule's detection.
    AddCondition {
        conditions: HashMap<String, SigmaValue>,
        /// If true, negate the added conditions.
        negated: bool,
    },

    /// Replace logsource fields.
    ChangeLogsource {
        category: Option<String>,
        product: Option<String>,
        service: Option<String>,
    },

    /// Regex replacement in string values.
    ///
    /// When `skip_special` is true, replacement is applied only to the plain
    /// (non-wildcard) segments of `SigmaString`, preserving `*` and `?` wildcards.
    /// Mirrors pySigma's `ReplaceStringTransformation.skip_special`.
    ReplaceString {
        regex: String,
        replacement: String,
        skip_special: bool,
    },

    /// Expand `%name%` placeholders with pipeline variables.
    ValuePlaceholders,

    /// Replace unresolved `%name%` placeholders with `*` wildcard.
    WildcardPlaceholders,

    /// Store expression template (no-op for eval, kept for YAML compat).
    QueryExpressionPlaceholders { expression: String },

    /// Set key-value in pipeline state.
    SetState { key: String, value: String },

    /// Fail if rule conditions match.
    RuleFailure { message: String },

    /// Fail if detection item conditions match.
    DetectionItemFailure { message: String },

    /// Apply a named function to field names (lowercase, uppercase, etc.).
    /// In pySigma this takes a Python callable; we support named functions.
    FieldNameTransform {
        /// One of: "lower", "upper", "title", "snake_case"
        transform_func: String,
        /// Explicit overrides: field → new_name (applied instead of the function).
        mapping: HashMap<String, String>,
    },

    /// Decompose the `Hashes` field into per-algorithm fields.
    ///
    /// `Hashes: "SHA1=abc,MD5=def"` → `FileSHA1: abc` + `FileMD5: def`
    HashesFields {
        /// Allowed hash algorithms (e.g. `["MD5", "SHA1", "SHA256"]`).
        valid_hash_algos: Vec<String>,
        /// Prefix for generated field names (e.g. `"File"` → `FileMD5`).
        field_prefix: String,
        /// If true, omit algo name from field (use just prefix).
        drop_algo_prefix: bool,
    },

    /// Map string values via a lookup table.
    ///
    /// Supports one-to-many mapping: a single value can map to multiple
    /// alternatives (pySigma compat). When one-to-many is used, the detection
    /// item's values list is expanded in place.
    MapString {
        mapping: HashMap<String, Vec<String>>,
    },

    /// Set all values of matching detection items to a fixed value.
    SetValue { value: SigmaValue },

    /// Convert detection item values to a different type.
    /// Supported: "str", "int", "float", "bool".
    ConvertType { target_type: String },

    /// Convert plain string values to regex patterns.
    Regex,

    /// Add a field name to the rule's output `fields` list.
    AddField { field: String },

    /// Remove a field name from the rule's output `fields` list.
    RemoveField { field: String },

    /// Set (replace) the rule's output `fields` list.
    SetField { fields: Vec<String> },

    /// Set a custom attribute on the rule.
    ///
    /// Stores the key-value pair in `SigmaRule.custom_attributes` as a
    /// `serde_yaml::Value::String`. Backends / engines can read these to
    /// modify per-rule behavior (e.g. `rsigma.suppress`, `rsigma.action`).
    /// Mirrors pySigma's `SetCustomAttributeTransformation`.
    SetCustomAttribute { attribute: String, value: String },

    /// Apply a case transformation to string values.
    /// Supported: "lower", "upper", "snake_case".
    CaseTransformation { case_type: String },

    /// Nested sub-pipeline: apply a list of transformations as a group.
    /// The inner items share the same conditions as the outer item.
    Nest {
        items: Vec<super::TransformationItem>,
    },
}

// =============================================================================
// Application logic
// =============================================================================

impl Transformation {
    /// Apply this transformation to a `SigmaRule`, mutating it in place.
    ///
    /// Returns `Ok(true)` if the transformation was applied, `Ok(false)` if skipped.
    pub fn apply(
        &self,
        rule: &mut SigmaRule,
        state: &mut PipelineState,
        detection_item_conditions: &[DetectionItemCondition],
        field_name_conditions: &[FieldNameCondition],
        field_name_cond_not: bool,
    ) -> Result<bool> {
        match self {
            Transformation::FieldNameMapping { mapping } => {
                helpers::apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| mapping.get(name).cloned(),
                )?;
                Ok(true)
            }

            Transformation::FieldNamePrefixMapping { mapping } => {
                helpers::apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| {
                        for (prefix, replacement) in mapping {
                            if name.starts_with(prefix.as_str()) {
                                return Some(vec![format!(
                                    "{}{}",
                                    replacement,
                                    &name[prefix.len()..]
                                )]);
                            }
                        }
                        None
                    },
                )?;
                Ok(true)
            }

            Transformation::FieldNamePrefix { prefix } => {
                helpers::apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| Some(vec![format!("{prefix}{name}")]),
                )?;
                Ok(true)
            }

            Transformation::FieldNameSuffix { suffix } => {
                helpers::apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| Some(vec![format!("{name}{suffix}")]),
                )?;
                Ok(true)
            }

            Transformation::DropDetectionItem => {
                helpers::drop_detection_items(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                );
                Ok(true)
            }

            Transformation::AddCondition {
                conditions,
                negated,
            } => {
                helpers::add_conditions(rule, conditions, *negated);
                Ok(true)
            }

            Transformation::ChangeLogsource {
                category,
                product,
                service,
            } => {
                if let Some(cat) = category {
                    rule.logsource.category = Some(cat.clone());
                }
                if let Some(prod) = product {
                    rule.logsource.product = Some(prod.clone());
                }
                if let Some(svc) = service {
                    rule.logsource.service = Some(svc.clone());
                }
                Ok(true)
            }

            Transformation::ReplaceString {
                regex,
                replacement,
                skip_special,
            } => {
                let re = Regex::new(regex)
                    .map_err(|e| EvalError::InvalidModifiers(format!("bad regex: {e}")))?;
                helpers::replace_strings_in_rule(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    &re,
                    replacement,
                    *skip_special,
                );
                Ok(true)
            }

            Transformation::ValuePlaceholders => {
                helpers::expand_placeholders_in_rule(rule, state, false);
                Ok(true)
            }

            Transformation::WildcardPlaceholders => {
                helpers::expand_placeholders_in_rule(rule, state, true);
                Ok(true)
            }

            Transformation::QueryExpressionPlaceholders { expression } => {
                state.set_state(
                    "query_expression_template".to_string(),
                    serde_json::Value::String(expression.clone()),
                );
                Ok(true)
            }

            Transformation::SetState { key, value } => {
                state.set_state(key.clone(), serde_json::Value::String(value.clone()));
                Ok(true)
            }

            Transformation::RuleFailure { message } => Err(EvalError::InvalidModifiers(format!(
                "Pipeline rule failure: {message} (rule: {})",
                rule.title
            ))),

            Transformation::DetectionItemFailure { message } => {
                let has_match =
                    helpers::rule_has_matching_item(rule, state, detection_item_conditions);
                if has_match {
                    Err(EvalError::InvalidModifiers(format!(
                        "Pipeline detection item failure: {message} (rule: {})",
                        rule.title
                    )))
                } else {
                    Ok(false)
                }
            }

            Transformation::FieldNameTransform {
                transform_func,
                mapping,
            } => {
                let func = transform_func.clone();
                let map = mapping.clone();
                helpers::apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| {
                        if let Some(mapped) = map.get(name) {
                            return Some(vec![mapped.clone()]);
                        }
                        Some(vec![helpers::apply_named_string_fn(&func, name)])
                    },
                )?;
                Ok(true)
            }

            Transformation::HashesFields {
                valid_hash_algos,
                field_prefix,
                drop_algo_prefix,
            } => {
                helpers::decompose_hashes_field(
                    rule,
                    valid_hash_algos,
                    field_prefix,
                    *drop_algo_prefix,
                );
                Ok(true)
            }

            Transformation::MapString { mapping } => {
                helpers::map_string_values(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    mapping,
                );
                Ok(true)
            }

            Transformation::SetValue { value } => {
                helpers::set_detection_item_values(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    value,
                );
                Ok(true)
            }

            Transformation::ConvertType { target_type } => {
                helpers::convert_detection_item_types(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    target_type,
                );
                Ok(true)
            }

            Transformation::Regex => {
                // No-op: marking that plain strings should be treated as regex.
                // In eval mode all matching goes through our compiled matchers,
                // so there is nothing to mutate. Kept for YAML compat.
                Ok(false)
            }

            Transformation::AddField { field } => {
                if !rule.fields.contains(field) {
                    rule.fields.push(field.clone());
                }
                Ok(true)
            }

            Transformation::RemoveField { field } => {
                rule.fields.retain(|f| f != field);
                Ok(true)
            }

            Transformation::SetField { fields } => {
                rule.fields = fields.clone();
                Ok(true)
            }

            Transformation::SetCustomAttribute { attribute, value } => {
                rule.custom_attributes
                    .insert(attribute.clone(), serde_yaml::Value::String(value.clone()));
                Ok(true)
            }

            Transformation::CaseTransformation { case_type } => {
                helpers::apply_case_transformation(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    case_type,
                );
                Ok(true)
            }

            Transformation::Nest { items } => {
                for item in items {
                    let mut merged_det_conds: Vec<DetectionItemCondition> =
                        detection_item_conditions.to_vec();
                    merged_det_conds.extend(item.detection_item_conditions.clone());

                    let mut merged_field_conds: Vec<FieldNameCondition> =
                        field_name_conditions.to_vec();
                    merged_field_conds.extend(item.field_name_conditions.clone());

                    let rule_ok = if item.rule_conditions.is_empty() {
                        true
                    } else {
                        super::conditions::all_rule_conditions_match(
                            &item.rule_conditions,
                            rule,
                            state,
                        )
                    };

                    if rule_ok {
                        item.transformation.apply(
                            rule,
                            state,
                            &merged_det_conds,
                            &merged_field_conds,
                            item.field_name_cond_not || field_name_cond_not,
                        )?;
                        if let Some(ref id) = item.id {
                            state.mark_applied(id);
                        }
                    }
                }
                Ok(true)
            }
        }
    }
}
