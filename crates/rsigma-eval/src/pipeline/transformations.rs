//! Pipeline transformations that mutate `SigmaRule` AST nodes.
//!
//! All 26 pySigma transformation types are implemented as variants of the
//! [`Transformation`] enum. Each variant carries its configuration parameters
//! and is applied via the [`Transformation::apply`] method.

use std::collections::HashMap;

use regex::Regex;

use rsigma_parser::{
    ConditionExpr, Detection, DetectionItem, FieldSpec, SigmaRule, SigmaString, SigmaValue,
};

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
    FieldNameMapping { mapping: HashMap<String, String> },

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
    ReplaceString { regex: String, replacement: String },

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
    MapString { mapping: HashMap<String, String> },

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
    /// Stores the key-value pair in `SigmaRule.custom_attributes`.
    /// Backends / engines can read these to modify per-rule behavior
    /// (e.g. `rsigma.suppress`, `rsigma.action`).
    /// Mirrors pySigma's `SetCustomAttributeTransformation`.
    SetCustomAttribute { attribute: String, value: String },

    /// Apply a case transformation to string values.
    /// Supported: "lower", "upper".
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
                apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| mapping.get(name).cloned(),
                );
                Ok(true)
            }

            Transformation::FieldNamePrefixMapping { mapping } => {
                apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| {
                        for (prefix, replacement) in mapping {
                            if name.starts_with(prefix.as_str()) {
                                return Some(format!("{}{}", replacement, &name[prefix.len()..]));
                            }
                        }
                        None
                    },
                );
                Ok(true)
            }

            Transformation::FieldNamePrefix { prefix } => {
                apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| Some(format!("{prefix}{name}")),
                );
                Ok(true)
            }

            Transformation::FieldNameSuffix { suffix } => {
                apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| Some(format!("{name}{suffix}")),
                );
                Ok(true)
            }

            Transformation::DropDetectionItem => {
                drop_detection_items(
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
                add_conditions(rule, conditions, *negated);
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

            Transformation::ReplaceString { regex, replacement } => {
                let re = Regex::new(regex)
                    .map_err(|e| EvalError::InvalidModifiers(format!("bad regex: {e}")))?;
                replace_strings_in_rule(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    &re,
                    replacement,
                );
                Ok(true)
            }

            Transformation::ValuePlaceholders => {
                expand_placeholders_in_rule(rule, state, false);
                Ok(true)
            }

            Transformation::WildcardPlaceholders => {
                expand_placeholders_in_rule(rule, state, true);
                Ok(true)
            }

            Transformation::QueryExpressionPlaceholders { .. } => {
                // No-op for eval mode
                Ok(false)
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
                // Check if any detection item matches the conditions
                let has_match = rule_has_matching_item(rule, state, detection_item_conditions);
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
                apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| {
                        if let Some(mapped) = map.get(name) {
                            return Some(mapped.clone());
                        }
                        Some(apply_named_string_fn(&func, name))
                    },
                );
                Ok(true)
            }

            Transformation::HashesFields {
                valid_hash_algos,
                field_prefix,
                drop_algo_prefix,
            } => {
                decompose_hashes_field(rule, valid_hash_algos, field_prefix, *drop_algo_prefix);
                Ok(true)
            }

            Transformation::MapString { mapping } => {
                map_string_values(
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
                set_detection_item_values(
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
                convert_detection_item_types(
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
                    .insert(attribute.clone(), value.clone());
                Ok(true)
            }

            Transformation::CaseTransformation { case_type } => {
                apply_case_transformation(
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
                    // Merge conditions: item's own + parent's
                    let mut merged_det_conds: Vec<DetectionItemCondition> =
                        detection_item_conditions.to_vec();
                    merged_det_conds.extend(item.detection_item_conditions.clone());

                    let mut merged_field_conds: Vec<FieldNameCondition> =
                        field_name_conditions.to_vec();
                    merged_field_conds.extend(item.field_name_conditions.clone());

                    // Evaluate rule conditions
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

// =============================================================================
// Field name transformation helper
// =============================================================================

fn apply_field_name_transform<F>(
    rule: &mut SigmaRule,
    state: &PipelineState,
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    transform_fn: F,
) where
    F: Fn(&str) -> Option<String>,
{
    for detection in rule.detection.named.values_mut() {
        transform_detection_fields(
            detection,
            state,
            field_name_conditions,
            field_name_cond_not,
            &transform_fn,
        );
    }
}

fn transform_detection_fields<F>(
    detection: &mut Detection,
    state: &PipelineState,
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    transform_fn: &F,
) where
    F: Fn(&str) -> Option<String>,
{
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if let Some(ref name) = item.field.name
                    && field_conditions_match(
                        name,
                        state,
                        field_name_conditions,
                        field_name_cond_not,
                    )
                    && let Some(new_name) = transform_fn(name)
                {
                    item.field.name = Some(new_name);
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                transform_detection_fields(
                    sub,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    transform_fn,
                );
            }
        }
        Detection::Keywords(_) => {}
    }
}

fn field_conditions_match(
    field_name: &str,
    state: &PipelineState,
    conditions: &[FieldNameCondition],
    negate: bool,
) -> bool {
    if conditions.is_empty() {
        return true;
    }
    let all_match = conditions
        .iter()
        .all(|c| c.matches_field_name(field_name, state));
    if negate { !all_match } else { all_match }
}

// =============================================================================
// Drop detection items
// =============================================================================

fn drop_detection_items(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
) {
    for detection in rule.detection.named.values_mut() {
        drop_from_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            field_name_cond_not,
        );
    }
}

fn drop_from_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
) {
    match detection {
        Detection::AllOf(items) => {
            items.retain(|item| {
                !should_drop_item(
                    item,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                )
            });
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                drop_from_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                );
            }
        }
        Detection::Keywords(_) => {}
    }
}

fn should_drop_item(
    item: &DetectionItem,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
) -> bool {
    // Check detection item conditions
    let det_match = detection_conditions.is_empty()
        || detection_conditions
            .iter()
            .all(|c| c.matches_item(item, state));

    // Check field name conditions
    let field_match = if let Some(ref name) = item.field.name {
        field_conditions_match(name, state, field_name_conditions, field_name_cond_not)
    } else {
        field_name_conditions.is_empty()
    };

    det_match && field_match
}

// =============================================================================
// Add conditions
// =============================================================================

fn add_conditions(rule: &mut SigmaRule, conditions: &HashMap<String, SigmaValue>, negated: bool) {
    // Create a new detection with the given conditions
    let items: Vec<DetectionItem> = conditions
        .iter()
        .map(|(field, value)| DetectionItem {
            field: FieldSpec::new(Some(field.clone()), Vec::new()),
            values: vec![value.clone()],
        })
        .collect();

    let det_name = format!("__pipeline_cond_{}", rule.detection.named.len());
    rule.detection
        .named
        .insert(det_name.clone(), Detection::AllOf(items));

    // Add to existing conditions: AND (or AND NOT if negated)
    let cond_ref = ConditionExpr::Identifier(det_name);
    let cond_expr = if negated {
        ConditionExpr::Not(Box::new(cond_ref))
    } else {
        cond_ref
    };

    rule.detection.conditions = rule
        .detection
        .conditions
        .iter()
        .map(|existing| ConditionExpr::And(vec![existing.clone(), cond_expr.clone()]))
        .collect();
}

// =============================================================================
// Replace strings
// =============================================================================

fn replace_strings_in_rule(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    re: &Regex,
    replacement: &str,
) {
    for detection in rule.detection.named.values_mut() {
        replace_strings_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            field_name_cond_not,
            re,
            replacement,
        );
    }
}

fn replace_strings_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    re: &Regex,
    replacement: &str,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                let det_match = detection_conditions.is_empty()
                    || detection_conditions
                        .iter()
                        .all(|c| c.matches_item(item, state));
                let field_match = if let Some(ref name) = item.field.name {
                    field_conditions_match(name, state, field_name_conditions, field_name_cond_not)
                } else {
                    field_name_conditions.is_empty()
                };

                if det_match && field_match {
                    replace_strings_in_values(&mut item.values, re, replacement);
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                replace_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    re,
                    replacement,
                );
            }
        }
        Detection::Keywords(values) => {
            replace_strings_in_values(values, re, replacement);
        }
    }
}

fn replace_strings_in_values(values: &mut [SigmaValue], re: &Regex, replacement: &str) {
    for value in values.iter_mut() {
        if let SigmaValue::String(s) = value {
            let replaced = re.replace_all(&s.original, replacement);
            if replaced != s.original {
                *s = SigmaString::new(&replaced);
            }
        }
    }
}

// =============================================================================
// Placeholder expansion
// =============================================================================

fn expand_placeholders_in_rule(rule: &mut SigmaRule, state: &PipelineState, wildcard: bool) {
    for detection in rule.detection.named.values_mut() {
        expand_placeholders_in_detection(detection, state, wildcard);
    }
}

fn expand_placeholders_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    wildcard: bool,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                expand_placeholders_in_values(&mut item.values, state, wildcard);
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                expand_placeholders_in_detection(sub, state, wildcard);
            }
        }
        Detection::Keywords(values) => {
            expand_placeholders_in_values(values, state, wildcard);
        }
    }
}

fn expand_placeholders_in_values(
    values: &mut Vec<SigmaValue>,
    state: &PipelineState,
    wildcard: bool,
) {
    let mut expanded_values = Vec::new();
    for value in values.drain(..) {
        if let SigmaValue::String(ref s) = value {
            let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
            if plain.contains('%') {
                // Try to expand %name% patterns
                let result = expand_placeholder_string(&plain, state, wildcard);
                expanded_values.extend(result);
                continue;
            }
        }
        expanded_values.push(value);
    }
    *values = expanded_values;
}

fn expand_placeholder_string(s: &str, state: &PipelineState, wildcard: bool) -> Vec<SigmaValue> {
    // Find %name% patterns
    let mut result = s.to_string();
    let mut has_unresolved = false;

    // Simple regex-free pattern matching for %name%
    loop {
        let Some(start) = result.find('%') else {
            break;
        };
        let rest = &result[start + 1..];
        let Some(end) = rest.find('%') else {
            break;
        };
        let placeholder = &rest[..end];

        if let Some(values) = state.vars.get(placeholder) {
            if values.len() == 1 {
                result = format!("{}{}{}", &result[..start], values[0], &rest[end + 1..]);
            } else if values.is_empty() {
                if wildcard {
                    result = format!("{}*{}", &result[..start], &rest[end + 1..]);
                } else {
                    has_unresolved = true;
                    break;
                }
            } else {
                // Multiple values: create one SigmaValue per expansion
                return values
                    .iter()
                    .map(|v| {
                        let expanded = format!("{}{}{}", &result[..start], v, &rest[end + 1..]);
                        SigmaValue::String(SigmaString::new(&expanded))
                    })
                    .collect();
            }
        } else if wildcard {
            result = format!("{}*{}", &result[..start], &rest[end + 1..]);
        } else {
            has_unresolved = true;
            break;
        }
    }

    if has_unresolved && wildcard {
        // Replace remaining unresolved placeholders with *
        // This is a simplistic approach
        vec![SigmaValue::String(SigmaString::new(&result))]
    } else {
        vec![SigmaValue::String(SigmaString::new(&result))]
    }
}

// =============================================================================
// Named string function helper (for FieldNameTransform)
// =============================================================================

fn apply_named_string_fn(func: &str, s: &str) -> String {
    match func {
        "lower" | "lowercase" => s.to_lowercase(),
        "upper" | "uppercase" => s.to_uppercase(),
        "title" => {
            // Capitalize first letter of each word
            s.split(|c: char| !c.is_alphanumeric())
                .filter(|w| !w.is_empty())
                .map(|w| {
                    let mut c = w.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => {
                            f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase()
                        }
                    }
                })
                .collect::<Vec<_>>()
                .join("_")
        }
        "snake_case" => {
            // Simple camelCase / PascalCase → snake_case
            let mut out = String::new();
            for (i, ch) in s.chars().enumerate() {
                if ch.is_uppercase() && i > 0 {
                    out.push('_');
                }
                out.push(ch.to_lowercase().next().unwrap_or(ch));
            }
            out
        }
        _ => s.to_string(), // unknown function → identity
    }
}

// =============================================================================
// Hashes field decomposition
// =============================================================================

fn decompose_hashes_field(
    rule: &mut SigmaRule,
    valid_algos: &[String],
    field_prefix: &str,
    drop_algo_prefix: bool,
) {
    for detection in rule.detection.named.values_mut() {
        decompose_hashes_in_detection(detection, valid_algos, field_prefix, drop_algo_prefix);
    }
}

fn decompose_hashes_in_detection(
    detection: &mut Detection,
    valid_algos: &[String],
    field_prefix: &str,
    drop_algo_prefix: bool,
) {
    match detection {
        Detection::AllOf(items) => {
            let mut new_items: Vec<DetectionItem> = Vec::new();
            let mut i = 0;
            while i < items.len() {
                let item = &items[i];
                let is_hashes = item
                    .field
                    .name
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case("hashes"))
                    .unwrap_or(false);

                if is_hashes {
                    // Decompose each value "ALGO=HASH"
                    for val in &item.values {
                        if let SigmaValue::String(s) = val {
                            let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                            for pair in plain.split(',') {
                                let pair = pair.trim();
                                if let Some((algo, hash)) = pair.split_once('=') {
                                    let algo_upper = algo.trim().to_uppercase();
                                    if valid_algos.is_empty()
                                        || valid_algos
                                            .iter()
                                            .any(|a| a.eq_ignore_ascii_case(&algo_upper))
                                    {
                                        let field_name = if drop_algo_prefix {
                                            field_prefix.to_string()
                                        } else {
                                            format!("{field_prefix}{}", algo.trim())
                                        };
                                        new_items.push(DetectionItem {
                                            field: FieldSpec::new(
                                                Some(field_name),
                                                item.field.modifiers.clone(),
                                            ),
                                            values: vec![SigmaValue::String(SigmaString::new(
                                                hash.trim(),
                                            ))],
                                        });
                                    }
                                }
                            }
                        }
                    }
                } else {
                    new_items.push(items[i].clone());
                }
                i += 1;
            }
            *items = new_items;
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                decompose_hashes_in_detection(sub, valid_algos, field_prefix, drop_algo_prefix);
            }
        }
        Detection::Keywords(_) => {}
    }
}

// =============================================================================
// Map string values
// =============================================================================

fn map_string_values(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    mapping: &HashMap<String, String>,
) {
    for detection in rule.detection.named.values_mut() {
        map_strings_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            field_name_cond_not,
            mapping,
        );
    }
}

fn map_strings_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    mapping: &HashMap<String, String>,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(
                    item,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                ) {
                    for val in item.values.iter_mut() {
                        if let SigmaValue::String(s) = val {
                            let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                            if let Some(replacement) = mapping.get(&plain) {
                                *s = SigmaString::new(replacement);
                            }
                        }
                    }
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                map_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    mapping,
                );
            }
        }
        Detection::Keywords(values) => {
            for val in values.iter_mut() {
                if let SigmaValue::String(s) = val {
                    let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                    if let Some(replacement) = mapping.get(&plain) {
                        *s = SigmaString::new(replacement);
                    }
                }
            }
        }
    }
}

// =============================================================================
// Set value
// =============================================================================

fn set_detection_item_values(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    value: &SigmaValue,
) {
    for detection in rule.detection.named.values_mut() {
        set_values_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            field_name_cond_not,
            value,
        );
    }
}

fn set_values_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    value: &SigmaValue,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(
                    item,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                ) {
                    item.values = vec![value.clone()];
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                set_values_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    value,
                );
            }
        }
        Detection::Keywords(_) => {}
    }
}

// =============================================================================
// Convert type
// =============================================================================

fn convert_detection_item_types(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    target_type: &str,
) {
    for detection in rule.detection.named.values_mut() {
        convert_types_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            field_name_cond_not,
            target_type,
        );
    }
}

fn convert_types_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    target_type: &str,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(
                    item,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                ) {
                    for val in item.values.iter_mut() {
                        *val = convert_value(val, target_type);
                    }
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                convert_types_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    target_type,
                );
            }
        }
        Detection::Keywords(_) => {}
    }
}

fn convert_value(val: &SigmaValue, target: &str) -> SigmaValue {
    match target {
        "str" | "string" => match val {
            SigmaValue::String(_) => val.clone(),
            SigmaValue::Integer(n) => SigmaValue::String(SigmaString::new(&n.to_string())),
            SigmaValue::Float(f) => SigmaValue::String(SigmaString::new(&f.to_string())),
            SigmaValue::Bool(b) => SigmaValue::String(SigmaString::new(&b.to_string())),
            SigmaValue::Null => SigmaValue::String(SigmaString::new("null")),
        },
        "int" | "integer" => match val {
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                plain
                    .parse::<i64>()
                    .map(SigmaValue::Integer)
                    .unwrap_or_else(|_| val.clone())
            }
            SigmaValue::Float(f) => SigmaValue::Integer(*f as i64),
            SigmaValue::Bool(b) => SigmaValue::Integer(if *b { 1 } else { 0 }),
            _ => val.clone(),
        },
        "float" => match val {
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                plain
                    .parse::<f64>()
                    .map(SigmaValue::Float)
                    .unwrap_or_else(|_| val.clone())
            }
            SigmaValue::Integer(n) => SigmaValue::Float(*n as f64),
            SigmaValue::Bool(b) => SigmaValue::Float(if *b { 1.0 } else { 0.0 }),
            _ => val.clone(),
        },
        "bool" | "boolean" => match val {
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                match plain.to_lowercase().as_str() {
                    "true" | "1" | "yes" => SigmaValue::Bool(true),
                    "false" | "0" | "no" => SigmaValue::Bool(false),
                    _ => val.clone(),
                }
            }
            SigmaValue::Integer(n) => SigmaValue::Bool(*n != 0),
            SigmaValue::Float(f) => SigmaValue::Bool(*f != 0.0),
            _ => val.clone(),
        },
        _ => val.clone(),
    }
}

// =============================================================================
// Case transformation
// =============================================================================

fn apply_case_transformation(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    case_type: &str,
) {
    for detection in rule.detection.named.values_mut() {
        apply_case_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            field_name_cond_not,
            case_type,
        );
    }
}

fn apply_case_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    case_type: &str,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(
                    item,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                ) {
                    for val in item.values.iter_mut() {
                        if let SigmaValue::String(s) = val {
                            let transformed = match case_type {
                                "lower" | "lowercase" => s.original.to_lowercase(),
                                "upper" | "uppercase" => s.original.to_uppercase(),
                                _ => continue,
                            };
                            if transformed != s.original {
                                *s = SigmaString::new(&transformed);
                            }
                        }
                    }
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                apply_case_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    case_type,
                );
            }
        }
        Detection::Keywords(values) => {
            for val in values.iter_mut() {
                if let SigmaValue::String(s) = val {
                    let transformed = match case_type {
                        "lower" | "lowercase" => s.original.to_lowercase(),
                        "upper" | "uppercase" => s.original.to_uppercase(),
                        _ => continue,
                    };
                    if transformed != s.original {
                        *s = SigmaString::new(&transformed);
                    }
                }
            }
        }
    }
}

// =============================================================================
// Shared helper: check if a detection item matches both sets of conditions
// =============================================================================

fn item_conditions_match(
    item: &DetectionItem,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
) -> bool {
    let det_match = detection_conditions.is_empty()
        || detection_conditions
            .iter()
            .all(|c| c.matches_item(item, state));

    let field_match = if let Some(ref name) = item.field.name {
        field_conditions_match(name, state, field_name_conditions, field_name_cond_not)
    } else {
        field_name_conditions.is_empty()
    };

    det_match && field_match
}

// =============================================================================
// Helper: check if rule has any item matching conditions
// =============================================================================

fn rule_has_matching_item(
    rule: &SigmaRule,
    state: &PipelineState,
    conditions: &[DetectionItemCondition],
) -> bool {
    for detection in rule.detection.named.values() {
        if detection_has_matching_item(detection, state, conditions) {
            return true;
        }
    }
    false
}

fn detection_has_matching_item(
    detection: &Detection,
    state: &PipelineState,
    conditions: &[DetectionItemCondition],
) -> bool {
    match detection {
        Detection::AllOf(items) => items
            .iter()
            .any(|item| conditions.iter().all(|c| c.matches_item(item, state))),
        Detection::AnyOf(subs) => subs
            .iter()
            .any(|sub| detection_has_matching_item(sub, state, conditions)),
        Detection::Keywords(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::{Detections, LogSource, Modifier};

    fn make_test_rule() -> SigmaRule {
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![
                DetectionItem {
                    field: FieldSpec::new(
                        Some("CommandLine".to_string()),
                        vec![Modifier::Contains],
                    ),
                    values: vec![SigmaValue::String(SigmaString::new("whoami"))],
                },
                DetectionItem {
                    field: FieldSpec::new(
                        Some("ParentImage".to_string()),
                        vec![Modifier::EndsWith],
                    ),
                    values: vec![SigmaValue::String(SigmaString::new("\\cmd.exe"))],
                },
            ]),
        );

        SigmaRule {
            title: "Test Rule".to_string(),
            logsource: LogSource {
                category: Some("process_creation".to_string()),
                product: Some("windows".to_string()),
                service: None,
                definition: None,
                custom: HashMap::new(),
            },
            detection: Detections {
                named,
                conditions: vec![ConditionExpr::Identifier("selection".to_string())],
                condition_strings: vec!["selection".to_string()],
                timeframe: None,
            },
            id: Some("test-001".to_string()),
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
            level: Some(rsigma_parser::Level::Medium),
            tags: vec![],
            scope: vec![],
            custom_attributes: HashMap::new(),
        }
    }

    #[test]
    fn test_field_name_mapping() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let mut mapping = HashMap::new();
        mapping.insert(
            "CommandLine".to_string(),
            "process.command_line".to_string(),
        );
        mapping.insert(
            "ParentImage".to_string(),
            "process.parent.executable".to_string(),
        );

        let t = Transformation::FieldNameMapping { mapping };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(
                items[0].field.name,
                Some("process.command_line".to_string())
            );
            assert_eq!(
                items[1].field.name,
                Some("process.parent.executable".to_string())
            );
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_field_name_prefix() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::FieldNamePrefix {
            prefix: "winlog.event_data.".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(
                items[0].field.name,
                Some("winlog.event_data.CommandLine".to_string())
            );
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_field_name_suffix() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::FieldNameSuffix {
            suffix: ".keyword".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("CommandLine.keyword".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_change_logsource() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::ChangeLogsource {
            category: Some("endpoint".to_string()),
            product: Some("elastic".to_string()),
            service: None,
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        assert_eq!(rule.logsource.category, Some("endpoint".to_string()));
        assert_eq!(rule.logsource.product, Some("elastic".to_string()));
    }

    #[test]
    fn test_replace_string() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::ReplaceString {
            regex: r"whoami".to_string(),
            replacement: "REPLACED".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "REPLACED");
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_add_condition() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let mut conds = HashMap::new();
        conds.insert(
            "index".to_string(),
            SigmaValue::String(SigmaString::new("windows-*")),
        );
        let t = Transformation::AddCondition {
            conditions: conds,
            negated: false,
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        // Check that a new detection was added
        assert!(
            rule.detection
                .named
                .keys()
                .any(|k| k.starts_with("__pipeline_cond_"))
        );
        // Check that conditions were wrapped
        assert_eq!(rule.detection.conditions.len(), 1);
        if let ConditionExpr::And(parts) = &rule.detection.conditions[0] {
            assert_eq!(parts.len(), 2);
        } else {
            panic!("Expected And condition");
        }
    }

    #[test]
    fn test_set_state() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::SetState {
            key: "index".to_string(),
            value: "windows".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
        assert!(state.state_matches("index", "windows"));
    }

    #[test]
    fn test_drop_detection_item_with_field_condition() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();

        let field_conds = vec![FieldNameCondition::IncludeFields {
            matcher: super::super::conditions::FieldMatcher::Plain(vec!["ParentImage".to_string()]),
        }];

        let t = Transformation::DropDetectionItem;
        t.apply(&mut rule, &mut state, &[], &field_conds, false)
            .unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items.len(), 1); // ParentImage was dropped
            assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_field_name_mapping_with_conditions() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();

        // Only map CommandLine, not ParentImage
        let field_conds = vec![FieldNameCondition::IncludeFields {
            matcher: super::super::conditions::FieldMatcher::Plain(vec!["CommandLine".to_string()]),
        }];

        let mut mapping = HashMap::new();
        mapping.insert("CommandLine".to_string(), "process.args".to_string());
        mapping.insert("ParentImage".to_string(), "process.parent".to_string());

        let t = Transformation::FieldNameMapping { mapping };
        t.apply(&mut rule, &mut state, &[], &field_conds, false)
            .unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("process.args".to_string()));
            // ParentImage should NOT have been mapped (field condition didn't match)
            assert_eq!(items[1].field.name, Some("ParentImage".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_rule_failure() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::RuleFailure {
            message: "Unsupported rule".to_string(),
        };
        let result = t.apply(&mut rule, &mut state, &[], &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_value_placeholders() {
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![DetectionItem {
                field: FieldSpec::new(Some("User".to_string()), vec![]),
                values: vec![SigmaValue::String(SigmaString::new("%admin_users%"))],
            }]),
        );

        let mut rule = SigmaRule {
            title: "Test".to_string(),
            logsource: LogSource::default(),
            detection: Detections {
                named,
                conditions: vec![ConditionExpr::Identifier("selection".to_string())],
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
            custom_attributes: HashMap::new(),
        };

        let mut state = PipelineState::default();
        state.vars.insert(
            "admin_users".to_string(),
            vec!["root".to_string(), "admin".to_string()],
        );

        let t = Transformation::ValuePlaceholders;
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            // Should have expanded to 2 values
            assert_eq!(items[0].values.len(), 2);
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_field_name_transform_lowercase() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::FieldNameTransform {
            transform_func: "lower".to_string(),
            mapping: HashMap::new(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("commandline".to_string()));
            assert_eq!(items[1].field.name, Some("parentimage".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_field_name_transform_with_mapping_override() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let mut mapping = HashMap::new();
        mapping.insert("CommandLine".to_string(), "cmd_line".to_string());
        let t = Transformation::FieldNameTransform {
            transform_func: "lower".to_string(),
            mapping,
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            // CommandLine → override from mapping
            assert_eq!(items[0].field.name, Some("cmd_line".to_string()));
            // ParentImage → lowercase (no override)
            assert_eq!(items[1].field.name, Some("parentimage".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_field_name_transform_snake_case() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::FieldNameTransform {
            transform_func: "snake_case".to_string(),
            mapping: HashMap::new(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("command_line".to_string()));
            assert_eq!(items[1].field.name, Some("parent_image".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_hashes_fields_decomposition() {
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![DetectionItem {
                field: FieldSpec::new(Some("Hashes".to_string()), vec![]),
                values: vec![SigmaValue::String(SigmaString::new(
                    "SHA1=abc123,MD5=def456",
                ))],
            }]),
        );

        let mut rule = make_test_rule();
        rule.detection.named = named;

        let mut state = PipelineState::default();
        let t = Transformation::HashesFields {
            valid_hash_algos: vec!["SHA1".to_string(), "MD5".to_string()],
            field_prefix: "File".to_string(),
            drop_algo_prefix: false,
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].field.name, Some("FileSHA1".to_string()));
            assert_eq!(items[1].field.name, Some("FileMD5".to_string()));
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "abc123");
            }
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.original, "def456");
            }
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_map_string() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let mut mapping = HashMap::new();
        mapping.insert("whoami".to_string(), "who_am_i".to_string());
        let t = Transformation::MapString { mapping };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "who_am_i");
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_map_string_no_match() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let mut mapping = HashMap::new();
        mapping.insert("nonexistent".to_string(), "replaced".to_string());
        let t = Transformation::MapString { mapping };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        // Values should be unchanged
        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det
            && let SigmaValue::String(s) = &items[0].values[0]
        {
            assert_eq!(s.original, "whoami");
        }
    }

    #[test]
    fn test_set_value() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::SetValue {
            value: SigmaValue::String(SigmaString::new("FIXED")),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            for item in items {
                assert_eq!(item.values.len(), 1);
                if let SigmaValue::String(s) = &item.values[0] {
                    assert_eq!(s.original, "FIXED");
                }
            }
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_convert_type_string_to_int() {
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![DetectionItem {
                field: FieldSpec::new(Some("EventID".to_string()), vec![]),
                values: vec![SigmaValue::String(SigmaString::new("4688"))],
            }]),
        );
        let mut rule = make_test_rule();
        rule.detection.named = named;

        let mut state = PipelineState::default();
        let t = Transformation::ConvertType {
            target_type: "int".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert!(matches!(items[0].values[0], SigmaValue::Integer(4688)));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_convert_type_int_to_string() {
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![DetectionItem {
                field: FieldSpec::new(Some("EventID".to_string()), vec![]),
                values: vec![SigmaValue::Integer(4688)],
            }]),
        );
        let mut rule = make_test_rule();
        rule.detection.named = named;

        let mut state = PipelineState::default();
        let t = Transformation::ConvertType {
            target_type: "str".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "4688");
            } else {
                panic!("Expected String");
            }
        }
    }

    #[test]
    fn test_convert_type_to_bool() {
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![DetectionItem {
                field: FieldSpec::new(Some("Enabled".to_string()), vec![]),
                values: vec![SigmaValue::String(SigmaString::new("true"))],
            }]),
        );
        let mut rule = make_test_rule();
        rule.detection.named = named;

        let mut state = PipelineState::default();
        let t = Transformation::ConvertType {
            target_type: "bool".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert!(matches!(items[0].values[0], SigmaValue::Bool(true)));
        }
    }

    #[test]
    fn test_regex_noop() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::Regex;
        let result = t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
        assert!(!result); // no-op returns false
    }

    #[test]
    fn test_add_field() {
        let mut rule = make_test_rule();
        assert!(rule.fields.is_empty());

        let mut state = PipelineState::default();
        let t = Transformation::AddField {
            field: "EventID".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
        assert_eq!(rule.fields, vec!["EventID".to_string()]);

        // Adding again should not duplicate
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
        assert_eq!(rule.fields, vec!["EventID".to_string()]);
    }

    #[test]
    fn test_remove_field() {
        let mut rule = make_test_rule();
        rule.fields = vec!["EventID".to_string(), "CommandLine".to_string()];

        let mut state = PipelineState::default();
        let t = Transformation::RemoveField {
            field: "EventID".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
        assert_eq!(rule.fields, vec!["CommandLine".to_string()]);
    }

    #[test]
    fn test_set_field() {
        let mut rule = make_test_rule();
        rule.fields = vec!["old".to_string()];

        let mut state = PipelineState::default();
        let t = Transformation::SetField {
            fields: vec!["new1".to_string(), "new2".to_string()],
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
        assert_eq!(rule.fields, vec!["new1".to_string(), "new2".to_string()]);
    }

    #[test]
    fn test_set_custom_attribute() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::SetCustomAttribute {
            attribute: "custom.key".to_string(),
            value: "custom_value".to_string(),
        };
        let result = t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
        assert!(result);
        assert_eq!(
            rule.custom_attributes.get("custom.key"),
            Some(&"custom_value".to_string())
        );
    }

    #[test]
    fn test_case_transformation_lower() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::CaseTransformation {
            case_type: "lower".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            // "whoami" is already lowercase
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "whoami");
            }
            // "\\cmd.exe" stays the same
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.original, "\\cmd.exe");
            }
        }
    }

    #[test]
    fn test_case_transformation_upper() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::CaseTransformation {
            case_type: "upper".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "WHOAMI");
            }
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.original, "\\CMD.EXE");
            }
        }
    }

    #[test]
    fn test_nest_transformation() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();

        // Create a nested pipeline: prefix + suffix in one nest
        let items = vec![
            super::super::TransformationItem {
                id: Some("inner_prefix".to_string()),
                transformation: Transformation::FieldNamePrefix {
                    prefix: "winlog.".to_string(),
                },
                rule_conditions: vec![],
                rule_cond_expr: None,
                detection_item_conditions: vec![],
                field_name_conditions: vec![],
                field_name_cond_not: false,
            },
            super::super::TransformationItem {
                id: Some("inner_suffix".to_string()),
                transformation: Transformation::FieldNameSuffix {
                    suffix: ".keyword".to_string(),
                },
                rule_conditions: vec![],
                rule_cond_expr: None,
                detection_item_conditions: vec![],
                field_name_conditions: vec![],
                field_name_cond_not: false,
            },
        ];

        let t = Transformation::Nest { items };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(
                items[0].field.name,
                Some("winlog.CommandLine.keyword".to_string())
            );
            assert_eq!(
                items[1].field.name,
                Some("winlog.ParentImage.keyword".to_string())
            );
        } else {
            panic!("Expected AllOf");
        }

        // Check inner items were tracked
        assert!(state.was_applied("inner_prefix"));
        assert!(state.was_applied("inner_suffix"));
    }

    // =========================================================================
    // Untested transformation types
    // =========================================================================

    #[test]
    fn test_field_name_prefix_mapping() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let mut mapping = HashMap::new();
        mapping.insert("Command".to_string(), "process.".to_string());
        mapping.insert("Parent".to_string(), "process.parent.".to_string());

        let t = Transformation::FieldNamePrefixMapping { mapping };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            // "CommandLine" starts with "Command" → "process." + "Line"
            assert_eq!(items[0].field.name, Some("process.Line".to_string()));
            // "ParentImage" starts with "Parent" → "process.parent." + "Image"
            assert_eq!(
                items[1].field.name,
                Some("process.parent.Image".to_string())
            );
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_field_name_prefix_mapping_no_match() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let mut mapping = HashMap::new();
        mapping.insert("NoMatch".to_string(), "replaced.".to_string());

        let t = Transformation::FieldNamePrefixMapping { mapping };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        // Fields should be unchanged — no prefix matched
        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
            assert_eq!(items[1].field.name, Some("ParentImage".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_wildcard_placeholders_replaces_unresolved() {
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![DetectionItem {
                field: FieldSpec::new(Some("User".to_string()), vec![]),
                values: vec![SigmaValue::String(SigmaString::new("%unknown_var%"))],
            }]),
        );

        let mut rule = SigmaRule {
            title: "Test".to_string(),
            logsource: LogSource::default(),
            detection: Detections {
                named,
                conditions: vec![ConditionExpr::Identifier("selection".to_string())],
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
            custom_attributes: HashMap::new(),
        };

        let mut state = PipelineState::default();
        // No vars set — placeholder should be replaced with wildcard
        let t = Transformation::WildcardPlaceholders;
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "*", "unresolved placeholder should become *");
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_wildcard_placeholders_with_known_var() {
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![DetectionItem {
                field: FieldSpec::new(Some("User".to_string()), vec![]),
                values: vec![SigmaValue::String(SigmaString::new("%admin%"))],
            }]),
        );

        let mut rule = SigmaRule {
            title: "Test".to_string(),
            logsource: LogSource::default(),
            detection: Detections {
                named,
                conditions: vec![ConditionExpr::Identifier("selection".to_string())],
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
            custom_attributes: HashMap::new(),
        };

        let mut state = PipelineState::default();
        state
            .vars
            .insert("admin".to_string(), vec!["root".to_string()]);

        // WildcardPlaceholders should still expand known vars
        let t = Transformation::WildcardPlaceholders;
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "root");
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_detection_item_failure_fires_on_match() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();

        // Condition that matches the "whoami" value in CommandLine
        let det_conds = vec![DetectionItemCondition::MatchString {
            regex: regex::Regex::new("whoami").unwrap(),
            negate: false,
        }];

        let t = Transformation::DetectionItemFailure {
            message: "Unsupported detection item".to_string(),
        };
        let result = t.apply(&mut rule, &mut state, &det_conds, &[], false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unsupported detection item"));
    }

    #[test]
    fn test_detection_item_failure_skips_on_no_match() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();

        // Condition that does NOT match any value
        let det_conds = vec![DetectionItemCondition::MatchString {
            regex: regex::Regex::new("nonexistent_value").unwrap(),
            negate: false,
        }];

        let t = Transformation::DetectionItemFailure {
            message: "Should not fire".to_string(),
        };
        let result = t.apply(&mut rule, &mut state, &det_conds, &[], false);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // returns false (not applied)
    }

    #[test]
    fn test_query_expression_placeholders_noop() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::QueryExpressionPlaceholders {
            expression: "{field}={value}".to_string(),
        };
        let result = t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
        assert!(!result); // no-op returns false
    }

    // =========================================================================
    // Edge cases: add_condition negated
    // =========================================================================

    #[test]
    fn test_add_condition_negated() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let mut conds = HashMap::new();
        conds.insert(
            "User".to_string(),
            SigmaValue::String(SigmaString::new("SYSTEM")),
        );
        let t = Transformation::AddCondition {
            conditions: conds,
            negated: true,
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        // The condition should be AND NOT (negated)
        assert_eq!(rule.detection.conditions.len(), 1);
        if let ConditionExpr::And(parts) = &rule.detection.conditions[0] {
            assert_eq!(parts.len(), 2);
            // Second part should be Not(...)
            assert!(
                matches!(&parts[1], ConditionExpr::Not(_)),
                "Expected negated condition, got: {:?}",
                parts[1]
            );
        } else {
            panic!("Expected And condition");
        }
    }

    // =========================================================================
    // Edge cases: detection_item_conditions with transformations
    // =========================================================================

    #[test]
    fn test_replace_string_with_detection_item_condition() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();

        // Only replace in items where value matches "whoami"
        let det_conds = vec![DetectionItemCondition::MatchString {
            regex: regex::Regex::new("whoami").unwrap(),
            negate: false,
        }];

        let t = Transformation::ReplaceString {
            regex: r"whoami".to_string(),
            replacement: "REPLACED".to_string(),
        };
        t.apply(&mut rule, &mut state, &det_conds, &[], false)
            .unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            // CommandLine value matches → replaced
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "REPLACED");
            }
            // ParentImage value "\\cmd.exe" does NOT match → unchanged
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.original, "\\cmd.exe");
            }
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_set_value_with_is_null_condition() {
        // Create a rule with a null value
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![
                DetectionItem {
                    field: FieldSpec::new(Some("FieldA".to_string()), vec![]),
                    values: vec![SigmaValue::Null],
                },
                DetectionItem {
                    field: FieldSpec::new(Some("FieldB".to_string()), vec![]),
                    values: vec![SigmaValue::String(SigmaString::new("value"))],
                },
            ]),
        );

        let mut rule = make_test_rule();
        rule.detection.named = named;
        let mut state = PipelineState::default();

        // Only apply set_value to items with null values
        let det_conds = vec![DetectionItemCondition::IsNull { negate: false }];

        let t = Transformation::SetValue {
            value: SigmaValue::String(SigmaString::new("DEFAULT")),
        };
        t.apply(&mut rule, &mut state, &det_conds, &[], false)
            .unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            // FieldA had null → should be replaced
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "DEFAULT");
            } else {
                panic!("Expected String after set_value on null");
            }
            // FieldB had "value" → should be unchanged
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.original, "value");
            }
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_drop_detection_item_with_match_string_condition() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();

        // Drop items where values match "whoami"
        let det_conds = vec![DetectionItemCondition::MatchString {
            regex: regex::Regex::new("whoami").unwrap(),
            negate: false,
        }];

        let t = Transformation::DropDetectionItem;
        t.apply(&mut rule, &mut state, &det_conds, &[], false)
            .unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items.len(), 1);
            // Only ParentImage should remain
            assert_eq!(items[0].field.name, Some("ParentImage".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    // =========================================================================
    // Edge case: field_name_cond_not (negated field name conditions)
    // =========================================================================

    #[test]
    fn test_field_name_mapping_with_cond_not() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();

        // IncludeFields for CommandLine, but negated → apply to everything EXCEPT CommandLine
        let field_conds = vec![FieldNameCondition::IncludeFields {
            matcher: super::super::conditions::FieldMatcher::Plain(vec!["CommandLine".to_string()]),
        }];

        let mut mapping = HashMap::new();
        mapping.insert("CommandLine".to_string(), "cmd".to_string());
        mapping.insert("ParentImage".to_string(), "parent".to_string());

        let t = Transformation::FieldNameMapping { mapping };
        // field_name_cond_not = true → negate the field condition
        t.apply(&mut rule, &mut state, &[], &field_conds, true)
            .unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            // CommandLine should NOT be mapped (negated: included fields are excluded)
            assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
            // ParentImage SHOULD be mapped (not in include list, negated = applies)
            assert_eq!(items[1].field.name, Some("parent".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    // =========================================================================
    // Edge cases: empty inputs
    // =========================================================================

    #[test]
    fn test_field_name_mapping_empty() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::FieldNameMapping {
            mapping: HashMap::new(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        // Fields should be unchanged
        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
            assert_eq!(items[1].field.name, Some("ParentImage".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_field_name_prefix_mapping_empty() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::FieldNamePrefixMapping {
            mapping: HashMap::new(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_map_string_empty_mapping() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::MapString {
            mapping: HashMap::new(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det
            && let SigmaValue::String(s) = &items[0].values[0]
        {
            assert_eq!(s.original, "whoami");
        }
    }

    #[test]
    fn test_hashes_fields_empty_algos() {
        // When valid_hash_algos is empty, all algorithms should be accepted
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![DetectionItem {
                field: FieldSpec::new(Some("Hashes".to_string()), vec![]),
                values: vec![SigmaValue::String(SigmaString::new(
                    "SHA256=abc123,IMPHASH=def456",
                ))],
            }]),
        );

        let mut rule = make_test_rule();
        rule.detection.named = named;

        let mut state = PipelineState::default();
        let t = Transformation::HashesFields {
            valid_hash_algos: vec![], // empty = accept all
            field_prefix: "File".to_string(),
            drop_algo_prefix: false,
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].field.name, Some("FileSHA256".to_string()));
            assert_eq!(items[1].field.name, Some("FileIMPHASH".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_hashes_fields_drop_algo_prefix() {
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![DetectionItem {
                field: FieldSpec::new(Some("Hashes".to_string()), vec![]),
                values: vec![SigmaValue::String(SigmaString::new("MD5=abc123"))],
            }]),
        );

        let mut rule = make_test_rule();
        rule.detection.named = named;
        let mut state = PipelineState::default();

        let t = Transformation::HashesFields {
            valid_hash_algos: vec!["MD5".to_string()],
            field_prefix: "Hash".to_string(),
            drop_algo_prefix: true,
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items.len(), 1);
            // drop_algo_prefix = true → field name is just the prefix
            assert_eq!(items[0].field.name, Some("Hash".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    // =========================================================================
    // Edge case: invalid regex in replace_string
    // =========================================================================

    #[test]
    fn test_replace_string_invalid_regex() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::ReplaceString {
            regex: r"[invalid".to_string(), // unclosed bracket
            replacement: "x".to_string(),
        };
        let result = t.apply(&mut rule, &mut state, &[], &[], false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("bad regex"),
            "error should mention regex: {err}"
        );
    }

    // =========================================================================
    // Edge case: detection_item_conditions with negate
    // =========================================================================

    #[test]
    fn test_case_transformation_with_negated_match_string() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();

        // Negate: transform items that do NOT match "whoami"
        let det_conds = vec![DetectionItemCondition::MatchString {
            regex: regex::Regex::new("whoami").unwrap(),
            negate: true,
        }];

        let t = Transformation::CaseTransformation {
            case_type: "upper".to_string(),
        };
        t.apply(&mut rule, &mut state, &det_conds, &[], false)
            .unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            // CommandLine has "whoami" → negate means NOT matched → unchanged
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "whoami");
            }
            // ParentImage has "\\cmd.exe" → negate means matched → uppercased
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.original, "\\CMD.EXE");
            }
        } else {
            panic!("Expected AllOf");
        }
    }

    // =========================================================================
    // Integration: multi-transformation chaining pipeline (YAML)
    // =========================================================================

    #[test]
    fn test_multi_transformation_chaining_pipeline() {
        use crate::pipeline::parse_pipeline;

        let yaml = r#"
name: Multi-step Pipeline
transformations:
  - id: step1_map
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      ParentImage: process.parent.executable
  - id: step2_prefix
    type: field_name_prefix
    prefix: "winlog."
    rule_conditions:
      - type: logsource
        product: windows
  - id: step3_case
    type: case_transformation
    case_type: upper
    field_name_conditions:
      - type: include_fields
        fields:
          - winlog.process.command_line
  - id: step4_attr
    type: set_custom_attribute
    attribute: rsigma.processed
    value: "true"
"#;
        let pipeline = parse_pipeline(yaml).unwrap();

        let mut rule = make_test_rule(); // Windows process_creation rule
        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply(&mut rule, &mut state).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            // step1: CommandLine → process.command_line
            // step2: process.command_line → winlog.process.command_line
            assert_eq!(
                items[0].field.name,
                Some("winlog.process.command_line".to_string())
            );
            // step3: case upper only on winlog.process.command_line
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "WHOAMI");
            }

            // ParentImage → process.parent.executable → winlog.process.parent.executable
            assert_eq!(
                items[1].field.name,
                Some("winlog.process.parent.executable".to_string())
            );
            // step3 does NOT apply to this field → value unchanged
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.original, "\\cmd.exe");
            }
        } else {
            panic!("Expected AllOf");
        }

        // step4: custom attribute was set
        assert_eq!(
            rule.custom_attributes.get("rsigma.processed"),
            Some(&"true".to_string())
        );

        // All steps should be tracked
        assert!(state.was_applied("step1_map"));
        assert!(state.was_applied("step2_prefix"));
        assert!(state.was_applied("step3_case"));
        assert!(state.was_applied("step4_attr"));
    }
}
