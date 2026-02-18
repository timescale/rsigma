//! Main YAML → AST parser for Sigma rules, correlations, filters, and collections.
//!
//! Handles:
//! - Single-document YAML (one rule)
//! - Multi-document YAML (--- separator, action: global/reset/repeat)
//! - Detection section parsing (named detections, field modifiers, values)
//! - Correlation rule parsing
//! - Filter rule parsing
//! - Directory-based rule collection loading
//!
//! Reference: pySigma collection.py, rule.py, rule/detection.py, correlations.py

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use serde_yaml::Value;

use crate::ast::*;
use crate::condition::parse_condition;
use crate::error::{Result, SigmaParserError};
use crate::value::{SigmaValue, Timespan};

// =============================================================================
// Public API
// =============================================================================

/// Parse a YAML string containing one or more Sigma documents.
///
/// Handles multi-document YAML (separated by `---`) and collection actions
/// (`action: global`, `action: reset`, `action: repeat`).
///
/// Reference: pySigma collection.py SigmaCollection.from_yaml
pub fn parse_sigma_yaml(yaml: &str) -> Result<SigmaCollection> {
    let mut collection = SigmaCollection::new();
    let mut global: Option<Value> = None;
    let mut previous: Option<Value> = None;

    for doc in serde_yaml::Deserializer::from_str(yaml) {
        let value: Value = match Value::deserialize(doc) {
            Ok(v) => v,
            Err(e) => {
                collection.errors.push(format!("YAML parse error: {e}"));
                // A parse error leaves the YAML stream in an undefined state;
                // the deserializer iterator may never terminate on malformed
                // input, so we must stop iterating.
                break;
            }
        };

        let Some(mapping) = value.as_mapping() else {
            collection
                .errors
                .push("Document is not a YAML mapping".to_string());
            continue;
        };

        // Check for collection action
        if let Some(action_val) = mapping.get(Value::String("action".to_string())) {
            let Some(action) = action_val.as_str() else {
                collection.errors.push(format!(
                    "collection 'action' must be a string, got: {action_val:?}"
                ));
                continue;
            };
            match action {
                "global" => {
                    let mut global_map = value.clone();
                    if let Some(m) = global_map.as_mapping_mut() {
                        m.remove(Value::String("action".to_string()));
                    }
                    global = Some(global_map);
                    continue;
                }
                "reset" => {
                    global = None;
                    continue;
                }
                "repeat" => {
                    // Merge current document onto the previous document
                    if let Some(ref prev) = previous {
                        let mut repeat_val = value.clone();
                        if let Some(m) = repeat_val.as_mapping_mut() {
                            m.remove(Value::String("action".to_string()));
                        }
                        let merged_repeat = deep_merge(prev.clone(), repeat_val);

                        // Apply global template if present
                        let final_val = if let Some(ref global_val) = global {
                            deep_merge(global_val.clone(), merged_repeat)
                        } else {
                            merged_repeat
                        };

                        previous = Some(final_val.clone());

                        match parse_document(&final_val) {
                            Ok(doc) => match doc {
                                SigmaDocument::Rule(rule) => collection.rules.push(*rule),
                                SigmaDocument::Correlation(corr) => {
                                    collection.correlations.push(corr)
                                }
                                SigmaDocument::Filter(filter) => collection.filters.push(filter),
                            },
                            Err(e) => {
                                collection.errors.push(e.to_string());
                            }
                        }
                    } else {
                        collection
                            .errors
                            .push("'action: repeat' without a previous document".to_string());
                    }
                    continue;
                }
                other => {
                    collection
                        .errors
                        .push(format!("Unknown collection action: {other}"));
                    continue;
                }
            }
        }

        // Merge with global template if present
        let merged = if let Some(ref global_val) = global {
            deep_merge(global_val.clone(), value)
        } else {
            value
        };

        // Track previous document for `action: repeat`
        previous = Some(merged.clone());

        // Determine document type and parse
        match parse_document(&merged) {
            Ok(doc) => match doc {
                SigmaDocument::Rule(rule) => collection.rules.push(*rule),
                SigmaDocument::Correlation(corr) => collection.correlations.push(corr),
                SigmaDocument::Filter(filter) => collection.filters.push(filter),
            },
            Err(e) => {
                collection.errors.push(e.to_string());
            }
        }
    }

    Ok(collection)
}

/// Parse a single Sigma YAML file from a path.
pub fn parse_sigma_file(path: &Path) -> Result<SigmaCollection> {
    let content = std::fs::read_to_string(path)?;
    parse_sigma_yaml(&content)
}

/// Parse all Sigma YAML files from a directory (recursively).
pub fn parse_sigma_directory(dir: &Path) -> Result<SigmaCollection> {
    let mut collection = SigmaCollection::new();

    fn walk(dir: &Path, collection: &mut SigmaCollection) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk(&path, collection)?;
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yml" | "yaml")
            ) {
                match parse_sigma_file(&path) {
                    Ok(sub) => {
                        collection.rules.extend(sub.rules);
                        collection.correlations.extend(sub.correlations);
                        collection.filters.extend(sub.filters);
                        collection.errors.extend(sub.errors);
                    }
                    Err(e) => {
                        collection.errors.push(format!("{}: {e}", path.display()));
                    }
                }
            }
        }
        Ok(())
    }

    walk(dir, &mut collection)?;
    Ok(collection)
}

// =============================================================================
// Document type detection and dispatch
// =============================================================================

/// Parse a single YAML value into the appropriate Sigma document type.
///
/// Reference: pySigma collection.py from_dicts — checks for 'correlation' and 'filter' keys
fn parse_document(value: &Value) -> Result<SigmaDocument> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| SigmaParserError::InvalidRule("Document is not a YAML mapping".into()))?;

    if mapping.contains_key(Value::String("correlation".into())) {
        parse_correlation_rule(value).map(SigmaDocument::Correlation)
    } else if mapping.contains_key(Value::String("filter".into())) {
        parse_filter_rule(value).map(SigmaDocument::Filter)
    } else {
        parse_detection_rule(value).map(|r| SigmaDocument::Rule(Box::new(r)))
    }
}

// =============================================================================
// Detection Rule Parsing
// =============================================================================

/// Parse a detection rule from a YAML value.
///
/// Reference: pySigma rule.py SigmaRule.from_yaml / from_dict
fn parse_detection_rule(value: &Value) -> Result<SigmaRule> {
    let m = value
        .as_mapping()
        .ok_or_else(|| SigmaParserError::InvalidRule("Expected a YAML mapping".into()))?;

    let title = get_str(m, "title")
        .ok_or_else(|| SigmaParserError::MissingField("title".into()))?
        .to_string();

    let detection_val = m
        .get(val_key("detection"))
        .ok_or_else(|| SigmaParserError::MissingField("detection".into()))?;
    let detection = parse_detections(detection_val)?;

    let logsource = m
        .get(val_key("logsource"))
        .map(parse_logsource)
        .transpose()?
        .unwrap_or_default();

    Ok(SigmaRule {
        title,
        logsource,
        detection,
        id: get_str(m, "id").map(|s| s.to_string()),
        name: get_str(m, "name").map(|s| s.to_string()),
        related: parse_related(m.get(val_key("related"))),
        taxonomy: get_str(m, "taxonomy").map(|s| s.to_string()),
        status: get_str(m, "status").and_then(|s| s.parse().ok()),
        description: get_str(m, "description").map(|s| s.to_string()),
        license: get_str(m, "license").map(|s| s.to_string()),
        author: get_str(m, "author").map(|s| s.to_string()),
        references: get_str_list(m, "references"),
        date: get_str(m, "date").map(|s| s.to_string()),
        modified: get_str(m, "modified").map(|s| s.to_string()),
        fields: get_str_list(m, "fields"),
        falsepositives: get_str_list(m, "falsepositives"),
        level: get_str(m, "level").and_then(|s| s.parse().ok()),
        tags: get_str_list(m, "tags"),
        scope: get_str_list(m, "scope"),
        custom_attributes: HashMap::new(),
    })
}

// =============================================================================
// Detection Section Parsing
// =============================================================================

/// Parse the `detection:` section of a rule.
///
/// The detection section contains:
/// - `condition`: string or list of strings
/// - `timeframe`: optional duration string
/// - Everything else: named detection identifiers
///
/// Reference: pySigma rule/detection.py SigmaDetections.from_dict
fn parse_detections(value: &Value) -> Result<Detections> {
    let m = value.as_mapping().ok_or_else(|| {
        SigmaParserError::InvalidDetection("Detection section must be a mapping".into())
    })?;

    // Extract condition (required)
    let condition_val = m
        .get(val_key("condition"))
        .ok_or_else(|| SigmaParserError::MissingField("condition".into()))?;

    let condition_strings = match condition_val {
        Value::String(s) => vec![s.clone()],
        Value::Sequence(seq) => {
            let mut strings = Vec::with_capacity(seq.len());
            for v in seq {
                match v.as_str() {
                    Some(s) => strings.push(s.to_string()),
                    None => {
                        return Err(SigmaParserError::InvalidDetection(format!(
                            "condition list items must be strings, got: {v:?}"
                        )));
                    }
                }
            }
            strings
        }
        _ => {
            return Err(SigmaParserError::InvalidDetection(
                "condition must be a string or list of strings".into(),
            ));
        }
    };

    // Parse each condition string
    let conditions: Vec<ConditionExpr> = condition_strings
        .iter()
        .map(|s| parse_condition(s))
        .collect::<Result<Vec<_>>>()?;

    // Extract optional timeframe
    let timeframe = get_str(m, "timeframe").map(|s| s.to_string());

    // Parse all named detections (everything except condition and timeframe)
    let mut named = HashMap::new();
    for (key, val) in m {
        let key_str = key.as_str().unwrap_or("");
        if key_str == "condition" || key_str == "timeframe" {
            continue;
        }
        named.insert(key_str.to_string(), parse_detection(val)?);
    }

    Ok(Detections {
        named,
        conditions,
        condition_strings,
        timeframe,
    })
}

/// Parse a single named detection definition.
///
/// A detection can be:
/// 1. A mapping (key-value pairs, AND-linked)
/// 2. A list of plain values (keyword detection)
/// 3. A list of mappings (OR-linked sub-detections)
///
/// Reference: pySigma rule/detection.py SigmaDetection.from_definition
fn parse_detection(value: &Value) -> Result<Detection> {
    match value {
        Value::Mapping(m) => {
            // Case 1: key-value mapping → AND-linked detection items
            let items: Vec<DetectionItem> = m
                .iter()
                .map(|(k, v)| parse_detection_item(k.as_str().unwrap_or(""), v))
                .collect::<Result<Vec<_>>>()?;
            Ok(Detection::AllOf(items))
        }
        Value::Sequence(seq) => {
            // Check if all items are plain values (strings/numbers/etc.)
            let all_plain = seq.iter().all(|v| !v.is_mapping() && !v.is_sequence());
            if all_plain {
                // Case 2: list of plain values → keyword detection
                let values = seq.iter().map(SigmaValue::from_yaml).collect();
                Ok(Detection::Keywords(values))
            } else {
                // Case 3: list of mappings → OR-linked sub-detections
                let subs: Vec<Detection> = seq
                    .iter()
                    .map(parse_detection)
                    .collect::<Result<Vec<_>>>()?;
                Ok(Detection::AnyOf(subs))
            }
        }
        // Plain value → single keyword
        _ => Ok(Detection::Keywords(vec![SigmaValue::from_yaml(value)])),
    }
}

/// Parse a single detection item from a key-value pair.
///
/// The key contains the field name and optional modifiers separated by `|`:
/// - `EventType` → field="EventType", no modifiers
/// - `TargetObject|endswith` → field="TargetObject", modifiers=[EndsWith]
/// - `Destination|contains|all` → field="Destination", modifiers=[Contains, All]
///
/// Reference: pySigma rule/detection.py SigmaDetectionItem.from_mapping
fn parse_detection_item(key: &str, value: &Value) -> Result<DetectionItem> {
    let field = parse_field_spec(key)?;

    let values = match value {
        Value::Sequence(seq) => seq.iter().map(|v| to_sigma_value(v, &field)).collect(),
        _ => vec![to_sigma_value(value, &field)],
    };

    Ok(DetectionItem { field, values })
}

/// Convert a YAML value to a SigmaValue, respecting field modifiers.
///
/// When the `re` modifier is present, strings are treated as raw (no wildcard parsing).
fn to_sigma_value(v: &Value, field: &FieldSpec) -> SigmaValue {
    if field.has_modifier(Modifier::Re)
        && let Value::String(s) = v
    {
        return SigmaValue::from_raw_string(s);
    }
    SigmaValue::from_yaml(v)
}

/// Parse a field specification string like `"TargetObject|endswith"`.
///
/// Reference: pySigma rule/detection.py — `field, *modifier_ids = key.split("|")`
pub fn parse_field_spec(key: &str) -> Result<FieldSpec> {
    if key.is_empty() {
        return Ok(FieldSpec::new(None, Vec::new()));
    }

    let parts: Vec<&str> = key.split('|').collect();
    let field_name = parts[0];
    let field = if field_name.is_empty() {
        None
    } else {
        Some(field_name.to_string())
    };

    let mut modifiers = Vec::new();
    for &mod_str in &parts[1..] {
        let m = mod_str
            .parse::<Modifier>()
            .map_err(|_| SigmaParserError::UnknownModifier(mod_str.to_string()))?;
        modifiers.push(m);
    }

    Ok(FieldSpec::new(field, modifiers))
}

// =============================================================================
// Log Source Parsing
// =============================================================================

fn parse_logsource(value: &Value) -> Result<LogSource> {
    let m = value
        .as_mapping()
        .ok_or_else(|| SigmaParserError::InvalidRule("logsource must be a mapping".into()))?;

    let mut custom = HashMap::new();
    let known_keys = ["category", "product", "service", "definition"];

    for (k, v) in m {
        let key_str = k.as_str().unwrap_or("");
        if !known_keys.contains(&key_str) && !key_str.is_empty() {
            match v.as_str() {
                Some(val_str) => {
                    custom.insert(key_str.to_string(), val_str.to_string());
                }
                None => {
                    log::warn!(
                        "logsource custom field '{key_str}' has non-string value ({v:?}), skipping"
                    );
                }
            }
        }
    }

    Ok(LogSource {
        category: get_str(m, "category").map(|s| s.to_string()),
        product: get_str(m, "product").map(|s| s.to_string()),
        service: get_str(m, "service").map(|s| s.to_string()),
        definition: get_str(m, "definition").map(|s| s.to_string()),
        custom,
    })
}

// =============================================================================
// Related Rules Parsing
// =============================================================================

fn parse_related(value: Option<&Value>) -> Vec<Related> {
    let Some(Value::Sequence(seq)) = value else {
        return Vec::new();
    };

    seq.iter()
        .filter_map(|item| {
            let m = item.as_mapping()?;
            let id = get_str(m, "id")?.to_string();
            let type_str = get_str(m, "type")?;
            let relation_type = type_str.parse().ok()?;
            Some(Related { id, relation_type })
        })
        .collect()
}

// =============================================================================
// Correlation Rule Parsing
// =============================================================================

/// Parse a correlation rule from a YAML value.
///
/// Reference: pySigma correlations.py SigmaCorrelationRule.from_dict
fn parse_correlation_rule(value: &Value) -> Result<CorrelationRule> {
    let m = value
        .as_mapping()
        .ok_or_else(|| SigmaParserError::InvalidCorrelation("Expected a YAML mapping".into()))?;

    let title = get_str(m, "title")
        .ok_or_else(|| SigmaParserError::MissingField("title".into()))?
        .to_string();

    let corr_val = m
        .get(val_key("correlation"))
        .ok_or_else(|| SigmaParserError::MissingField("correlation".into()))?;
    let corr = corr_val.as_mapping().ok_or_else(|| {
        SigmaParserError::InvalidCorrelation("correlation must be a mapping".into())
    })?;

    // Correlation type (required)
    let type_str = get_str(corr, "type")
        .ok_or_else(|| SigmaParserError::InvalidCorrelation("Missing correlation type".into()))?;
    let correlation_type: CorrelationType = type_str.parse().map_err(|_| {
        SigmaParserError::InvalidCorrelation(format!("Unknown correlation type: {type_str}"))
    })?;

    // Rules references
    let rules = match corr.get(val_key("rules")) {
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    };

    // Group-by
    let group_by = match corr.get(val_key("group-by")) {
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    };

    // Timespan (required) — accept both "timeframe" (Sigma standard) and "timespan"
    let timespan_str = get_str(corr, "timeframe")
        .or_else(|| get_str(corr, "timespan"))
        .ok_or_else(|| SigmaParserError::InvalidCorrelation("Missing timeframe".into()))?;
    let timespan = Timespan::parse(timespan_str)?;

    // Generate flag
    let generate = corr
        .get(val_key("generate"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Condition
    let condition = parse_correlation_condition(corr, correlation_type)?;

    // Aliases
    let aliases = parse_correlation_aliases(corr);

    // Custom attributes (rsigma.* extension keys)
    let custom_attributes = if let Some(Value::Mapping(attrs)) = m.get(val_key("custom_attributes"))
    {
        attrs
            .iter()
            .filter_map(|(k, v)| Some((k.as_str()?.to_string(), v.as_str()?.to_string())))
            .collect()
    } else {
        std::collections::HashMap::new()
    };

    Ok(CorrelationRule {
        title,
        id: get_str(m, "id").map(|s| s.to_string()),
        name: get_str(m, "name").map(|s| s.to_string()),
        status: get_str(m, "status").and_then(|s| s.parse().ok()),
        description: get_str(m, "description").map(|s| s.to_string()),
        author: get_str(m, "author").map(|s| s.to_string()),
        date: get_str(m, "date").map(|s| s.to_string()),
        modified: get_str(m, "modified").map(|s| s.to_string()),
        references: get_str_list(m, "references"),
        tags: get_str_list(m, "tags"),
        level: get_str(m, "level").and_then(|s| s.parse().ok()),
        correlation_type,
        rules,
        group_by,
        timespan,
        condition,
        aliases,
        generate,
        custom_attributes,
    })
}

/// Parse a correlation condition (either threshold dict or extended string).
///
/// Reference: pySigma correlations.py SigmaCorrelationCondition.from_dict
fn parse_correlation_condition(
    corr: &serde_yaml::Mapping,
    correlation_type: CorrelationType,
) -> Result<CorrelationCondition> {
    let condition_val = corr.get(val_key("condition"));

    match condition_val {
        Some(Value::Mapping(cm)) => {
            // Threshold condition: { gte: 100 } or range { gt: 100, lte: 200, field: "username" }
            let operators = ["lt", "lte", "gt", "gte", "eq", "neq"];
            let mut predicates = Vec::new();

            for &op_str in &operators {
                if let Some(val) = cm.get(val_key(op_str))
                    && let Ok(parsed_op) = op_str.parse::<ConditionOperator>()
                {
                    let count = val
                        .as_u64()
                        .or_else(|| val.as_i64().map(|i| i as u64))
                        .ok_or_else(|| {
                            SigmaParserError::InvalidCorrelation(format!(
                                "correlation condition operator '{op_str}' requires a numeric value, got: {val:?}"
                            ))
                        })?;
                    predicates.push((parsed_op, count));
                }
            }

            if predicates.is_empty() {
                return Err(SigmaParserError::InvalidCorrelation(
                    "Correlation condition must have an operator (lt, lte, gt, gte, eq, neq)"
                        .into(),
                ));
            }

            let field = get_str(cm, "field").map(|s| s.to_string());

            Ok(CorrelationCondition::Threshold { predicates, field })
        }
        Some(Value::String(expr_str)) => {
            // Extended condition for temporal types: "rule_a and rule_b"
            let expr = parse_condition(expr_str)?;
            Ok(CorrelationCondition::Extended(expr))
        }
        None => {
            // Default for temporal types: all rules must match
            match correlation_type {
                CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                    Ok(CorrelationCondition::Threshold {
                        predicates: vec![(ConditionOperator::Gte, 1)],
                        field: None,
                    })
                }
                _ => Err(SigmaParserError::InvalidCorrelation(
                    "Non-temporal correlation rule requires a condition".into(),
                )),
            }
        }
        _ => Err(SigmaParserError::InvalidCorrelation(
            "Correlation condition must be a mapping or string".into(),
        )),
    }
}

/// Parse correlation field aliases.
fn parse_correlation_aliases(corr: &serde_yaml::Mapping) -> Vec<FieldAlias> {
    let Some(Value::Mapping(aliases_map)) = corr.get(val_key("aliases")) else {
        return Vec::new();
    };

    aliases_map
        .iter()
        .filter_map(|(alias_key, alias_val)| {
            let alias = alias_key.as_str()?.to_string();
            let mapping_map = alias_val.as_mapping()?;
            let mapping: HashMap<String, String> = mapping_map
                .iter()
                .filter_map(|(k, v)| Some((k.as_str()?.to_string(), v.as_str()?.to_string())))
                .collect();
            Some(FieldAlias { alias, mapping })
        })
        .collect()
}

// =============================================================================
// Filter Rule Parsing
// =============================================================================

/// Parse a filter rule from a YAML value.
fn parse_filter_rule(value: &Value) -> Result<FilterRule> {
    let m = value
        .as_mapping()
        .ok_or_else(|| SigmaParserError::InvalidRule("Expected a YAML mapping".into()))?;

    let title = get_str(m, "title")
        .ok_or_else(|| SigmaParserError::MissingField("title".into()))?
        .to_string();

    // Get filter section for rules list
    let filter_val = m.get(val_key("filter"));
    let filter_mapping = filter_val.and_then(|v| v.as_mapping());
    let rules = match filter_mapping {
        Some(fm) => match fm.get(val_key("rules")) {
            Some(Value::Sequence(seq)) => seq
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };

    // Parse detection from filter.selection + filter.condition
    // (Sigma filter spec: selection/condition live inside the filter section).
    let detection = if let Some(fm) = filter_mapping {
        let mut det_map = serde_yaml::Mapping::new();
        for (k, v) in fm.iter() {
            let key_str = k.as_str().unwrap_or("");
            if key_str != "rules" {
                det_map.insert(k.clone(), v.clone());
            }
        }
        if det_map.is_empty() {
            return Err(SigmaParserError::MissingField("filter.selection".into()));
        }
        parse_detections(&Value::Mapping(det_map))?
    } else {
        return Err(SigmaParserError::MissingField("filter".into()));
    };

    let logsource = m
        .get(val_key("logsource"))
        .map(parse_logsource)
        .transpose()?;

    Ok(FilterRule {
        title,
        id: get_str(m, "id").map(|s| s.to_string()),
        name: get_str(m, "name").map(|s| s.to_string()),
        status: get_str(m, "status").and_then(|s| s.parse().ok()),
        description: get_str(m, "description").map(|s| s.to_string()),
        author: get_str(m, "author").map(|s| s.to_string()),
        date: get_str(m, "date").map(|s| s.to_string()),
        modified: get_str(m, "modified").map(|s| s.to_string()),
        logsource,
        rules,
        detection,
    })
}

// =============================================================================
// YAML Helpers
// =============================================================================

fn val_key(s: &str) -> Value {
    Value::String(s.to_string())
}

fn get_str<'a>(m: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    m.get(val_key(key)).and_then(|v| v.as_str())
}

fn get_str_list(m: &serde_yaml::Mapping, key: &str) -> Vec<String> {
    match m.get(val_key(key)) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Deep-merge two YAML values (src overrides dest, recursively for mappings).
///
/// Reference: pySigma collection.py deep_dict_update
fn deep_merge(dest: Value, src: Value) -> Value {
    match (dest, src) {
        (Value::Mapping(mut dest_map), Value::Mapping(src_map)) => {
            for (k, v) in src_map {
                let merged = if let Some(existing) = dest_map.remove(&k) {
                    deep_merge(existing, v)
                } else {
                    v
                };
                dest_map.insert(k, merged);
            }
            Value::Mapping(dest_map)
        }
        (_, src) => src, // non-mapping: source wins
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let yaml = r#"
title: Test Rule
id: 12345678-1234-1234-1234-123456789012
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 1);

        let rule = &collection.rules[0];
        assert_eq!(rule.title, "Test Rule");
        assert_eq!(rule.logsource.product, Some("windows".to_string()));
        assert_eq!(
            rule.logsource.category,
            Some("process_creation".to_string())
        );
        assert_eq!(rule.level, Some(Level::Medium));
        assert_eq!(rule.detection.conditions.len(), 1);
        assert_eq!(
            rule.detection.conditions[0],
            ConditionExpr::Identifier("selection".to_string())
        );
        assert!(rule.detection.named.contains_key("selection"));
    }

    #[test]
    fn test_parse_field_modifiers() {
        let spec = parse_field_spec("TargetObject|endswith").unwrap();
        assert_eq!(spec.name, Some("TargetObject".to_string()));
        assert_eq!(spec.modifiers, vec![Modifier::EndsWith]);

        let spec = parse_field_spec("Destination|contains|all").unwrap();
        assert_eq!(spec.name, Some("Destination".to_string()));
        assert_eq!(spec.modifiers, vec![Modifier::Contains, Modifier::All]);

        let spec = parse_field_spec("Details|re").unwrap();
        assert_eq!(spec.name, Some("Details".to_string()));
        assert_eq!(spec.modifiers, vec![Modifier::Re]);

        let spec = parse_field_spec("Destination|base64offset|contains").unwrap();
        assert_eq!(
            spec.modifiers,
            vec![Modifier::Base64Offset, Modifier::Contains]
        );
    }

    #[test]
    fn test_parse_complex_condition() {
        let yaml = r#"
title: Complex Rule
logsource:
    product: windows
    category: registry_set
detection:
    selection_main:
        TargetObject|contains: '\SOFTWARE\Microsoft\Windows Defender\'
    selection_dword_1:
        Details: 'DWORD (0x00000001)'
    filter_optional_symantec:
        Image|startswith: 'C:\Program Files\Symantec\'
    condition: selection_main and 1 of selection_dword_* and not 1 of filter_optional_*
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 1);

        let rule = &collection.rules[0];
        assert_eq!(rule.detection.named.len(), 3);

        let cond = &rule.detection.conditions[0];
        match cond {
            ConditionExpr::And(args) => {
                assert_eq!(args.len(), 3);
            }
            _ => panic!("Expected AND condition"),
        }
    }

    #[test]
    fn test_parse_condition_list() {
        let yaml = r#"
title: Multi-condition Rule
logsource:
    category: test
detection:
    selection1:
        username: user1
    selection2:
        username: user2
    condition:
        - selection1
        - selection2
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let rule = &collection.rules[0];
        assert_eq!(rule.detection.conditions.len(), 2);
    }

    #[test]
    fn test_parse_correlation_rule() {
        let yaml = r#"
title: Base Rule
id: f305fd62-beca-47da-ad95-7690a0620084
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: "s3.amazonaws.com"
    condition: selection
level: low
---
title: Multiple AWS bucket enumerations
id: be246094-01d3-4bba-88de-69e582eba0cc
status: experimental
correlation:
    type: event_count
    rules:
        - f305fd62-beca-47da-ad95-7690a0620084
    group-by:
        - userIdentity.arn
    timespan: 1h
    condition:
        gte: 100
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 1);
        assert_eq!(collection.correlations.len(), 1);

        let corr = &collection.correlations[0];
        assert_eq!(corr.correlation_type, CorrelationType::EventCount);
        assert_eq!(corr.timespan.seconds, 3600);
        assert_eq!(corr.group_by, vec!["userIdentity.arn"]);

        match &corr.condition {
            CorrelationCondition::Threshold { predicates, .. } => {
                assert_eq!(predicates.len(), 1);
                assert_eq!(predicates[0].0, ConditionOperator::Gte);
                assert_eq!(predicates[0].1, 100);
            }
            _ => panic!("Expected threshold condition"),
        }
    }

    #[test]
    fn test_parse_correlation_rule_custom_attributes() {
        let yaml = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
custom_attributes:
    rsigma.correlation_event_mode: refs
    rsigma.suppress: 5m
    rsigma.action: reset
    rsigma.max_correlation_events: "25"
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.correlations.len(), 1);

        let corr = &collection.correlations[0];
        assert_eq!(
            corr.custom_attributes.get("rsigma.correlation_event_mode"),
            Some(&"refs".to_string())
        );
        assert_eq!(
            corr.custom_attributes.get("rsigma.suppress"),
            Some(&"5m".to_string())
        );
        assert_eq!(
            corr.custom_attributes.get("rsigma.action"),
            Some(&"reset".to_string())
        );
        assert_eq!(
            corr.custom_attributes.get("rsigma.max_correlation_events"),
            Some(&"25".to_string())
        );
    }

    #[test]
    fn test_parse_correlation_rule_no_custom_attributes() {
        let yaml = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let corr = &collection.correlations[0];
        assert!(corr.custom_attributes.is_empty());
    }

    #[test]
    fn test_parse_detection_or_linked() {
        let yaml = r#"
title: OR-linked detections
logsource:
    product: windows
    category: wmi_event
detection:
    selection:
        - Destination|contains|all:
              - 'new-object'
              - 'net.webclient'
        - Destination|contains:
              - 'WScript.Shell'
    condition: selection
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let rule = &collection.rules[0];
        let detection = &rule.detection.named["selection"];

        match detection {
            Detection::AnyOf(subs) => {
                assert_eq!(subs.len(), 2);
            }
            _ => panic!("Expected AnyOf detection, got {detection:?}"),
        }
    }

    #[test]
    fn test_parse_global_action() {
        let yaml = r#"
action: global
title: Global Rule
logsource:
    product: windows
---
detection:
    selection:
        EventID: 1
    condition: selection
level: high
---
detection:
    selection:
        EventID: 2
    condition: selection
level: medium
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 2);
        assert_eq!(collection.rules[0].title, "Global Rule");
        assert_eq!(collection.rules[1].title, "Global Rule");
    }

    #[test]
    fn test_unknown_modifier_error() {
        let result = parse_field_spec("field|foobar");
        assert!(result.is_err());
    }

    // ── Field modifier edge cases ────────────────────────────────────────

    #[test]
    fn test_parse_contains_re_combination() {
        let spec = parse_field_spec("CommandLine|contains|re").unwrap();
        assert_eq!(spec.modifiers, vec![Modifier::Contains, Modifier::Re]);
    }

    #[test]
    fn test_parse_duplicate_modifiers() {
        let spec = parse_field_spec("Field|contains|contains").unwrap();
        assert_eq!(spec.modifiers, vec![Modifier::Contains, Modifier::Contains]);
    }

    #[test]
    fn test_parse_conflicting_string_match_modifiers() {
        let spec = parse_field_spec("Field|contains|startswith").unwrap();
        assert_eq!(
            spec.modifiers,
            vec![Modifier::Contains, Modifier::StartsWith]
        );
    }

    #[test]
    fn test_parse_conflicting_endswith_startswith() {
        let spec = parse_field_spec("Field|endswith|startswith").unwrap();
        assert_eq!(
            spec.modifiers,
            vec![Modifier::EndsWith, Modifier::StartsWith]
        );
    }

    #[test]
    fn test_parse_re_with_contains() {
        let spec = parse_field_spec("Field|re|contains").unwrap();
        assert_eq!(spec.modifiers, vec![Modifier::Re, Modifier::Contains]);
    }

    #[test]
    fn test_parse_cidr_with_contains() {
        let spec = parse_field_spec("Field|cidr|contains").unwrap();
        assert_eq!(spec.modifiers, vec![Modifier::Cidr, Modifier::Contains]);
    }

    #[test]
    fn test_parse_multiple_encoding_modifiers() {
        let spec = parse_field_spec("Field|base64|wide|base64offset").unwrap();
        assert_eq!(
            spec.modifiers,
            vec![Modifier::Base64, Modifier::Wide, Modifier::Base64Offset]
        );
    }

    #[test]
    fn test_parse_numeric_with_string_modifiers() {
        let spec = parse_field_spec("Field|gt|contains").unwrap();
        assert_eq!(spec.modifiers, vec![Modifier::Gt, Modifier::Contains]);
    }

    #[test]
    fn test_parse_exists_with_other_modifiers() {
        let spec = parse_field_spec("Field|exists|contains").unwrap();
        assert_eq!(spec.modifiers, vec![Modifier::Exists, Modifier::Contains]);
    }

    #[test]
    fn test_parse_re_with_regex_flags() {
        let spec = parse_field_spec("Field|re|i|m|s").unwrap();
        assert_eq!(
            spec.modifiers,
            vec![
                Modifier::Re,
                Modifier::IgnoreCase,
                Modifier::Multiline,
                Modifier::DotAll
            ]
        );
    }

    #[test]
    fn test_parse_regex_flags_without_re() {
        let spec = parse_field_spec("Field|i|m").unwrap();
        assert_eq!(
            spec.modifiers,
            vec![Modifier::IgnoreCase, Modifier::Multiline]
        );
    }

    #[test]
    fn test_keyword_detection() {
        let yaml = r#"
title: Keyword Rule
logsource:
    category: test
detection:
    keywords:
        - 'suspicious'
        - 'malware'
    condition: keywords
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let rule = &collection.rules[0];
        let det = &rule.detection.named["keywords"];
        match det {
            Detection::Keywords(vals) => assert_eq!(vals.len(), 2),
            _ => panic!("Expected Keywords detection"),
        }
    }

    #[test]
    fn test_action_repeat() {
        let yaml = r#"
title: Base Rule
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
---
action: repeat
title: Repeated Rule
detection:
    selection:
        CommandLine|contains: 'ipconfig'
    condition: selection
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 2);
        assert!(
            collection.errors.is_empty(),
            "errors: {:?}",
            collection.errors
        );

        // First rule is the original
        assert_eq!(collection.rules[0].title, "Base Rule");
        assert_eq!(collection.rules[0].level, Some(crate::ast::Level::Medium));
        assert_eq!(
            collection.rules[0].logsource.product,
            Some("windows".to_string())
        );

        // Second rule inherits from first, but overrides title and detection
        assert_eq!(collection.rules[1].title, "Repeated Rule");
        // Logsource and level are inherited from the previous document
        assert_eq!(
            collection.rules[1].logsource.product,
            Some("windows".to_string())
        );
        assert_eq!(
            collection.rules[1].logsource.category,
            Some("process_creation".to_string())
        );
        assert_eq!(collection.rules[1].level, Some(crate::ast::Level::Medium));
    }

    #[test]
    fn test_action_repeat_no_previous() {
        let yaml = r#"
action: repeat
title: Orphan Rule
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 0);
        assert_eq!(collection.errors.len(), 1);
        assert!(collection.errors[0].contains("without a previous document"));
    }

    #[test]
    fn test_action_repeat_multiple_repeats() {
        // Base rule + two repeats producing three rules total
        let yaml = r#"
title: Base
logsource:
    product: windows
    category: process_creation
level: high
detection:
    selection:
        CommandLine|contains: 'cmd'
    condition: selection
---
action: repeat
title: Repeat One
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
---
action: repeat
title: Repeat Two
detection:
    selection:
        CommandLine|contains: 'wscript'
    condition: selection
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 3);
        assert!(collection.errors.is_empty());
        assert_eq!(collection.rules[0].title, "Base");
        assert_eq!(collection.rules[1].title, "Repeat One");
        assert_eq!(collection.rules[2].title, "Repeat Two");

        // All three should inherit logsource and level from the base
        for rule in &collection.rules {
            assert_eq!(rule.logsource.product, Some("windows".to_string()));
            assert_eq!(
                rule.logsource.category,
                Some("process_creation".to_string())
            );
            assert_eq!(rule.level, Some(crate::ast::Level::High));
        }
    }

    #[test]
    fn test_action_repeat_chained_inherits_from_last() {
        // Repeat chains from the *last* document, not the original
        let yaml = r#"
title: First
logsource:
    product: linux
level: low
detection:
    selection:
        command|contains: 'ls'
    condition: selection
---
action: repeat
title: Second
level: medium
detection:
    selection:
        command|contains: 'cat'
    condition: selection
---
action: repeat
title: Third
detection:
    selection:
        command|contains: 'grep'
    condition: selection
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 3);

        // First: level low
        assert_eq!(collection.rules[0].level, Some(crate::ast::Level::Low));
        // Second: level overridden to medium
        assert_eq!(collection.rules[1].level, Some(crate::ast::Level::Medium));
        // Third: inherits from second (merged onto second), so level medium
        assert_eq!(collection.rules[2].level, Some(crate::ast::Level::Medium));
        // All should have linux product
        for rule in &collection.rules {
            assert_eq!(rule.logsource.product, Some("linux".to_string()));
        }
    }

    #[test]
    fn test_action_repeat_with_global_template() {
        let yaml = r#"
action: global
logsource:
    product: windows
level: medium
---
title: Rule A
detection:
    selection:
        EventID: 1
    condition: selection
---
action: repeat
title: Rule B
detection:
    selection:
        EventID: 2
    condition: selection
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 2);
        assert!(collection.errors.is_empty());

        assert_eq!(collection.rules[0].title, "Rule A");
        assert_eq!(collection.rules[1].title, "Rule B");

        // Both should have the global logsource and level
        for rule in &collection.rules {
            assert_eq!(rule.logsource.product, Some("windows".to_string()));
            assert_eq!(rule.level, Some(crate::ast::Level::Medium));
        }
    }

    #[test]
    fn test_correlation_condition_range() {
        let yaml = r#"
title: Base Rule
name: base_rule
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
level: low
---
title: Range Correlation
name: range_test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - User
    timespan: 1h
    condition:
        gt: 10
        lte: 100
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.correlations.len(), 1);
        let corr = &collection.correlations[0];

        match &corr.condition {
            CorrelationCondition::Threshold { predicates, field } => {
                assert_eq!(predicates.len(), 2);
                // Check we got both operators (order doesn't matter, but they come from iteration)
                let has_gt = predicates
                    .iter()
                    .any(|(op, v)| *op == ConditionOperator::Gt && *v == 10);
                let has_lte = predicates
                    .iter()
                    .any(|(op, v)| *op == ConditionOperator::Lte && *v == 100);
                assert!(has_gt, "Expected gt: 10 predicate");
                assert!(has_lte, "Expected lte: 100 predicate");
                assert!(field.is_none());
            }
            _ => panic!("Expected threshold condition"),
        }
    }

    #[test]
    fn test_correlation_condition_range_with_field() {
        let yaml = r#"
title: Base Rule
name: base_rule
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
level: low
---
title: Range With Field
name: range_with_field
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 5
        lt: 50
        field: TargetUser
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let corr = &collection.correlations[0];

        match &corr.condition {
            CorrelationCondition::Threshold { predicates, field } => {
                assert_eq!(predicates.len(), 2);
                assert_eq!(field.as_deref(), Some("TargetUser"));
            }
            _ => panic!("Expected threshold condition"),
        }
    }

    #[test]
    fn test_parse_neq_modifier() {
        let yaml = r#"
title: Neq Modifier
logsource:
    product: windows
detection:
    selection:
        Port|neq: 443
    condition: selection
level: medium
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let rule = &collection.rules[0];
        let det = rule.detection.named.get("selection").unwrap();
        match det {
            crate::ast::Detection::AllOf(items) => {
                assert!(items[0].field.modifiers.contains(&Modifier::Neq));
            }
            _ => panic!("Expected AllOf detection"),
        }
    }

    #[test]
    fn test_parse_utf16be_modifier() {
        let yaml = r#"
title: Utf16be Modifier
logsource:
    product: windows
detection:
    selection:
        Payload|utf16be|base64: 'data'
    condition: selection
level: medium
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let rule = &collection.rules[0];
        let det = rule.detection.named.get("selection").unwrap();
        match det {
            crate::ast::Detection::AllOf(items) => {
                assert!(items[0].field.modifiers.contains(&Modifier::Utf16be));
                assert!(items[0].field.modifiers.contains(&Modifier::Base64));
            }
            _ => panic!("Expected AllOf detection"),
        }
    }

    #[test]
    fn test_parse_utf16_modifier() {
        let yaml = r#"
title: Utf16 BOM Modifier
logsource:
    product: windows
detection:
    selection:
        Payload|utf16|base64: 'data'
    condition: selection
level: medium
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let rule = &collection.rules[0];
        let det = rule.detection.named.get("selection").unwrap();
        match det {
            crate::ast::Detection::AllOf(items) => {
                assert!(items[0].field.modifiers.contains(&Modifier::Utf16));
                assert!(items[0].field.modifiers.contains(&Modifier::Base64));
            }
            _ => panic!("Expected AllOf detection"),
        }
    }

    // ── Multi-document YAML inheritance tests ─────────────────────────────

    #[test]
    fn test_action_reset_clears_global() {
        let yaml = r#"
action: global
title: Global Template
logsource:
    product: windows
level: high
---
detection:
    selection:
        EventID: 1
    condition: selection
---
action: reset
---
title: After Reset
logsource:
    product: linux
detection:
    selection:
        command: ls
    condition: selection
level: low
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert!(
            collection.errors.is_empty(),
            "errors: {:?}",
            collection.errors
        );
        assert_eq!(collection.rules.len(), 2);

        // First rule inherits from global: title "Global Template", product windows
        assert_eq!(collection.rules[0].title, "Global Template");
        assert_eq!(
            collection.rules[0].logsource.product,
            Some("windows".to_string())
        );
        assert_eq!(collection.rules[0].level, Some(Level::High));

        // After reset, global is cleared — second rule is standalone
        assert_eq!(collection.rules[1].title, "After Reset");
        assert_eq!(
            collection.rules[1].logsource.product,
            Some("linux".to_string())
        );
        assert_eq!(collection.rules[1].level, Some(Level::Low));
    }

    #[test]
    fn test_global_repeat_reset_combined() {
        let yaml = r#"
action: global
logsource:
    product: windows
level: medium
---
title: Rule A
detection:
    selection:
        EventID: 1
    condition: selection
---
action: repeat
title: Rule B
detection:
    selection:
        EventID: 2
    condition: selection
---
action: reset
---
title: Rule C
logsource:
    product: linux
detection:
    selection:
        command: cat
    condition: selection
level: low
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert!(
            collection.errors.is_empty(),
            "errors: {:?}",
            collection.errors
        );
        assert_eq!(collection.rules.len(), 3);

        // Rule A: global applied
        assert_eq!(collection.rules[0].title, "Rule A");
        assert_eq!(
            collection.rules[0].logsource.product,
            Some("windows".to_string())
        );
        assert_eq!(collection.rules[0].level, Some(Level::Medium));

        // Rule B: repeat of Rule A + global
        assert_eq!(collection.rules[1].title, "Rule B");
        assert_eq!(
            collection.rules[1].logsource.product,
            Some("windows".to_string())
        );
        assert_eq!(collection.rules[1].level, Some(Level::Medium));

        // Rule C: after reset, no global — standalone
        assert_eq!(collection.rules[2].title, "Rule C");
        assert_eq!(
            collection.rules[2].logsource.product,
            Some("linux".to_string())
        );
        assert_eq!(collection.rules[2].level, Some(Level::Low));
    }

    #[test]
    fn test_deep_repeat_chain() {
        let yaml = r#"
title: Base
logsource:
    product: windows
    category: process_creation
level: low
detection:
    selection:
        CommandLine|contains: 'cmd'
    condition: selection
---
action: repeat
title: Second
level: medium
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
---
action: repeat
title: Third
level: high
detection:
    selection:
        CommandLine|contains: 'wscript'
    condition: selection
---
action: repeat
title: Fourth
detection:
    selection:
        CommandLine|contains: 'cscript'
    condition: selection
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert!(
            collection.errors.is_empty(),
            "errors: {:?}",
            collection.errors
        );
        assert_eq!(collection.rules.len(), 4);

        assert_eq!(collection.rules[0].level, Some(Level::Low));
        assert_eq!(collection.rules[1].level, Some(Level::Medium));
        assert_eq!(collection.rules[2].level, Some(Level::High));
        // Fourth inherits from Third (which had level high)
        assert_eq!(collection.rules[3].level, Some(Level::High));

        // All should inherit logsource from the chain
        for rule in &collection.rules {
            assert_eq!(rule.logsource.product, Some("windows".to_string()));
            assert_eq!(
                rule.logsource.category,
                Some("process_creation".to_string())
            );
        }
    }

    #[test]
    fn test_collect_errors_mixed_valid_invalid() {
        let yaml = r#"
title: Valid Rule
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: low
---
title: Invalid Rule
detection:
    selection:
        field: value
"#;
        // The second document is missing 'condition' — should generate an error
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 1);
        assert_eq!(collection.rules[0].title, "Valid Rule");
        assert!(
            !collection.errors.is_empty(),
            "Expected errors for invalid doc"
        );
    }

    #[test]
    fn test_reset_followed_by_repeat_inherits_previous() {
        // `action: reset` only clears the global template — `previous`
        // is not affected, so a subsequent `repeat` still inherits from
        // the last non-action document.
        let yaml = r#"
title: Base
logsource:
    category: test
detection:
    selection:
        field: val
    condition: selection
level: low
---
action: reset
---
action: repeat
title: Repeated After Reset
detection:
    selection:
        field: val2
    condition: selection
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert!(
            collection.errors.is_empty(),
            "errors: {:?}",
            collection.errors
        );
        assert_eq!(collection.rules.len(), 2);
        assert_eq!(collection.rules[0].title, "Base");
        assert_eq!(collection.rules[1].title, "Repeated After Reset");
        // Inherits logsource from Base (previous), but no global
        assert_eq!(
            collection.rules[1].logsource.category,
            Some("test".to_string())
        );
        assert_eq!(collection.rules[1].level, Some(Level::Low));
    }

    #[test]
    fn test_deep_merge_nested_maps() {
        let yaml = r#"
action: global
logsource:
    product: windows
    service: sysmon
    category: process_creation
---
title: Override Service
logsource:
    service: security
detection:
    selection:
        EventID: 1
    condition: selection
level: low
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert!(
            collection.errors.is_empty(),
            "errors: {:?}",
            collection.errors
        );
        assert_eq!(collection.rules.len(), 1);

        let rule = &collection.rules[0];
        // Deep merge: product and category from global, service overridden
        assert_eq!(rule.logsource.product, Some("windows".to_string()));
        assert_eq!(rule.logsource.service, Some("security".to_string()));
        assert_eq!(
            rule.logsource.category,
            Some("process_creation".to_string())
        );
    }
}
