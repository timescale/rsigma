use std::collections::HashMap;

use serde_yaml::Value;

use crate::ast::*;
use crate::condition::parse_condition;
use crate::error::{Result, SigmaParserError};
use crate::value::SigmaValue;

use super::{
    collect_custom_attributes, get_str, get_str_list, parse_logsource, parse_related, val_key,
};

// =============================================================================
// Detection Rule Parsing
// =============================================================================

/// Parse a detection rule from a YAML value.
///
/// Reference: pySigma rule.py SigmaRule.from_yaml / from_dict
pub(super) fn parse_detection_rule(value: &Value) -> Result<SigmaRule> {
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

    // Custom attributes: merge arbitrary top-level keys and the entries of the
    // dedicated `custom_attributes:` mapping. Entries in `custom_attributes:`
    // win over a top-level key of the same name (last-write-wins).
    // Mirrors pySigma's `SigmaRule.custom_attributes` dict.
    let standard_rule_keys: &[&str] = &[
        "title",
        "id",
        "related",
        "name",
        "taxonomy",
        "status",
        "description",
        "license",
        "author",
        "references",
        "date",
        "modified",
        "logsource",
        "detection",
        "fields",
        "falsepositives",
        "level",
        "tags",
        "scope",
        "custom_attributes",
    ];
    let custom_attributes = collect_custom_attributes(m, standard_rule_keys);

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
        custom_attributes,
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
pub(super) fn parse_detections(value: &Value) -> Result<Detections> {
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
