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

mod correlation;
mod detection;
mod filter;
#[cfg(test)]
mod tests;

pub use detection::parse_field_spec;

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use serde_yaml::Value;

use crate::ast::*;
use crate::error::{Result, SigmaParserError};

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
        correlation::parse_correlation_rule(value).map(SigmaDocument::Correlation)
    } else if mapping.contains_key(Value::String("filter".into())) {
        filter::parse_filter_rule(value).map(SigmaDocument::Filter)
    } else {
        detection::parse_detection_rule(value).map(|r| SigmaDocument::Rule(Box::new(r)))
    }
}

// =============================================================================
// Shared helpers
// =============================================================================

/// Build the unified `custom_attributes` map for a rule document.
///
/// Merges two sources:
/// 1. Any top-level YAML key not in `standard_keys` (kept as-is, supports
///    arbitrary nested values).
/// 2. The entries of the top-level `custom_attributes:` mapping (if present),
///    which override (1) for colliding keys.
///
/// Pipeline transformations such as `SetCustomAttribute` are applied later
/// and can further override both sources.
pub(super) fn collect_custom_attributes(
    m: &serde_yaml::Mapping,
    standard_keys: &[&str],
) -> HashMap<String, Value> {
    let mut attrs: HashMap<String, Value> = m
        .iter()
        .filter_map(|(k, v)| {
            let key = k.as_str()?;
            if standard_keys.contains(&key) {
                None
            } else {
                Some((key.to_string(), v.clone()))
            }
        })
        .collect();

    if let Some(Value::Mapping(explicit)) = m.get(val_key("custom_attributes")) {
        for (k, v) in explicit {
            if let Some(key) = k.as_str() {
                attrs.insert(key.to_string(), v.clone());
            }
        }
    }

    attrs
}

pub(super) fn parse_logsource(value: &Value) -> Result<LogSource> {
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

pub(super) fn parse_related(value: Option<&Value>) -> Vec<Related> {
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

pub(super) fn val_key(s: &str) -> Value {
    Value::String(s.to_string())
}

pub(super) fn get_str<'a>(m: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    m.get(val_key(key)).and_then(|v| v.as_str())
}

pub(super) fn get_str_list(m: &serde_yaml::Mapping, key: &str) -> Vec<String> {
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
