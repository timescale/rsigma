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
pub(crate) use {
    correlation::STANDARD_CORRELATION_KEYS, detection::STANDARD_RULE_KEYS,
    filter::STANDARD_FILTER_KEYS,
};

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use yaml_serde::Value;

use crate::ast::*;
use crate::diagnostic::{CollectionDiagnostic, DiagnosticKind};
use crate::error::{Result, SigmaParserError, SourceLocation};

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

    for (index, doc) in yaml_serde::Deserializer::from_str(yaml).enumerate() {
        let report = |collection: &mut SigmaCollection, diagnostic: CollectionDiagnostic| {
            collection.diagnostics.push(diagnostic.with_document(index));
        };

        let value: Value = match Value::deserialize(doc) {
            Ok(v) => v,
            Err(e) => {
                let location = e.location().map(|loc| SourceLocation {
                    line: u32::try_from(loc.line()).unwrap_or(u32::MAX),
                    col: u32::try_from(loc.column()).unwrap_or(u32::MAX),
                });
                report(
                    &mut collection,
                    CollectionDiagnostic::error(
                        DiagnosticKind::YamlSyntax,
                        format!("YAML parse error: {e}"),
                    )
                    .with_location(location),
                );
                // A parse error leaves the YAML stream in an undefined state;
                // the deserializer iterator may never terminate on malformed
                // input, so we must stop iterating.
                break;
            }
        };

        let Some(mapping) = value.as_mapping() else {
            report(
                &mut collection,
                CollectionDiagnostic::error(
                    DiagnosticKind::NotAMapping,
                    "Document is not a YAML mapping",
                ),
            );
            continue;
        };

        // Check for collection action
        let to_parse = if let Some(action_val) = mapping.get(Value::String("action".to_string())) {
            let Some(action) = action_val.as_str() else {
                report(
                    &mut collection,
                    CollectionDiagnostic::error(
                        DiagnosticKind::CollectionAction,
                        format!("collection 'action' must be a string, got: {action_val:?}"),
                    ),
                );
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
                    let Some(ref prev) = previous else {
                        report(
                            &mut collection,
                            CollectionDiagnostic::error(
                                DiagnosticKind::CollectionAction,
                                "'action: repeat' without a previous document",
                            ),
                        );
                        continue;
                    };
                    let mut repeat_val = value.clone();
                    if let Some(m) = repeat_val.as_mapping_mut() {
                        m.remove(Value::String("action".to_string()));
                    }
                    let merged_repeat = deep_merge(prev.clone(), repeat_val)?;

                    // Apply global template if present
                    if let Some(ref global_val) = global {
                        deep_merge(global_val.clone(), merged_repeat)?
                    } else {
                        merged_repeat
                    }
                }
                other => {
                    report(
                        &mut collection,
                        CollectionDiagnostic::error(
                            DiagnosticKind::CollectionAction,
                            format!("Unknown collection action: {other}"),
                        ),
                    );
                    continue;
                }
            }
        } else if let Some(ref global_val) = global {
            // Merge with global template if present
            deep_merge(global_val.clone(), value)?
        } else {
            value
        };

        // Track previous document for `action: repeat`
        previous = Some(to_parse.clone());

        // Determine document type and parse
        let mut doc_warnings = Vec::new();
        let parsed = parse_document(&to_parse, &mut doc_warnings);
        for warning in doc_warnings {
            report(&mut collection, warning);
        }
        match parsed {
            Ok(SigmaDocument::Rule(rule)) => collection.rules.push(*rule),
            Ok(SigmaDocument::Correlation(corr)) => collection.correlations.push(corr),
            Ok(SigmaDocument::Filter(filter)) => collection.filters.push(filter),
            Err(e) => report(&mut collection, CollectionDiagnostic::document(&e)),
        }
    }

    Ok(collection)
}

/// Parse a single Sigma YAML file from a path.
///
/// Every diagnostic in the returned collection carries `path`.
pub fn parse_sigma_file(path: &Path) -> Result<SigmaCollection> {
    let content = std::fs::read_to_string(path)?;
    let mut collection = parse_sigma_yaml(&content)?;
    for diagnostic in &mut collection.diagnostics {
        diagnostic.path = Some(path.to_path_buf());
    }
    Ok(collection)
}

/// Parse all Sigma YAML files from a directory (recursively).
///
/// A file that cannot be read or parsed at all is recorded as a
/// [`DiagnosticKind::File`] error and the walk continues.
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
                        collection.diagnostics.extend(sub.diagnostics);
                    }
                    Err(e) => {
                        collection
                            .diagnostics
                            .push(CollectionDiagnostic::file(&path, &e));
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
fn parse_document(
    value: &Value,
    warnings: &mut Vec<CollectionDiagnostic>,
) -> Result<SigmaDocument> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| SigmaParserError::InvalidRule("Document is not a YAML mapping".into()))?;

    if mapping.contains_key(Value::String("correlation".into())) {
        correlation::parse_correlation_rule(value, warnings).map(SigmaDocument::Correlation)
    } else if mapping.contains_key(Value::String("filter".into())) {
        filter::parse_filter_rule(value, warnings).map(SigmaDocument::Filter)
    } else {
        detection::parse_detection_rule(value, warnings).map(|r| SigmaDocument::Rule(Box::new(r)))
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
    m: &yaml_serde::Mapping,
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

    let known_keys = ["category", "product", "service", "definition"];
    for key in known_keys {
        if let Some(v) = m.get(val_key(key))
            && !v.is_string()
            && !v.is_null()
        {
            return Err(SigmaParserError::InvalidRule(format!(
                "logsource {key} must be a string"
            )));
        }
    }
    if ["category", "product", "service"]
        .iter()
        .all(|key| get_str(m, key).is_none_or(str::is_empty))
    {
        return Err(SigmaParserError::InvalidRule(
            "logsource must set at least one of category, product, or service".into(),
        ));
    }

    let mut custom = HashMap::new();

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

/// Parse a `related:` list. Surfaces invalid entries through
/// `warnings` instead of silently dropping them so a typo in
/// `type: derved` (a misspelt `derived`) shows up in
/// `SigmaCollection.diagnostics` rather than being absent without trace.
pub(super) fn parse_related(
    value: Option<&Value>,
    warnings: &mut Vec<CollectionDiagnostic>,
) -> Vec<Related> {
    let Some(seq_val) = value else {
        return Vec::new();
    };
    let Some(seq) = seq_val.as_sequence() else {
        warnings.push(metadata_warning(format!(
            "'related' must be a sequence of mappings, got: {seq_val:?}"
        )));
        return Vec::new();
    };

    seq.iter()
        .enumerate()
        .filter_map(|(i, item)| {
            let Some(m) = item.as_mapping() else {
                warnings.push(metadata_warning(format!(
                    "related[{i}] is not a mapping: {item:?}"
                )));
                return None;
            };
            let id = match get_str(m, "id") {
                Some(s) => s.to_string(),
                None => {
                    warnings.push(metadata_warning(format!("related[{i}] missing 'id'")));
                    return None;
                }
            };
            let type_str = match get_str(m, "type") {
                Some(s) => s,
                None => {
                    warnings.push(metadata_warning(format!("related[{i}] missing 'type'")));
                    return None;
                }
            };
            let relation_type = match type_str.parse() {
                Ok(t) => t,
                Err(_) => {
                    warnings.push(metadata_warning(format!(
                        "related[{i}] invalid type '{type_str}' (expected one of: \
                         derived, obsolete, merged, renamed, similar)"
                    )));
                    return None;
                }
            };
            Some(Related { id, relation_type })
        })
        .collect()
}

/// Parse a string value into an enum, pushing a warning into
/// `warnings` when the value is present but does not parse. Returns
/// `None` for both "absent" and "invalid", matching the previous
/// silent `parse().ok()` contract for downstream consumers.
pub(super) fn parse_enum_with_warn<T: std::str::FromStr>(
    raw: Option<&str>,
    field: &str,
    warnings: &mut Vec<CollectionDiagnostic>,
) -> Option<T> {
    let raw = raw?;
    match raw.parse() {
        Ok(v) => Some(v),
        Err(_) => {
            warnings.push(metadata_warning(format!("invalid {field}: '{raw}'")));
            None
        }
    }
}

/// Parse the optional top-level `sigma-version` attribute into its
/// specification MAJOR version. Accepts an integer major (`3`) or a release
/// string (`"2.1.0"`); only the major is significant, since breaking spec
/// changes occur only at major bumps. A present-but-malformed value is reported
/// through `warnings` and treated as absent (resolving to the fixed floor).
pub(super) fn parse_sigma_version(
    m: &yaml_serde::Mapping,
    warnings: &mut Vec<CollectionDiagnostic>,
) -> Option<u32> {
    let value = m.get(val_key("sigma-version"))?;
    match crate::version::major_from_value(value) {
        Some(major) => Some(major),
        None => {
            warnings.push(metadata_warning(format!(
                "invalid sigma-version: {value:?} (expected a major version integer like 3, \
                 or a release string like \"2.1.0\")"
            )));
            None
        }
    }
}

fn metadata_warning(message: String) -> CollectionDiagnostic {
    CollectionDiagnostic::warning(DiagnosticKind::Metadata, message)
}

pub(super) fn val_key(s: &str) -> Value {
    Value::String(s.to_string())
}

pub(super) fn get_str<'a>(m: &'a yaml_serde::Mapping, key: &str) -> Option<&'a str> {
    m.get(val_key(key)).and_then(|v| v.as_str())
}

pub(super) fn get_str_list(m: &yaml_serde::Mapping, key: &str) -> Vec<String> {
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
/// Uses an explicit work-stack to avoid unbounded recursion from crafted input.
/// Returns `MergeTooDeep` if nesting exceeds `MAX_DEPTH`.
///
/// Reference: pySigma collection.py deep_dict_update
fn deep_merge(dest: Value, src: Value) -> crate::error::Result<Value> {
    const MAX_DEPTH: usize = 64;

    let (mut root_dest, root_src) = match (dest, src) {
        (Value::Mapping(d), Value::Mapping(s)) => (d, s),
        (_, src) => return Ok(src),
    };

    fn merge_level(
        dest: &mut yaml_serde::Mapping,
        src: yaml_serde::Mapping,
        depth: usize,
    ) -> crate::error::Result<()> {
        if depth > MAX_DEPTH {
            return Err(crate::error::SigmaParserError::MergeTooDeep(MAX_DEPTH));
        }
        for (k, v) in src {
            if let Some(existing) = dest.remove(&k) {
                match (existing, v) {
                    (Value::Mapping(mut d), Value::Mapping(s)) => {
                        merge_level(&mut d, s, depth + 1)?;
                        dest.insert(k, Value::Mapping(d));
                    }
                    (_, src_val) => {
                        dest.insert(k, src_val);
                    }
                }
            } else {
                dest.insert(k, v);
            }
        }
        Ok(())
    }

    merge_level(&mut root_dest, root_src, 0)?;
    Ok(Value::Mapping(root_dest))
}
