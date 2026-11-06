//! Document kinds for the formatter.
//!
//! A Sigma collection can mix detection rules, correlations, filters, and
//! `action: global`/`repeat`/`reset` fragments. Classification follows the
//! parser's collection rules so the formatter can choose the right key order
//! for every document.

use std::collections::BTreeSet;

use crate::fmt::FormatError;
use crate::fmt::context::DocKind;

/// Classify every document in the stream.
pub(crate) fn classify(values: &[yaml_serde::Value]) -> Result<Vec<DocKind>, FormatError> {
    if values.is_empty() {
        return Err(FormatError::NotSigma {
            document: 0,
            reason: "the file contains no YAML documents".to_string(),
        });
    }
    let mut kinds = Vec::with_capacity(values.len());
    let mut global_keys: Option<BTreeSet<String>> = None;
    let mut previous_keys: Option<BTreeSet<String>> = None;
    for (index, value) in values.iter().enumerate() {
        let value = unwrap_tagged(value);
        let Some(mapping) = value.as_mapping() else {
            let reason = if matches!(value, yaml_serde::Value::Null) {
                "the document is empty"
            } else {
                "the document is not a mapping"
            };
            return Err(not_sigma(index, reason));
        };
        let keys = string_keys(mapping);
        let action = mapping.get(yaml_serde::Value::String("action".to_string()));
        match action.and_then(|value| value.as_str()) {
            Some("global") => {
                let kind = kind_of(&keys).unwrap_or(DocKind::Common);
                global_keys = Some(without_action(&keys));
                kinds.push(kind);
            }
            Some("reset") => {
                global_keys = None;
                kinds.push(DocKind::Reset);
            }
            Some("repeat") => {
                let mut merged = previous_keys.clone().unwrap_or_default();
                merged.extend(keys.iter().cloned());
                merged.extend(global_keys.clone().unwrap_or_default());
                let kind = kind_of(&merged).unwrap_or(DocKind::Common);
                previous_keys = Some(merged);
                kinds.push(kind);
            }
            Some(_) => {
                let Some(kind) = kind_of(&keys) else {
                    return Err(not_sigma(index, "`action` is not global, reset, or repeat"));
                };
                kinds.push(kind);
            }
            None => {
                let mut effective = keys.clone();
                effective.extend(global_keys.clone().unwrap_or_default());
                let Some(kind) = kind_of(&effective) else {
                    return Err(not_sigma(
                        index,
                        "no `detection`, `logsource`, `correlation`, or `filter` key",
                    ));
                };
                previous_keys = Some(effective);
                kinds.push(kind);
            }
        }
    }
    Ok(kinds)
}

fn kind_of(keys: &BTreeSet<String>) -> Option<DocKind> {
    if keys.contains("correlation") {
        Some(DocKind::Correlation)
    } else if keys.contains("filter") {
        Some(DocKind::Filter)
    } else if keys.contains("detection") || keys.contains("logsource") {
        Some(DocKind::Detection)
    } else {
        None
    }
}

fn string_keys(mapping: &yaml_serde::Mapping) -> BTreeSet<String> {
    mapping
        .keys()
        .filter_map(|key| key.as_str())
        .map(str::to_string)
        .collect()
}

fn without_action(keys: &BTreeSet<String>) -> BTreeSet<String> {
    keys.iter()
        .filter(|key| key.as_str() != "action")
        .cloned()
        .collect()
}

fn not_sigma(document: usize, reason: &str) -> FormatError {
    FormatError::NotSigma {
        document,
        reason: reason.to_string(),
    }
}

fn unwrap_tagged(value: &yaml_serde::Value) -> &yaml_serde::Value {
    match value {
        yaml_serde::Value::Tagged(tagged) => unwrap_tagged(&tagged.value),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn values(source: &str) -> Vec<yaml_serde::Value> {
        yaml_serde::Deserializer::from_str(source)
            .map(|doc| yaml_serde::Value::deserialize(doc).unwrap())
            .collect()
    }

    const RULE: &str = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
    const CORRELATION: &str =
        "title: Correlation\ncorrelation:\n    type: event_count\n    rules:\n        - Test\n";
    const FILTER: &str = "title: Filter\nlogsource:\n    category: test\nfilter:\n    rules: []\n";

    #[test]
    fn detection_is_accepted() {
        assert_eq!(classify(&values(RULE)).unwrap(), vec![DocKind::Detection]);
    }

    #[test]
    fn correlation_and_filter_are_accepted() {
        assert_eq!(
            classify(&values(CORRELATION)).unwrap(),
            vec![DocKind::Correlation]
        );
        assert_eq!(classify(&values(FILTER)).unwrap(), vec![DocKind::Filter]);
    }

    #[test]
    fn empty_stream_is_refused() {
        let error = classify(&[]).unwrap_err();
        assert!(matches!(
            error,
            FormatError::NotSigma { document: 0, ref reason }
                if reason == "the file contains no YAML documents"
        ));
    }

    #[test]
    fn empty_document_is_refused() {
        let error = classify(&values("---\n")).unwrap_err();
        assert!(matches!(
            error,
            FormatError::NotSigma { document: 0, ref reason }
                if reason == "the document is empty"
        ));
    }

    #[test]
    fn non_mapping_is_refused() {
        let error = classify(&values("- a\n- b\n")).unwrap_err();
        assert!(matches!(
            error,
            FormatError::NotSigma { document: 0, ref reason }
                if reason == "the document is not a mapping"
        ));
    }

    #[test]
    fn document_without_sigma_keys_is_refused() {
        let error = classify(&values("name: pipeline\npriority: 20\n")).unwrap_err();
        assert!(matches!(
            error,
            FormatError::NotSigma { document: 0, ref reason }
                if reason == "no `detection`, `logsource`, `correlation`, or `filter` key"
        ));
    }

    #[test]
    fn global_action_classifies_by_its_keys() {
        let source =
            format!("action: global\ntitle: Global\nlogsource:\n    category: test\n---\n{RULE}");
        assert_eq!(
            classify(&values(&source)).unwrap(),
            vec![DocKind::Detection, DocKind::Detection]
        );
    }

    #[test]
    fn global_action_with_only_common_keys_is_common() {
        let source = "action: global\ntitle: Global\nlevel: low\n";
        assert_eq!(classify(&values(source)).unwrap(), vec![DocKind::Common]);
    }

    #[test]
    fn reset_action_is_reset() {
        let source = "action: reset\ntitle: Reset\n";
        assert_eq!(classify(&values(source)).unwrap(), vec![DocKind::Reset]);
    }

    #[test]
    fn repeat_inherits_the_previous_kind() {
        let source = format!("{RULE}---\naction: repeat\ntitle: Repeat\nlevel: high\n");
        assert_eq!(
            classify(&values(&source)).unwrap(),
            vec![DocKind::Detection, DocKind::Detection]
        );
    }

    #[test]
    fn repeat_without_previous_is_common() {
        let source = "action: repeat\ntitle: Repeat\nlevel: high\n";
        assert_eq!(classify(&values(source)).unwrap(), vec![DocKind::Common]);
    }

    #[test]
    fn global_keys_are_inherited_by_later_documents() {
        let source = "action: global\ntitle: Global\nlevel: low\n---\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        assert_eq!(
            classify(&values(source)).unwrap(),
            vec![DocKind::Common, DocKind::Detection]
        );
    }

    #[test]
    fn bad_action_uses_the_document_kind() {
        let source = format!("action: sideways\n{RULE}");
        assert_eq!(
            classify(&values(&source)).unwrap(),
            vec![DocKind::Detection]
        );
    }

    #[test]
    fn bad_action_without_a_kind_is_refused() {
        let error = classify(&values("action: sideways\ntitle: Test\n")).unwrap_err();
        assert!(matches!(
            error,
            FormatError::NotSigma { document: 0, ref reason }
                if reason == "`action` is not global, reset, or repeat"
        ));
    }

    #[test]
    fn later_document_index_is_reported() {
        let source = format!("{RULE}---\nname: pipeline\n");
        let error = classify(&values(&source)).unwrap_err();
        assert!(matches!(error, FormatError::NotSigma { document: 1, .. }));
    }
}
