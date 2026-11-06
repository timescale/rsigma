//! Document kinds.
//!
//! Only plain detection rules are recognised here; documents with `action`,
//! `correlation`, or `filter` are not Sigma for the formatter.

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
    for (index, value) in values.iter().enumerate() {
        kinds.push(classify_one(index, value)?);
    }
    Ok(kinds)
}

fn classify_one(document: usize, value: &yaml_serde::Value) -> Result<DocKind, FormatError> {
    let value = unwrap_tagged(value);
    let Some(mapping) = value.as_mapping() else {
        return Err(not_sigma(document, "the document is not a YAML mapping"));
    };
    if mapping.contains_key("action") {
        return Err(not_sigma(document, "the document is a collection action"));
    }
    if mapping.contains_key("correlation") {
        return Err(not_sigma(document, "the document is a correlation rule"));
    }
    if mapping.contains_key("filter") {
        return Err(not_sigma(document, "the document is a filter rule"));
    }
    if mapping.contains_key("detection") || mapping.contains_key("logsource") {
        return Ok(DocKind::Detection);
    }
    Err(not_sigma(
        document,
        "the document has neither `logsource` nor `detection`",
    ))
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

    #[test]
    fn detection_is_accepted() {
        assert_eq!(classify(&values(RULE)).unwrap(), vec![DocKind::Detection]);
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
    fn non_mapping_is_refused() {
        let error = classify(&values("- a\n- b\n")).unwrap_err();
        assert!(matches!(
            error,
            FormatError::NotSigma { document: 0, .. }
        ));
    }

    #[test]
    fn action_correlation_filter_and_pipeline_are_refused() {
        for source in [
            "action: global\ntitle: Test\n",
            "title: Test\ncorrelation:\n    type: event_count\n",
            "title: Test\nfilter:\n    rules: []\n",
            "name: pipeline\npriority: 20\ntransformations: []\n",
        ] {
            let error = classify(&values(source)).unwrap_err();
            assert!(matches!(error, FormatError::NotSigma { document: 0, .. }));
        }
    }

    #[test]
    fn later_document_index_is_reported() {
        let source = format!("{RULE}---\nname: pipeline\n");
        let error = classify(&values(&source)).unwrap_err();
        assert!(matches!(
            error,
            FormatError::NotSigma { document: 1, .. }
        ));
    }
}
