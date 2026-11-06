//! Refusal and edge-case tests for the Sigma YAML formatter.

use rsigma_parser::{FormatError, format_yaml};

const RULE: &str = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";

fn rule_with_tail(tail: &str) -> String {
    format!("{RULE}{tail}")
}

#[test]
fn invalid_yaml_reports_a_one_based_position() {
    let error = format_yaml("title: [unclosed\n").unwrap_err();
    let FormatError::Yaml { line, column, .. } = error else {
        panic!("expected Yaml, got {error:?}");
    };
    assert_eq!(line, 1);
    assert!(column >= 1);
}

#[test]
fn duplicate_key_is_yaml_error() {
    let source = "title: One\ntitle: Two\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
    assert!(matches!(format_yaml(source), Err(FormatError::Yaml { .. })));
}

#[test]
fn tab_indentation_is_yaml_error() {
    let source = "title: Test\nlogsource:\n\tcategory: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
    assert!(matches!(format_yaml(source), Err(FormatError::Yaml { .. })));
}

#[test]
fn explicit_complex_key_is_unsupported() {
    let source = rule_with_tail("custom:\n    ? [a]\n    : value\n");
    let error = format_yaml(&source).unwrap_err();
    assert!(
        matches!(error, FormatError::Unsupported { .. }),
        "expected Unsupported, got {error:?}"
    );
}

#[test]
fn comment_inside_a_flow_sequence_is_unsupported() {
    let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: [a, # note\n            b]\n    condition: selection\n";
    let error = format_yaml(source).unwrap_err();
    assert!(
        matches!(error, FormatError::Unsupported { .. }),
        "expected Unsupported, got {error:?}"
    );
}

#[test]
fn nesting_deeper_than_64_levels_is_unsupported() {
    let mut source = String::from(RULE);
    source.push_str("custom:\n");
    let mut indent = 4;
    for _ in 0..70 {
        source.push_str(&" ".repeat(indent));
        source.push_str("a:\n");
        indent += 4;
    }
    source.push_str(&" ".repeat(indent));
    source.push_str("value\n");
    let error = format_yaml(&source).unwrap_err();
    assert!(
        matches!(
            error,
            FormatError::Unsupported { ref construct, .. }
                if construct == "nesting deeper than 64 levels"
        ),
        "expected depth refusal, got {error:?}"
    );
}

#[test]
fn processing_pipeline_is_not_sigma() {
    let source = "name: pipeline\npriority: 20\ntransformations: []\n";
    let error = format_yaml(source).unwrap_err();
    assert!(
        matches!(
            error,
            FormatError::NotSigma { document: 0, .. }
        ),
        "expected NotSigma, got {error:?}"
    );
}

#[test]
fn rule_followed_by_a_pipeline_document_is_not_sigma() {
    let source = format!("{RULE}---\nname: pipeline\npriority: 20\ntransformations: []\n");
    let error = format_yaml(&source).unwrap_err();
    assert!(
        matches!(
            error,
            FormatError::NotSigma { document: 1, .. }
        ),
        "expected NotSigma in document 1, got {error:?}"
    );
}

#[test]
fn trailing_empty_document_is_not_sigma() {
    let source = format!("{RULE}---\n");
    let error = format_yaml(&source).unwrap_err();
    assert!(
        matches!(error, FormatError::NotSigma { .. }),
        "expected NotSigma, got {error:?}"
    );
}

#[test]
fn empty_file_is_not_sigma() {
    let error = format_yaml("").unwrap_err();
    assert!(
        matches!(
            error,
            FormatError::NotSigma { document: 0, ref reason }
                if reason == "the file contains no YAML documents"
        ),
        "expected empty-stream NotSigma, got {error:?}"
    );
}

#[test]
fn detection_without_condition_is_invalid_sigma() {
    let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n";
    let error = format_yaml(source).unwrap_err();
    assert!(
        matches!(error, FormatError::InvalidSigma { .. }),
        "expected InvalidSigma, got {error:?}"
    );
}

#[test]
fn crlf_input_formats_to_lf() {
    let source = "title: Test\r\nlogsource:\r\n    category: test\r\ndetection:\r\n    selection:\r\n        Field: value\r\n    condition: selection\r\n";
    let outcome = format_yaml(source).unwrap();
    assert!(outcome.changed);
    assert_eq!(outcome.formatted, RULE);
    assert!(!outcome.formatted.contains('\r'));
}

#[test]
fn bom_is_dropped() {
    let source = format!("\u{FEFF}{RULE}");
    let outcome = format_yaml(&source).unwrap();
    assert!(outcome.changed);
    assert_eq!(outcome.formatted, RULE);
    assert!(!outcome.formatted.starts_with('\u{FEFF}'));
}
