//! Golden tests for range formatting: the exact spliced text for each case.

use rsigma_parser::{FormatError, format_yaml_range};

fn apply(source: &str, start: usize, end: usize) -> Result<Option<String>, FormatError> {
    match format_yaml_range(source, start, end)? {
        Some(edit) => {
            let mut out = String::new();
            out.push_str(&source[..edit.start]);
            out.push_str(&edit.replacement);
            out.push_str(&source[edit.end..]);
            Ok(Some(out))
        }
        None => Ok(None),
    }
}

fn range_of(source: &str, needle: &str) -> (usize, usize) {
    let start = source.find(needle).expect("needle");
    (start, start + needle.len())
}

#[test]
fn badly_indented_detection_mapping_keeps_outer_indentation() {
    let source = "title: Test\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";
    let start = source.find("selection:").unwrap();
    let end = source.find("condition: selection").unwrap() + "condition: selection".len();
    let output = apply(source, start, end).unwrap().expect("edit");
    assert_eq!(
        output,
        "title: Test\nlogsource:\n  category: test\ndetection:\n  selection:\n      Field: value\n  condition: selection\n"
    );
}

#[test]
fn flow_list_in_tags_becomes_block() {
    let source = "title: Test\ntags: [attack.execution, attack.discovery]\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";
    let (start, end) = range_of(source, "attack.execution");
    let output = apply(source, start, end).unwrap().expect("edit");
    assert_eq!(
        output,
        "title: Test\ntags:\n    - attack.execution\n    - attack.discovery\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n"
    );
}

#[test]
fn compact_list_item_mapping_is_reindented() {
    let source = "title: Test\nrelated:\n  - id: 00000000-0000-0000-0000-000000000001\n    extra:\n       nested: value\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";
    let (start, end) = range_of(source, "id: 00000000-0000-0000-0000-000000000001");
    let output = apply(source, start, end).unwrap().expect("edit");
    assert_eq!(
        output,
        "title: Test\nrelated:\n  - id: 00000000-0000-0000-0000-000000000001\n    extra:\n        nested: value\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n"
    );
}

#[test]
fn canonical_range_is_a_no_op() {
    let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
    let (start, end) = range_of(source, "selection:");
    assert_eq!(apply(source, start, end).unwrap(), None);
}
