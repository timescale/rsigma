//! Golden tests for the Sigma YAML formatter.
//!
//! Each case is an input file and the exact canonical output in
//! `tests/fmt/`. The test also asserts that formatting the output again is a
//! no-op, so every golden is a fixed point.

use std::fs;
use std::path::Path;

use rsigma_parser::format_yaml;

fn run_golden(name: &str) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fmt");
    let input_path = base.join(format!("{name}.in.yml"));
    let expected_path = base.join(format!("{name}.out.yml"));

    let input = fs::read_to_string(&input_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", input_path.display()));
    let expected = fs::read_to_string(&expected_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", expected_path.display()));

    let outcome =
        format_yaml(&input).unwrap_or_else(|error| panic!("formatting '{name}' failed: {error}"));
    assert_eq!(
        outcome.formatted, expected,
        "\n\nGolden mismatch for '{name}':\n--- actual ---\n{}\n--- expected ---\n{expected}\n",
        outcome.formatted
    );

    let again = format_yaml(&expected)
        .unwrap_or_else(|error| panic!("formatting '{name}' output failed: {error}"));
    assert!(
        !again.changed,
        "'{name}' output is not a fixed point:\n{}",
        again.formatted
    );
    assert_eq!(again.formatted, expected);
}

#[test]
fn golden_sigmahq_sample() {
    run_golden("sigmahq_sample");
}

#[test]
fn golden_already_canonical() {
    run_golden("already_canonical");
}

#[test]
fn golden_key_order_root() {
    run_golden("key_order_root");
}

#[test]
fn golden_key_order_nested() {
    run_golden("key_order_nested");
}

#[test]
fn golden_selection_order_kept() {
    run_golden("selection_order_kept");
}

#[test]
fn golden_indent_two_space() {
    run_golden("indent_two_space");
}

#[test]
fn golden_indentless_sequence() {
    run_golden("indentless_sequence");
}

#[test]
fn golden_list_of_maps() {
    run_golden("list_of_maps");
}

#[test]
fn golden_flow_collections() {
    run_golden("flow_collections");
}

#[test]
fn golden_quoting_canonical() {
    run_golden("quoting_canonical");
}

#[test]
fn golden_double_quoted_escapes() {
    run_golden("double_quoted_escapes");
}

#[test]
fn golden_block_scalars() {
    run_golden("block_scalars");
}

#[test]
fn golden_comments_positions() {
    run_golden("comments_positions");
}

#[test]
fn golden_comments_follow_keys() {
    run_golden("comments_follow_keys");
}

#[test]
fn golden_blank_lines() {
    run_golden("blank_lines");
}

#[test]
fn golden_document_markers() {
    run_golden("document_markers");
}

#[test]
fn golden_directives() {
    run_golden("directives");
}

#[test]
fn golden_tags_anchors_aliases() {
    run_golden("tags_anchors_aliases");
}

#[test]
fn golden_anchor_redefinition() {
    run_golden("anchor_redefinition");
}

#[test]
fn golden_merge_key() {
    run_golden("merge_key");
}

#[test]
fn golden_empty_nodes() {
    run_golden("empty_nodes");
}

#[test]
fn golden_verbatim_scalars() {
    run_golden("verbatim_scalars");
}

#[test]
fn golden_trailing_whitespace_eof() {
    run_golden("trailing_whitespace_eof");
}

#[test]
fn golden_item_props_comments() {
    run_golden("item_props_comments");
}

#[test]
fn golden_unicode() {
    run_golden("unicode");
}

#[test]
fn golden_correlation_rule() {
    run_golden("correlation_rule");
}

#[test]
fn golden_correlation_with_rules_in_file() {
    run_golden("correlation_with_rules_in_file");
}

#[test]
fn golden_filter_rule() {
    run_golden("filter_rule");
}

#[test]
fn golden_action_global_repeat_reset() {
    run_golden("action_global_repeat_reset");
}

#[test]
fn golden_action_global_common_only() {
    run_golden("action_global_common_only");
}

#[test]
fn golden_action_repeat_common_only() {
    run_golden("action_repeat_common_only");
}

#[test]
fn golden_multi_doc_trailing_comment() {
    run_golden("multi_doc_trailing_comment");
}

#[test]
fn golden_comment_before_block_value() {
    run_golden("comment_before_block_value");
}

#[test]
fn golden_split_trailing_comment() {
    run_golden("split_trailing_comment");
}
