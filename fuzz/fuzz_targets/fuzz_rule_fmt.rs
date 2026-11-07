#![no_main]

//! Fuzz the Sigma formatter on whole files and byte ranges.
//!
//! A successful result must format to itself again, deserialize to the same
//! YAML values, keep the same comments, anchors, and aliases, and stay under
//! the size cap. A range edit must sit on char boundaries and splice into a
//! file with the same values and syntax.

use libfuzzer_sys::fuzz_target;
use rsigma_parser::{format_yaml, format_yaml_range};
use serde::Deserialize;
use tree_sitter::Node;

fn values(text: &str) -> Option<Vec<yaml_serde::Value>> {
    let mut values = Vec::new();
    for document in yaml_serde::Deserializer::from_str(text) {
        values.push(yaml_serde::Value::deserialize(document).ok()?);
    }
    Some(values)
}

fn syntax(text: &str) -> Option<(Vec<String>, Vec<String>, Vec<String>)> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_yaml::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(text, None)?;
    if tree.root_node().has_error() {
        return None;
    }

    let mut comments = Vec::new();
    let mut anchors = Vec::new();
    let mut aliases = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "comment" => comments.push(node_text(node, text).trim_end().to_string()),
            "anchor_name" => anchors.push(node_text(node, text).to_string()),
            "alias_name" => aliases.push(node_text(node, text).to_string()),
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    comments.sort();
    anchors.sort();
    aliases.sort();
    Some((comments, anchors, aliases))
}

fn node_text<'a>(node: Node<'_>, text: &'a str) -> &'a str {
    &text[node.byte_range()]
}

fn range_of(data: &[u8], text: &str) -> (usize, usize) {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let limit = text.len() + 1;
    let mut start = (hash % limit as u64) as usize;
    let mut end = ((hash >> 32) % limit as u64) as usize;
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (start.min(end), start.max(end))
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let plain = text.strip_prefix('\u{feff}').unwrap_or(text);
    if let Ok(outcome) = format_yaml(text) {
        let out = &outcome.formatted;
        assert!(out.len() <= 16 * text.len() + 4096);
        let again = format_yaml(out).expect("formatted output must format again");
        assert!(!again.changed, "formatting is not idempotent");
        assert_eq!(values(plain), values(out));
        assert_eq!(syntax(plain), syntax(out));
    }
    let (start, end) = range_of(data, text);
    if let Ok(Some(edit)) = format_yaml_range(text, start, end) {
        assert!(edit.start <= edit.end && edit.end <= text.len());
        assert!(text.is_char_boundary(edit.start) && text.is_char_boundary(edit.end));
        let spliced = format!(
            "{}{}{}",
            &text[..edit.start],
            edit.replacement,
            &text[edit.end..]
        );
        assert_eq!(
            values(plain),
            values(spliced.strip_prefix('\u{feff}').unwrap_or(&spliced))
        );
        assert_eq!(syntax(plain), syntax(&spliced));
    }
});
