//! Canonical text output and the output span map.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::fmt::context::{DocKind, key_ctx, map_ctx, scalar_ctx};
use crate::fmt::cst::{
    Comment, Decoded, Entry, Item, Model, NodeId, NodeKind, PathSeg, PreludeLine, Prop, key_string,
};
use crate::fmt::order::Plan;
use crate::style::{Encoded, STEP, encode, encode_key};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpanInfo {
    pub start: usize,
    pub end: usize,
    pub child_col: usize,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Render {
    pub text: String,
    pub spans: BTreeMap<(usize, Vec<PathSeg>), SpanInfo>,
}

pub(crate) fn render(model: &Model, kinds: &[DocKind], plan: &Plan) -> Render {
    let mut render = Render::default();
    for (index, doc) in model.docs.iter().enumerate() {
        let kind = kinds.get(index).copied().unwrap_or(DocKind::Common);
        let has_directives = !doc.prelude.is_empty();
        if index > 0 || has_directives {
            if has_directives && index > 0 {
                render.text.push_str("...\n");
            }
            for line in &doc.prelude {
                match line {
                    PreludeLine::Directive(text) => {
                        render.text.push_str(text);
                        render.text.push('\n');
                    }
                    PreludeLine::Comment(comment) => {
                        render.text.push_str(&comment.text);
                        render.text.push('\n');
                    }
                }
            }
            render.text.push_str("---");
            if let Some(comment) = &doc.start_comment {
                render.text.push(' ');
                render.text.push_str(&comment.text);
            }
            render.text.push('\n');
        } else if let Some(comment) = &doc.start_comment {
            render.text.push_str(&comment.text);
            render.text.push('\n');
        }
        for comment in &doc.header {
            render.text.push_str(&comment.text);
            render.text.push('\n');
        }
        render_map_entries(
            &mut render,
            model,
            plan,
            kind,
            index,
            doc.root,
            &[],
            "",
            false,
        );
    }
    if !render.text.ends_with('\n') {
        render.text.push('\n');
    }
    render
}

#[allow(clippy::too_many_arguments)]
fn render_map_entries(
    render: &mut Render,
    model: &Model,
    plan: &Plan,
    kind: DocKind,
    doc: usize,
    map_id: NodeId,
    path: &[PathSeg],
    indent: &str,
    skip_first_leading: bool,
) {
    let NodeKind::Map { entries, .. } = &model.nodes[map_id as usize].kind else {
        return;
    };
    let start = render.text.len();
    let order = plan.order(map_id, entries.len());
    let ctx = map_ctx(kind, path);
    let key_ctx = key_ctx(ctx);
    for (position, index) in order.iter().enumerate() {
        let entry = &entries[*index];
        let mut entry_path = path.to_vec();
        entry_path.push(PathSeg::Key(key_string(model, entry.key)));
        render_entry(
            render,
            model,
            plan,
            kind,
            doc,
            entry,
            &entry_path,
            indent,
            key_ctx,
            skip_first_leading && position == 0,
        );
    }
    if let NodeKind::Map { dangling, .. } = &model.nodes[map_id as usize].kind {
        for comment in dangling {
            write_comment(render, indent, comment);
        }
    }
    render.spans.insert(
        (doc, path.to_vec()),
        SpanInfo {
            start,
            end: render.text.len(),
            child_col: indent.len(),
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn render_entry(
    render: &mut Render,
    model: &Model,
    plan: &Plan,
    kind: DocKind,
    doc: usize,
    entry: &Entry,
    entry_path: &[PathSeg],
    indent: &str,
    key_ctx: crate::style::KeyCtx,
    skip_leading: bool,
) {
    if !skip_leading {
        for comment in &entry.leading {
            write_comment(render, indent, comment);
        }
    }
    let key = key_text(model, entry.key, key_ctx);
    let prefix = format!("{indent}{key}:");
    render_value(
        render,
        model,
        plan,
        kind,
        doc,
        entry.value,
        entry_path,
        &prefix,
        indent,
        entry.trailing.as_ref(),
    );
}

#[allow(clippy::too_many_arguments)]
fn render_value(
    render: &mut Render,
    model: &Model,
    plan: &Plan,
    kind: DocKind,
    doc: usize,
    value: NodeId,
    value_path: &[PathSeg],
    prefix: &str,
    indent: &str,
    trailing: Option<&Comment>,
) {
    let node = &model.nodes[value as usize];
    let props = props_text(&node.props);
    match &node.kind {
        NodeKind::Empty => {
            let mut line = prefix.to_string();
            if !props.is_empty() {
                line.push(' ');
                line.push_str(props.trim_end());
            }
            if let Some(comment) = trailing {
                line.push(' ');
                line.push_str(&comment.text);
            }
            render.text.push_str(&line);
            render.text.push('\n');
        }
        NodeKind::Alias(name) => {
            let mut line = prefix.to_string();
            line.push(' ');
            line.push_str(&props);
            line.push('*');
            line.push_str(name);
            if let Some(comment) = trailing {
                line.push(' ');
                line.push_str(&comment.text);
            }
            render.text.push_str(&line);
            render.text.push('\n');
        }
        NodeKind::Scalar {
            text,
            decoded,
            block,
        } => match decoded {
            Decoded::Str(s) => {
                let ctx = scalar_ctx(value_path);
                let encoded = encode(s, ctx);
                let first = match &encoded {
                    Encoded::Plain(token) | Encoded::Single(token) | Encoded::Double(token) => {
                        token.clone()
                    }
                    Encoded::Literal { header, .. } => header.clone(),
                };
                let mut line = prefix.to_string();
                line.push(' ');
                line.push_str(&props);
                line.push_str(&first);
                if let Some(comment) = trailing {
                    line.push(' ');
                    line.push_str(&comment.text);
                }
                render.text.push_str(&line);
                render.text.push('\n');
                if let Encoded::Literal { lines, .. } = encoded {
                    for line in lines {
                        if line.is_empty() {
                            render.text.push('\n');
                        } else {
                            let _ = writeln!(render.text, "{indent}{STEP}{line}");
                        }
                    }
                }
            }
            Decoded::Verbatim => {
                if *block {
                    render_verbatim_block(render, text, &props, prefix, indent, trailing);
                } else {
                    let mut line = prefix.to_string();
                    line.push(' ');
                    line.push_str(&props);
                    line.push_str(text);
                    if let Some(comment) = trailing {
                        line.push(' ');
                        line.push_str(&comment.text);
                    }
                    render.text.push_str(&line);
                    render.text.push('\n');
                }
            }
        },
        NodeKind::Map { entries, .. } => {
            let mut line = prefix.to_string();
            if entries.is_empty() {
                line.push(' ');
                line.push_str(&props);
                line.push_str("{}");
            } else if !props.is_empty() {
                line.push(' ');
                line.push_str(props.trim_end());
            }
            if let Some(comment) = trailing {
                line.push(' ');
                line.push_str(&comment.text);
            }
            render.text.push_str(&line);
            render.text.push('\n');
            if !entries.is_empty() {
                let deeper = format!("{indent}{STEP}");
                render_map_entries(
                    render, model, plan, kind, doc, value, value_path, &deeper, false,
                );
            }
        }
        NodeKind::Seq { items, .. } => {
            let mut line = prefix.to_string();
            if items.is_empty() {
                line.push(' ');
                line.push_str(&props);
                line.push_str("[]");
            } else if !props.is_empty() {
                line.push(' ');
                line.push_str(props.trim_end());
            }
            if let Some(comment) = trailing {
                line.push(' ');
                line.push_str(&comment.text);
            }
            render.text.push_str(&line);
            render.text.push('\n');
            if !items.is_empty() {
                let deeper = format!("{indent}{STEP}");
                render_sequence(render, model, plan, kind, doc, value, value_path, &deeper);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_sequence(
    render: &mut Render,
    model: &Model,
    plan: &Plan,
    kind: DocKind,
    doc: usize,
    seq_id: NodeId,
    path: &[PathSeg],
    indent: &str,
) {
    let NodeKind::Seq { items, .. } = &model.nodes[seq_id as usize].kind else {
        return;
    };
    for (index, item) in items.iter().enumerate() {
        let mut item_path = path.to_vec();
        item_path.push(PathSeg::Index(index));
        render_item(render, model, plan, kind, doc, item, &item_path, indent);
    }
    if let NodeKind::Seq { dangling, .. } = &model.nodes[seq_id as usize].kind {
        for comment in dangling {
            write_comment(render, indent, comment);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_item(
    render: &mut Render,
    model: &Model,
    plan: &Plan,
    kind: DocKind,
    doc: usize,
    item: &Item,
    item_path: &[PathSeg],
    indent: &str,
) {
    let node = &model.nodes[item.value as usize];
    match &node.kind {
        NodeKind::Map { entries, .. } if !entries.is_empty() => {
            if node.props.is_empty() && item.trailing.is_none() {
                render_compact_mapping_item(
                    render, model, plan, kind, doc, item, item_path, indent,
                );
            } else {
                for comment in &item.leading {
                    write_comment(render, indent, comment);
                }
                let order = plan.order(item.value, entries.len());
                for comment in &entries[order[0]].leading {
                    write_comment(render, indent, comment);
                }
                let mut line = format!("{indent}-");
                let props = props_text(&node.props);
                if !props.is_empty() {
                    line.push(' ');
                    line.push_str(props.trim_end());
                }
                if let Some(comment) = &item.trailing {
                    line.push(' ');
                    line.push_str(&comment.text);
                }
                render.text.push_str(&line);
                render.text.push('\n');
                let deeper = format!("{indent}  ");
                render_map_entries(
                    render, model, plan, kind, doc, item.value, item_path, &deeper, true,
                );
            }
        }
        NodeKind::Seq { items, .. } if !items.is_empty() => {
            for comment in &item.leading {
                write_comment(render, indent, comment);
            }
            let mut line = format!("{indent}-");
            let props = props_text(&node.props);
            if !props.is_empty() {
                line.push(' ');
                line.push_str(props.trim_end());
            }
            if let Some(comment) = &item.trailing {
                line.push(' ');
                line.push_str(&comment.text);
            }
            render.text.push_str(&line);
            render.text.push('\n');
            let deeper = format!("{indent}{STEP}");
            render_sequence(
                render, model, plan, kind, doc, item.value, item_path, &deeper,
            );
        }
        _ => {
            for comment in &item.leading {
                write_comment(render, indent, comment);
            }
            let dash = format!("{indent}-");
            render_value(
                render,
                model,
                plan,
                kind,
                doc,
                item.value,
                item_path,
                &dash,
                indent,
                item.trailing.as_ref(),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_compact_mapping_item(
    render: &mut Render,
    model: &Model,
    plan: &Plan,
    kind: DocKind,
    doc: usize,
    item: &Item,
    item_path: &[PathSeg],
    indent: &str,
) {
    let NodeKind::Map { entries, .. } = &model.nodes[item.value as usize].kind else {
        return;
    };
    let start = render.text.len();
    let order = plan.order(item.value, entries.len());
    let ctx = map_ctx(kind, item_path);
    let key_ctx = key_ctx(ctx);
    let first_index = order[0];
    let first = &entries[first_index];
    for comment in &item.leading {
        write_comment(render, indent, comment);
    }
    for comment in &first.leading {
        write_comment(render, indent, comment);
    }
    let cont = format!("{indent}  ");
    let insertion = render.text.len();
    let mut scratch = Render {
        text: String::new(),
        spans: BTreeMap::new(),
    };
    let mut first_path = item_path.to_vec();
    first_path.push(PathSeg::Key(key_string(model, first.key)));
    render_entry(
        &mut scratch,
        model,
        plan,
        kind,
        doc,
        first,
        &first_path,
        &cont,
        key_ctx,
        true,
    );
    let first_entry = scratch.text;
    for (key, span) in scratch.spans {
        render.spans.insert(
            key,
            SpanInfo {
                start: span.start + insertion,
                end: span.end + insertion,
                child_col: span.child_col,
            },
        );
    }
    let mut lines = first_entry.split_inclusive('\n');
    if let Some(line) = lines.next() {
        let trimmed = line.strip_prefix(&cont).unwrap_or(line);
        let _ = write!(render.text, "{indent}- {trimmed}");
    }
    for line in lines {
        render.text.push_str(line);
    }
    for (position, index) in order.iter().enumerate() {
        if position == 0 {
            continue;
        }
        let entry = &entries[*index];
        let mut entry_path = item_path.to_vec();
        entry_path.push(PathSeg::Key(key_string(model, entry.key)));
        render_entry(
            render,
            model,
            plan,
            kind,
            doc,
            entry,
            &entry_path,
            &cont,
            key_ctx,
            false,
        );
    }
    if let NodeKind::Map { dangling, .. } = &model.nodes[item.value as usize].kind {
        for comment in dangling {
            write_comment(render, &cont, comment);
        }
    }
    render.spans.insert(
        (doc, item_path.to_vec()),
        SpanInfo {
            start,
            end: render.text.len(),
            child_col: indent.len() + 2,
        },
    );
}

fn render_verbatim_block(
    render: &mut Render,
    text: &str,
    props: &str,
    prefix: &str,
    indent: &str,
    trailing: Option<&Comment>,
) {
    let stripped = text.strip_suffix('\n').unwrap_or(text);
    let mut lines = stripped.split('\n');
    let header = lines.next().unwrap_or_default().trim_end();
    let header = rewrite_indent_indicator(header);
    let content: Vec<&str> = lines.collect();
    let min_indent = content
        .iter()
        .filter(|line| !line.is_empty())
        .map(|line| line.len() - line.trim_start_matches(' ').len())
        .min()
        .unwrap_or(0);
    let target = indent.len() + STEP.len();
    let mut line = prefix.to_string();
    line.push(' ');
    line.push_str(props);
    line.push_str(&header);
    if let Some(comment) = trailing {
        line.push(' ');
        line.push_str(&comment.text);
    }
    render.text.push_str(&line);
    render.text.push('\n');
    for content_line in content {
        if content_line.is_empty() {
            render.text.push('\n');
            continue;
        }
        let current = content_line.len() - content_line.trim_start_matches(' ').len();
        let adjusted = if current >= min_indent {
            target + current - min_indent
        } else {
            target.saturating_sub(min_indent - current)
        };
        for _ in 0..adjusted {
            render.text.push(' ');
        }
        render.text.push_str(content_line.trim_start_matches(' '));
        render.text.push('\n');
    }
}

fn rewrite_indent_indicator(header: &str) -> String {
    let mut result = String::with_capacity(header.len());
    let mut replaced = false;
    for c in header.chars() {
        if !replaced && c.is_ascii_digit() && c != '0' {
            result.push('4');
            replaced = true;
        } else {
            result.push(c);
        }
    }
    result
}

fn key_text(model: &Model, key: NodeId, ctx: crate::style::KeyCtx) -> String {
    let node = &model.nodes[key as usize];
    let mut text = props_text(&node.props);
    match &node.kind {
        NodeKind::Scalar {
            decoded: Decoded::Str(s),
            text: raw,
            ..
        } => {
            if s == "<<" && raw == "<<" {
                text.push_str("<<");
            } else {
                text.push_str(&encode_key(s, ctx));
            }
        }
        NodeKind::Scalar { text: raw, .. } => text.push_str(raw),
        NodeKind::Alias(name) => {
            text.push('*');
            text.push_str(name);
            text.push(' ');
        }
        _ => {}
    }
    text
}

fn props_text(props: &[Prop]) -> String {
    let mut text = String::new();
    for prop in props {
        match prop {
            Prop::Anchor(name) => {
                text.push('&');
                text.push_str(name);
            }
            Prop::Tag(tag) => text.push_str(tag),
        }
        text.push(' ');
    }
    text
}

fn write_comment(render: &mut Render, indent: &str, comment: &Comment) {
    render.text.push_str(indent);
    render.text.push_str(&comment.text);
    render.text.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fmt::{classify, comments, cst};

    fn formatted(source: &str) -> String {
        let mut parser = tree_sitter::Parser::new();
        let language: tree_sitter::Language = tree_sitter_yaml::LANGUAGE.into();
        parser.set_language(&language).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let values: Vec<yaml_serde::Value> = yaml_serde::Deserializer::from_str(source)
            .map(|doc| yaml_serde::Value::deserialize(doc).unwrap())
            .collect();
        let kinds = classify::classify(&values).unwrap();
        let mut model = cst::build(source, &tree, &values).unwrap();
        comments::attach(&mut model, source).unwrap();
        let plan = crate::fmt::order::plan(&model, &kinds);
        render(&model, &kinds, &plan).text
    }

    use serde::Deserialize;

    #[test]
    fn renders_canonical_rule() {
        let source = "title: Test\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";
        let expected = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        assert_eq!(formatted(source), expected);
    }

    #[test]
    fn renders_compact_mapping_items() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        - Field: value\n          Other: two\n    condition: selection\n";
        let expected = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        - Field: value\n          Other: two\n    condition: selection\n";
        assert_eq!(formatted(source), expected);
    }

    #[test]
    fn renders_literal_blocks_under_keys_and_dashes() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: |-\n            one\n            two\n    condition: selection\n";
        let expected = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: |-\n            one\n            two\n    condition: selection\n";
        assert_eq!(formatted(source), expected);
    }

    #[test]
    fn renders_empty_collections() {
        let source = "title: Test\nlogsource: {}\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let expected = "title: Test\nlogsource: {}\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        assert_eq!(formatted(source), expected);
    }
}
