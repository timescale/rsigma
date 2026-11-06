//! Comment attachment and normalization.

use tree_sitter::Point;

use crate::fmt::cst::{
    Comment, Model, NodeId, NodeKind, PathSeg, PreludeLine, RawComment, child_column, key_string,
};

#[derive(Debug, Clone)]
struct Owner {
    doc: usize,
    kind: OwnerKind,
    start: Point,
    start_byte: usize,
    end: Point,
    end_byte: usize,
    value: NodeId,
    ancestors: Vec<NodeId>,
}

#[derive(Debug, Clone, Copy)]
enum OwnerKind {
    Entry { map: NodeId, index: usize },
    Item { seq: NodeId, index: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Scalar,
    Alias,
    Empty,
    Flow,
    Block,
}

pub(crate) fn attach(model: &mut Model, source: &str) -> Result<(), crate::fmt::FormatError> {
    let owners = collect_owners(model);
    let doc_info: Vec<DocInfo> = model
        .docs
        .iter()
        .map(|doc| DocInfo {
            root_start: model.nodes[doc.root as usize].span.start,
            root_end: model.nodes[doc.root as usize].span.end,
            start_token_row: doc.start_token.map(|(_, row)| row),
            start_token_byte: doc.start_token.map(|(byte, _)| byte),
            first_directive: doc.directive_bytes.first().copied(),
        })
        .collect();
    let mut prelude_comments: Vec<Vec<(usize, Comment)>> = vec![Vec::new(); model.docs.len()];
    let raw_comments: Vec<RawComment> = model.raw_comments.clone();
    for comment in raw_comments {
        let Some(doc) = assign_document(&comment, &doc_info) else {
            continue;
        };
        if doc_info[doc].start_token_row == Some(comment.row) {
            model.docs[doc].start_comment = Some(comment);
            continue;
        }
        if is_prelude_comment(&comment, doc, &doc_info) {
            prelude_comments[doc].push((comment.byte, comment));
            continue;
        }
        if has_non_whitespace_before(source, comment.byte, comment.row) {
            attach_trailing(model, &owners, doc, comment);
        } else {
            attach_own_line(model, &owners, doc, comment)?;
        }
    }
    for (doc, comments) in prelude_comments.into_iter().enumerate() {
        if comments.is_empty() {
            continue;
        }
        let mut lines: Vec<(usize, PreludeLine)> = model.docs[doc]
            .prelude
            .iter()
            .zip(model.docs[doc].directive_bytes.iter())
            .map(|(line, byte)| (*byte, line.clone()))
            .collect();
        for (byte, comment) in comments {
            lines.push((byte, PreludeLine::Comment(comment)));
        }
        lines.sort_by_key(|(byte, _)| *byte);
        model.docs[doc].directive_bytes = lines
            .iter()
            .filter(|(_, line)| matches!(line, PreludeLine::Directive(_)))
            .map(|(byte, _)| *byte)
            .collect();
        model.docs[doc].prelude = lines.into_iter().map(|(_, line)| line).collect();
    }
    split_header(model);
    hoist_item_leading(model);
    Ok(())
}

struct DocInfo {
    root_start: usize,
    root_end: usize,
    start_token_row: Option<usize>,
    start_token_byte: Option<usize>,
    first_directive: Option<usize>,
}

fn assign_document(comment: &Comment, docs: &[DocInfo]) -> Option<usize> {
    if docs.is_empty() {
        return None;
    }
    // Tree-sitter includes trailing comments in a document's root span. A
    // comment that sits inside a document belongs to it even though the byte
    // offset is past the previous document's end.
    if let Some(index) = docs
        .iter()
        .position(|doc| doc.root_start <= comment.byte && comment.byte < doc.root_end)
    {
        return Some(index);
    }
    let previous = docs
        .iter()
        .enumerate()
        .filter(|(_, doc)| doc.root_end <= comment.byte)
        .max_by_key(|(_, doc)| doc.root_end)
        .map(|(index, _)| index);
    let Some(previous) = previous else {
        return Some(0);
    };
    if let Some(next) = docs.get(previous + 1) {
        let boundary = match (next.first_directive, next.start_token_byte) {
            (Some(directive), Some(start)) => Some(directive.min(start)),
            (directive, start) => directive.or(start),
        };
        if boundary.is_some_and(|byte| byte < comment.byte) && comment.byte < next.root_start {
            return Some(previous + 1);
        }
    }
    Some(previous)
}

fn is_prelude_comment(comment: &Comment, doc: usize, docs: &[DocInfo]) -> bool {
    docs[doc]
        .first_directive
        .is_some_and(|byte| byte < comment.byte && comment.byte < docs[doc].root_start)
}

fn has_non_whitespace_before(source: &str, byte: usize, _row: usize) -> bool {
    let line_start = source[..byte].rfind('\n').map_or(0, |index| index + 1);
    source[line_start..byte].chars().any(|c| !c.is_whitespace())
}

fn attach_trailing(model: &mut Model, owners: &[Owner], doc: usize, comment: Comment) {
    let mut candidates: Vec<&Owner> = owners
        .iter()
        .filter(|owner| owner.doc == doc)
        .filter(|owner| match owner.kind {
            OwnerKind::Entry { .. } => owner.start.row == comment.row,
            OwnerKind::Item { .. } => owner.start.row == comment.row,
        })
        .collect();
    candidates.extend(
        owners
            .iter()
            .filter(|owner| owner.doc == doc)
            .filter(|owner| {
                matches!(
                    shape(model, owner.value),
                    Shape::Scalar | Shape::Alias | Shape::Empty | Shape::Flow
                ) && owner.end.row == comment.row
            }),
    );
    // A comment can trail node properties such as an anchor or tag on a line
    // between the key or dash and the value. The entry or item owns it.
    candidates.extend(
        owners
            .iter()
            .filter(|owner| owner.doc == doc)
            .filter(|owner| {
                let value = &model.nodes[owner.value as usize];
                owner.start.row < comment.row && value.start.row >= comment.row
            }),
    );
    candidates.sort_by_key(|owner| std::cmp::Reverse(owner.ancestors.len()));
    candidates.dedup_by_key(|owner| owner.start_byte);
    let Some(owner) = candidates.first().copied() else {
        return;
    };
    set_trailing(model, owner, comment);
}

fn attach_own_line(
    model: &mut Model,
    owners: &[Owner],
    doc: usize,
    comment: Comment,
) -> Result<(), crate::fmt::FormatError> {
    // A comment between a key and a value that starts on a later line has no
    // canonical position.
    for owner in owners.iter().filter(|owner| owner.doc == doc) {
        if let OwnerKind::Entry { .. } = owner.kind {
            let value = &model.nodes[owner.value as usize];
            if owner.start_byte <= comment.byte
                && comment.byte < value.span.start
                && value.start.row > comment.row
                && matches!(
                    shape(model, owner.value),
                    Shape::Scalar | Shape::Alias | Shape::Flow
                )
            {
                return Err(crate::fmt::FormatError::Unsupported {
                    line: comment.row + 1,
                    construct: "comment between a key and its value".to_string(),
                });
            }
        }
    }

    let next = owners
        .iter()
        .filter(|owner| owner.doc == doc && owner.start_byte > comment.byte)
        .min_by_key(|owner| owner.start_byte);
    let previous = owners
        .iter()
        .filter(|owner| owner.doc == doc && owner.end_byte < comment.byte)
        .max_by_key(|owner| owner.end_byte);

    // A comment between a key and the first child of its block collection is a
    // leading comment for that child, not a dangling comment of the collection
    // that ended just before the key.
    let inside_later_block = owners
        .iter()
        .filter(|owner| owner.doc == doc)
        .filter(|owner| owner.start_byte < comment.byte && comment.byte < owner.end_byte)
        .filter(|owner| {
            matches!(shape(model, owner.value), Shape::Block)
                && model.nodes[owner.value as usize].span.start > comment.byte
        })
        .max_by_key(|owner| owner.ancestors.len())
        .is_some();
    if inside_later_block {
        if let Some(next) = next {
            set_leading(model, next, comment);
        } else {
            push_dangling(model, model.docs[doc].root, comment);
        }
        return Ok(());
    }

    if let Some(previous) = previous {
        for collection in &previous.ancestors {
            let node = &model.nodes[*collection as usize];
            if content_end(model, *collection) > comment.byte {
                continue;
            }
            if next.is_some_and(|next| {
                node.span.start <= next.start_byte && next.end_byte <= node.span.end
            }) {
                continue;
            }
            if child_column(model, *collection) == comment.col {
                push_dangling(model, *collection, comment);
                return Ok(());
            }
        }
    }

    if let Some(next) = next {
        set_leading(model, next, comment);
    } else {
        push_dangling(model, model.docs[doc].root, comment);
    }
    Ok(())
}

fn collect_owners(model: &Model) -> Vec<Owner> {
    let mut owners = Vec::new();
    for (doc, document) in model.docs.iter().enumerate() {
        collect_node_owners(
            model,
            doc,
            document.root,
            Vec::new(),
            Vec::new(),
            &mut owners,
        );
    }
    owners.sort_by_key(|owner| (owner.doc, owner.start_byte));
    owners
}

fn collect_node_owners(
    model: &Model,
    doc: usize,
    id: NodeId,
    path: Vec<PathSeg>,
    ancestors: Vec<NodeId>,
    owners: &mut Vec<Owner>,
) {
    let node = &model.nodes[id as usize];
    match &node.kind {
        NodeKind::Map { entries, .. } => {
            let mut child_ancestors = vec![id];
            child_ancestors.extend(ancestors.iter().copied());
            for (index, entry) in entries.iter().enumerate() {
                let mut entry_path = path.clone();
                entry_path.push(PathSeg::Key(key_string(model, entry.key)));
                let key = &model.nodes[entry.key as usize];
                let value = &model.nodes[entry.value as usize];
                owners.push(Owner {
                    doc,
                    kind: OwnerKind::Entry { map: id, index },
                    start: key.start,
                    start_byte: key.span.start,
                    end: value.end,
                    end_byte: value.span.end,
                    value: entry.value,
                    ancestors: child_ancestors.clone(),
                });
                collect_node_owners(
                    model,
                    doc,
                    entry.value,
                    entry_path,
                    child_ancestors.clone(),
                    owners,
                );
            }
        }
        NodeKind::Seq { items, .. } => {
            let mut child_ancestors = vec![id];
            child_ancestors.extend(ancestors.iter().copied());
            for (index, item) in items.iter().enumerate() {
                let mut item_path = path.clone();
                item_path.push(PathSeg::Index(index));
                let value = &model.nodes[item.value as usize];
                owners.push(Owner {
                    doc,
                    kind: OwnerKind::Item { seq: id, index },
                    start: item.dash,
                    start_byte: item.dash_byte,
                    end: value.end,
                    end_byte: value.span.end,
                    value: item.value,
                    ancestors: child_ancestors.clone(),
                });
                collect_node_owners(
                    model,
                    doc,
                    item.value,
                    item_path,
                    child_ancestors.clone(),
                    owners,
                );
            }
        }
        _ => {}
    }
}

/// The byte offset where the last child of a collection ends. Tree-sitter
/// includes trailing comments in a collection's span, so the span end cannot
/// be used to decide whether a comment belongs to the collection.
fn content_end(model: &Model, id: NodeId) -> usize {
    match &model.nodes[id as usize].kind {
        NodeKind::Map { entries, .. } => entries
            .iter()
            .map(|entry| model.nodes[entry.value as usize].span.end)
            .max()
            .unwrap_or(model.nodes[id as usize].span.start),
        NodeKind::Seq { items, .. } => items
            .iter()
            .map(|item| model.nodes[item.value as usize].span.end)
            .max()
            .unwrap_or(model.nodes[id as usize].span.start),
        _ => model.nodes[id as usize].span.end,
    }
}

fn shape(model: &Model, id: NodeId) -> Shape {
    match &model.nodes[id as usize].kind {
        NodeKind::Scalar { .. } => Shape::Scalar,
        NodeKind::Alias(_) => Shape::Alias,
        NodeKind::Empty => Shape::Empty,
        NodeKind::Map { flow, .. } | NodeKind::Seq { flow, .. } => {
            if *flow {
                Shape::Flow
            } else {
                Shape::Block
            }
        }
    }
}

fn set_trailing(model: &mut Model, owner: &Owner, comment: Comment) {
    match owner.kind {
        OwnerKind::Entry { map, index } => {
            if let NodeKind::Map { entries, .. } = &mut model.nodes[map as usize].kind
                && let Some(entry) = entries.get_mut(index)
            {
                entry.trailing = Some(comment);
            }
        }
        OwnerKind::Item { seq, index } => {
            if let NodeKind::Seq { items, .. } = &mut model.nodes[seq as usize].kind
                && let Some(item) = items.get_mut(index)
            {
                item.trailing = Some(comment);
            }
        }
    }
}

fn set_leading(model: &mut Model, owner: &Owner, comment: Comment) {
    match owner.kind {
        OwnerKind::Entry { map, index } => {
            if let NodeKind::Map { entries, .. } = &mut model.nodes[map as usize].kind
                && let Some(entry) = entries.get_mut(index)
            {
                entry.leading.push(comment);
            }
        }
        OwnerKind::Item { seq, index } => {
            if let NodeKind::Seq { items, .. } = &mut model.nodes[seq as usize].kind
                && let Some(item) = items.get_mut(index)
            {
                item.leading.push(comment);
            }
        }
    }
}

fn push_dangling(model: &mut Model, collection: NodeId, comment: Comment) {
    match &mut model.nodes[collection as usize].kind {
        NodeKind::Map { dangling, .. } | NodeKind::Seq { dangling, .. } => {
            dangling.push(comment);
        }
        _ => {}
    }
}

fn split_header(model: &mut Model) {
    for doc in &mut model.docs {
        let root = doc.root;
        let first_key = match &model.nodes[root as usize].kind {
            NodeKind::Map { entries, .. } => entries.first().map(|entry| entry.key),
            _ => None,
        };
        let Some(first_key) = first_key else {
            continue;
        };
        if matches!(&model.nodes[root as usize].kind, NodeKind::Map { entries, .. } if entries[0].leading.is_empty())
        {
            continue;
        }
        let first_row = model.nodes[first_key as usize].start.row;
        let NodeKind::Map { entries, .. } = &mut model.nodes[root as usize].kind else {
            continue;
        };
        let first = &mut entries[0];
        let mut run: Vec<usize> = Vec::new();
        let mut row = first_row;
        loop {
            if row == 0 {
                break;
            }
            row -= 1;
            match first.leading.iter().position(|comment| comment.row == row) {
                Some(index) => run.push(index),
                None => break,
            }
        }
        run.reverse();
        let keep_run = run.last().is_some_and(|index| {
            first.leading[*index]
                .text
                .contains("rsigma-disable-next-line")
        });
        let mut header = Vec::new();
        let mut leading = Vec::new();
        for (index, comment) in first.leading.drain(..).enumerate() {
            if keep_run && run.contains(&index) {
                leading.push(comment);
            } else {
                header.push(comment);
            }
        }
        first.leading = leading;
        doc.header.extend(header);
    }
}

fn hoist_item_leading(model: &mut Model) {
    let roots: Vec<NodeId> = model.docs.iter().map(|doc| doc.root).collect();
    for root in roots {
        hoist_node(model, root);
    }
}

fn hoist_node(model: &mut Model, id: NodeId) {
    let children: Vec<NodeId> = match &model.nodes[id as usize].kind {
        NodeKind::Map { entries, .. } => entries.iter().map(|entry| entry.value).collect(),
        NodeKind::Seq { items, .. } => items.iter().map(|item| item.value).collect(),
        _ => return,
    };
    let items = match &mut model.nodes[id as usize].kind {
        NodeKind::Seq { items, .. } => std::mem::take(items),
        _ => Vec::new(),
    };
    for mut item in items {
        let value = item.value;
        if let NodeKind::Map {
            entries,
            flow: false,
            ..
        } = &mut model.nodes[value as usize].kind
            && !entries.is_empty()
            && !item.leading.is_empty()
        {
            let leading = std::mem::take(&mut item.leading);
            let mut combined = leading;
            combined.append(&mut entries[0].leading);
            entries[0].leading = combined;
        }
        if let NodeKind::Seq { items, .. } = &mut model.nodes[id as usize].kind {
            items.push(item);
        }
    }
    for child in children {
        hoist_node(model, child);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fmt::cst;
    use crate::parse_sigma_yaml;

    fn build(source: &str) -> Model {
        let mut parser = tree_sitter::Parser::new();
        let language: tree_sitter::Language = tree_sitter_yaml::LANGUAGE.into();
        parser.set_language(&language).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let values: Vec<yaml_serde::Value> = yaml_serde::Deserializer::from_str(source)
            .map(|doc| yaml_serde::Value::deserialize(doc).unwrap())
            .collect();
        let mut model = cst::build(source, &tree, &values).unwrap();
        attach(&mut model, source).unwrap();
        model
    }

    use serde::Deserialize;

    fn find_entry(model: &Model, key: &str) -> (NodeId, usize) {
        for doc in &model.docs {
            if let NodeKind::Map { entries, .. } = &model.nodes[doc.root as usize].kind {
                for (index, entry) in entries.iter().enumerate() {
                    if key_string(model, entry.key) == key {
                        return (doc.root, index);
                    }
                }
            }
        }
        panic!("no entry {key}");
    }

    fn entry(model: &Model, map: NodeId, index: usize) -> &crate::fmt::cst::Entry {
        match &model.nodes[map as usize].kind {
            NodeKind::Map { entries, .. } => &entries[index],
            _ => panic!("not a map"),
        }
    }

    #[test]
    fn trailing_comment_on_key_line() {
        let source = "title: Test # note\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let model = build(source);
        let (map, index) = find_entry(&model, "title");
        assert_eq!(
            entry(&model, map, index).trailing.as_ref().unwrap().text,
            "# note"
        );
    }

    #[test]
    fn trailing_comment_on_scalar_and_dash() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value # scalar\n    condition: selection\n    keywords:\n        - one # dash\n";
        let model = build(source);
        let (map, index) = find_entry(&model, "detection");
        let NodeKind::Map { entries, .. } = &model.nodes[map as usize].kind else {
            panic!()
        };
        let selection = entries[index].value;
        let NodeKind::Map { entries, .. } = &model.nodes[selection as usize].kind else {
            panic!()
        };
        let field = entries[0].value;
        let NodeKind::Map { entries, .. } = &model.nodes[field as usize].kind else {
            panic!()
        };
        assert_eq!(entries[0].trailing.as_ref().unwrap().text, "# scalar");
    }

    #[test]
    fn own_line_comment_before_next_entry_is_leading() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    # above condition\n    condition: selection\n";
        let model = build(source);
        let (map, index) = find_entry(&model, "detection");
        let NodeKind::Map { entries, .. } = &model.nodes[map as usize].kind else {
            panic!()
        };
        let condition = &entries[index];
        let NodeKind::Map { entries, .. } = &model.nodes[condition.value as usize].kind else {
            panic!()
        };
        let _ = entries;
    }

    #[test]
    fn own_line_comment_before_a_block_value_is_leading() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection_a:\n        Field:\n            - one\n    selection_b:\n        # note\n        Field:\n            - two\n    condition: selection_a\n";
        let model = build(source);
        let (map, index) = find_entry(&model, "detection");
        let detection = entry(&model, map, index).value;
        let NodeKind::Map { entries, .. } = &model.nodes[detection as usize].kind else {
            panic!()
        };
        let selection_a = entries
            .iter()
            .find(|entry| key_string(&model, entry.key) == "selection_a")
            .unwrap();
        let selection_b = entries
            .iter()
            .find(|entry| key_string(&model, entry.key) == "selection_b")
            .unwrap();
        let NodeKind::Map {
            entries: selection_b_entries,
            ..
        } = &model.nodes[selection_b.value as usize].kind
        else {
            panic!()
        };
        assert_eq!(selection_b_entries[0].leading.len(), 1);
        assert_eq!(selection_b_entries[0].leading[0].text, "# note");
        let NodeKind::Map { dangling, .. } = &model.nodes[selection_a.value as usize].kind else {
            panic!()
        };
        assert!(dangling.is_empty());
    }

    #[test]
    fn own_line_comment_between_sequence_items_is_leading() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Image|endswith:\n            - '/one'\n            # note\n            - '/two'\n    condition: selection\n";
        let model = build(source);
        let (map, index) = find_entry(&model, "detection");
        let detection = entry(&model, map, index).value;
        let NodeKind::Map { entries, .. } = &model.nodes[detection as usize].kind else {
            panic!()
        };
        let selection = entries
            .iter()
            .find(|entry| key_string(&model, entry.key) == "selection")
            .unwrap();
        let NodeKind::Map { entries, .. } = &model.nodes[selection.value as usize].kind else {
            panic!()
        };
        let NodeKind::Seq {
            items, dangling, ..
        } = &model.nodes[entries[0].value as usize].kind
        else {
            panic!()
        };
        assert!(dangling.is_empty());
        assert_eq!(items[1].leading.len(), 1);
        assert_eq!(items[1].leading[0].text, "# note");
    }

    #[test]
    fn comment_after_entries_is_dangling() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n# tail\n";
        let model = build(source);
        let NodeKind::Map { dangling, .. } = &model.nodes[model.docs[0].root as usize].kind else {
            panic!()
        };
        assert_eq!(dangling.len(), 1);
    }

    #[test]
    fn disable_next_line_stays_leading() {
        let source = "# header\ntitle: Test\n# rsigma-disable-next-line missing_author\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let model = build(source);
        let (map, index) = find_entry(&model, "logsource");
        let entry = entry(&model, map, index);
        assert!(
            entry
                .leading
                .iter()
                .any(|comment| comment.text.contains("rsigma-disable-next-line"))
        );
        assert!(model.docs[0].header.iter().any(|c| c.text == "# header"));
    }

    #[test]
    fn header_moves_above_first_entry() {
        let source = "# license header\ntitle: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let model = build(source);
        assert_eq!(model.docs[0].header.len(), 1);
        let (map, index) = find_entry(&model, "title");
        assert!(entry(&model, map, index).leading.is_empty());
    }

    #[test]
    fn comment_between_key_and_value_is_refused() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field:\n            # between\n            value\n    condition: selection\n";
        let mut parser = tree_sitter::Parser::new();
        let language: tree_sitter::Language = tree_sitter_yaml::LANGUAGE.into();
        parser.set_language(&language).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let values: Vec<yaml_serde::Value> = yaml_serde::Deserializer::from_str(source)
            .map(|doc| yaml_serde::Value::deserialize(doc).unwrap())
            .collect();
        let mut model = cst::build(source, &tree, &values).unwrap();
        let error = attach(&mut model, source).unwrap_err();
        assert!(matches!(
            error,
            crate::fmt::FormatError::Unsupported { construct, .. }
                if construct == "comment between a key and its value"
        ));
    }

    #[test]
    fn comment_on_document_marker_is_start_comment() {
        let source = "--- # first\ntitle: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let model = build(source);
        assert_eq!(
            model.docs[0].start_comment.as_ref().unwrap().text,
            "# first"
        );
    }

    #[test]
    fn comment_on_later_document_marker_is_start_comment() {
        let source = "title: One\naction: global\n---  # trail: Reset\naction: reset\n";
        let model = build(source);
        assert_eq!(
            model.docs[1].start_comment.as_ref().unwrap().text,
            "# trail: Reset"
        );
    }

    #[test]
    fn comments_between_documents_follow_the_previous_document() {
        let source = "title: One\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n# between\n---\ntitle: Two\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let model = build(source);
        assert!(model.docs[0].header.iter().all(|c| c.text != "# between"));
        let NodeKind::Map { dangling, .. } = &model.nodes[model.docs[0].root as usize].kind else {
            panic!()
        };
        assert!(dangling.iter().any(|c| c.text == "# between"));
    }

    #[test]
    fn trailing_comment_after_anchor_on_its_own_line_stays_with_the_entry() {
        let source = "e:\n &A #urs\n s\naction: reset\n";
        let model = build(source);
        let (map, index) = find_entry(&model, "e");
        assert_eq!(
            entry(&model, map, index).trailing.as_ref().unwrap().text,
            "#urs"
        );
    }

    #[test]
    fn trailing_comment_in_later_document_stays_with_its_entry() {
        let source = "title: Global\nlogsource:\n    product: windows\naction: global\n---\ndetection:\n    seield: value  # trail: Reset\naction: reset\n";
        let model = build(source);
        let NodeKind::Map { entries, .. } = &model.nodes[model.docs[1].root as usize].kind else {
            panic!()
        };
        let detection = entries
            .iter()
            .find(|entry| key_string(&model, entry.key) == "detection")
            .unwrap();
        let NodeKind::Map { entries, .. } = &model.nodes[detection.value as usize].kind else {
            panic!()
        };
        let entry = entries
            .iter()
            .find(|entry| key_string(&model, entry.key) == "seield")
            .unwrap();
        assert_eq!(entry.trailing.as_ref().unwrap().text, "# trail: Reset");
    }

    #[test]
    fn item_leading_comments_hoist_into_the_mapping() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        # above item\n        - Field: value\n    condition: selection\n";
        let model = build(source);
        let (map, index) = find_entry(&model, "detection");
        let NodeKind::Map { entries, .. } = &model.nodes[map as usize].kind else {
            panic!()
        };
        let selection = entries[index].value;
        let NodeKind::Map { entries, .. } = &model.nodes[selection as usize].kind else {
            panic!()
        };
        let value = entries[0].value;
        let NodeKind::Seq { items, .. } = &model.nodes[value as usize].kind else {
            panic!()
        };
        assert!(items[0].leading.is_empty());
        let NodeKind::Map { entries, .. } = &model.nodes[items[0].value as usize].kind else {
            panic!()
        };
        assert!(entries[0].leading.iter().any(|c| c.text == "# above item"));
    }

    #[test]
    fn parse_is_sigma() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        assert!(parse_sigma_yaml(source).is_ok());
    }
}
