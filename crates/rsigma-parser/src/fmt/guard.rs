//! Semantic guard and fingerprint for formatted output.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::fmt::cst::{Model, NodeId, NodeKind, PathSeg, PreludeLine, Prop, key_string};
use crate::fmt::context::DocKind;
use crate::fmt::order::Plan;
use crate::fmt::{FormatError, comments, cst, deserialize_values, order, parse_tree};
use crate::parser::parse_sigma_yaml;

const FINGERPRINT_REASON: &str = "comments, anchors, aliases, tags, or directives changed";

/// Everything the guard needs from the source file.
pub(crate) struct Before<'a> {
    pub values: &'a [yaml_serde::Value],
    pub collection: &'a crate::SigmaCollection,
    pub fingerprint: Vec<String>,
    pub kinds: &'a [DocKind],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CommentRole {
    Leading,
    Trailing,
    Dangling,
}

impl std::fmt::Display for CommentRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            CommentRole::Leading => "leading",
            CommentRole::Trailing => "trailing",
            CommentRole::Dangling => "dangling",
        })
    }
}

/// Build the per-document fingerprint used to compare the source and output.
///
/// The fingerprint normalises the leading comments of the root mapping's first
/// entry in canonical order into the document header, because output text
/// cannot distinguish them once blank lines are gone.
pub(crate) fn fingerprint(model: &Model, _kinds: &[DocKind], plan: &Plan) -> Vec<String> {
    let mut normalized = model.clone();
    for doc in &mut normalized.docs {
        let root = doc.root;
        let NodeKind::Map { entries, .. } = &mut normalized.nodes[root as usize].kind else {
            continue;
        };
        if entries.is_empty() {
            continue;
        }
        let first = plan.order(root, entries.len())[0];
        let leading = std::mem::take(&mut entries[first].leading);
        doc.header.extend(leading);
    }
    let mut documents = Vec::with_capacity(normalized.docs.len());
    for doc in &normalized.docs {
        let mut lines = Vec::new();
        for line in &doc.prelude {
            match line {
                PreludeLine::Directive(text) => lines.push(format!("directive: {text}")),
                PreludeLine::Comment(comment) => {
                    lines.push(format!("prelude-comment: {}", comment.text));
                }
            }
        }
        for comment in &doc.header {
            lines.push(format!("header: {}", comment.text));
        }
        let mut comments: BTreeMap<(Vec<PathSeg>, CommentRole), Vec<String>> = BTreeMap::new();
        let mut tags: BTreeMap<Vec<PathSeg>, String> = BTreeMap::new();
        let mut anchors: BTreeMap<Vec<PathSeg>, String> = BTreeMap::new();
        let mut aliases: BTreeMap<Vec<PathSeg>, String> = BTreeMap::new();
        collect_fingerprint(
            &normalized,
            doc.root,
            Vec::new(),
            &mut comments,
            &mut tags,
            &mut anchors,
            &mut aliases,
        );
        for ((path, role), texts) in comments {
            lines.push(format!("{role} {}: {}", path_text(&path), texts.join(" | ")));
        }
        for (path, tag) in tags {
            lines.push(format!("tag {}: {tag}", path_text(&path)));
        }
        for (path, anchor) in anchors {
            lines.push(format!("anchor {}: {anchor}", path_text(&path)));
        }
        for (path, alias) in aliases {
            lines.push(format!("alias {}: {alias}", path_text(&path)));
        }
        if let Some(bindings) = order::bindings(&normalized, None, doc.root) {
            for (path, anchor_path) in bindings {
                lines.push(format!(
                    "binding {}: {}",
                    path_text(&path),
                    path_text(&anchor_path)
                ));
            }
        }
        if let Some(action) = action_value(&normalized, doc.root) {
            lines.push(format!("action: {action}"));
        }
        documents.push(lines.join("\n"));
    }
    documents
}

#[allow(clippy::too_many_arguments)]
fn collect_fingerprint(
    model: &Model,
    id: NodeId,
    path: Vec<PathSeg>,
    comments: &mut BTreeMap<(Vec<PathSeg>, CommentRole), Vec<String>>,
    tags: &mut BTreeMap<Vec<PathSeg>, String>,
    anchors: &mut BTreeMap<Vec<PathSeg>, String>,
    aliases: &mut BTreeMap<Vec<PathSeg>, String>,
) {
    let node = &model.nodes[id as usize];
    for prop in &node.props {
        match prop {
            Prop::Tag(tag) => {
                tags.insert(path.clone(), tag.clone());
            }
            Prop::Anchor(name) => {
                anchors.insert(path.clone(), name.clone());
            }
        }
    }
    match &node.kind {
        NodeKind::Map { entries, dangling, .. } => {
            for comment in dangling {
                comments
                    .entry((path.clone(), CommentRole::Dangling))
                    .or_default()
                    .push(comment.text.clone());
            }
            for entry in entries {
                let mut entry_path = path.clone();
                entry_path.push(PathSeg::Key(key_string(model, entry.key)));
                let mut key_path = entry_path.clone();
                key_path.push(PathSeg::KeyNode);
                collect_key_props(model, entry.key, &key_path, tags, anchors, aliases);
                for comment in &entry.leading {
                    comments
                        .entry((entry_path.clone(), CommentRole::Leading))
                        .or_default()
                        .push(comment.text.clone());
                }
                if let Some(comment) = &entry.trailing {
                    comments
                        .entry((entry_path.clone(), CommentRole::Trailing))
                        .or_default()
                        .push(comment.text.clone());
                }
                collect_fingerprint(
                    model,
                    entry.value,
                    entry_path,
                    comments,
                    tags,
                    anchors,
                    aliases,
                );
            }
        }
        NodeKind::Seq { items, dangling, .. } => {
            for comment in dangling {
                comments
                    .entry((path.clone(), CommentRole::Dangling))
                    .or_default()
                    .push(comment.text.clone());
            }
            for (index, item) in items.iter().enumerate() {
                let mut item_path = path.clone();
                item_path.push(PathSeg::Index(index));
                for comment in &item.leading {
                    comments
                        .entry((item_path.clone(), CommentRole::Leading))
                        .or_default()
                        .push(comment.text.clone());
                }
                if let Some(comment) = &item.trailing {
                    comments
                        .entry((item_path.clone(), CommentRole::Trailing))
                        .or_default()
                        .push(comment.text.clone());
                }
                collect_fingerprint(
                    model,
                    item.value,
                    item_path,
                    comments,
                    tags,
                    anchors,
                    aliases,
                );
            }
        }
        NodeKind::Alias(name) => {
            aliases.insert(path, name.clone());
        }
        _ => {}
    }
}

fn collect_key_props(
    model: &Model,
    id: NodeId,
    path: &[PathSeg],
    tags: &mut BTreeMap<Vec<PathSeg>, String>,
    anchors: &mut BTreeMap<Vec<PathSeg>, String>,
    aliases: &mut BTreeMap<Vec<PathSeg>, String>,
) {
    let node = &model.nodes[id as usize];
    for prop in &node.props {
        match prop {
            Prop::Tag(tag) => {
                tags.insert(path.to_vec(), tag.clone());
            }
            Prop::Anchor(name) => {
                anchors.insert(path.to_vec(), name.clone());
            }
        }
    }
    if let NodeKind::Alias(name) = &node.kind {
        aliases.insert(path.to_vec(), name.clone());
    }
}

fn action_value(model: &Model, root: NodeId) -> Option<String> {
    let NodeKind::Map { entries, .. } = &model.nodes[root as usize].kind else {
        return None;
    };
    let entry = entries
        .iter()
        .find(|entry| key_string(model, entry.key) == "action")?;
    Some(node_text(model, entry.value))
}

fn node_text(model: &Model, id: NodeId) -> String {
    match &model.nodes[id as usize].kind {
        NodeKind::Scalar { text, .. } => text.clone(),
        NodeKind::Alias(name) => format!("*{name}"),
        _ => String::new(),
    }
}

fn path_text(path: &[PathSeg]) -> String {
    if path.is_empty() {
        return "<root>".to_string();
    }
    let mut out = String::new();
    for (index, segment) in path.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        match segment {
            PathSeg::Key(key) => {
                out.push_str(&key.replace('\\', "\\\\").replace('/', "\\/"));
            }
            PathSeg::Index(value) => {
                let _ = write!(out, "#{value}");
            }
            PathSeg::KeyNode => out.push_str("<key>"),
        }
    }
    out
}

/// Check that `output` is semantically identical to the source described by
/// `before`.
pub(crate) fn check(before: &Before<'_>, output: &str) -> Result<(), FormatError> {
    let tree = parse_tree(output).map_err(|_| guard(FINGERPRINT_REASON))?;
    if tree.root_node().has_error() {
        return Err(FormatError::Guard(
            "the output is not valid YAML".to_string(),
        ));
    }
    let values = deserialize_values(output).map_err(|_| guard(FINGERPRINT_REASON))?;
    if values.len() != before.values.len() {
        return Err(FormatError::Guard(format!(
            "document count changed from {} to {}",
            before.values.len(),
            values.len()
        )));
    }
    for (index, (source, formatted)) in before.values.iter().zip(&values).enumerate() {
        if source != formatted {
            return Err(FormatError::Guard(format!(
                "document {} changed value",
                index + 1
            )));
        }
    }
    let collection = parse_sigma_yaml(output).map_err(|_| guard("parser diagnostics changed"))?;
    if collection.diagnostics.iter().any(|diagnostic| diagnostic.is_error()) {
        return Err(guard("parser diagnostics changed"));
    }
    if collection.rules != before.collection.rules {
        return Err(guard("parsed rules changed"));
    }
    if collection.correlations != before.collection.correlations {
        return Err(guard("parsed correlations changed"));
    }
    if collection.filters != before.collection.filters {
        return Err(guard("parsed filters changed"));
    }
    let mut formatted_diagnostics = collection.diagnostics.clone();
    let mut source_diagnostics = before.collection.diagnostics.clone();
    for diagnostic in &mut formatted_diagnostics {
        diagnostic.location = None;
        diagnostic.path = None;
    }
    for diagnostic in &mut source_diagnostics {
        diagnostic.location = None;
        diagnostic.path = None;
    }
    if formatted_diagnostics != source_diagnostics {
        return Err(guard("parser diagnostics changed"));
    }
    let mut model = cst::build(output, &tree, &values).map_err(|_| guard(FINGERPRINT_REASON))?;
    comments::attach(&mut model, output).map_err(|_| guard(FINGERPRINT_REASON))?;
    let plan = order::plan(&model, before.kinds);
    let after = fingerprint(&model, before.kinds, &plan);
    if after != before.fingerprint {
        let item = first_difference(&before.fingerprint, &after);
        return Err(FormatError::Guard(match item {
            Some(item) => format!("{FINGERPRINT_REASON}: {item}"),
            None => FINGERPRINT_REASON.to_string(),
        }));
    }
    Ok(())
}

fn first_difference(before: &[String], after: &[String]) -> Option<String> {
    for (index, (source, formatted)) in before.iter().zip(after).enumerate() {
        if source == formatted {
            continue;
        }
        let source_lines: Vec<&str> = source.lines().collect();
        let formatted_lines: Vec<&str> = formatted.lines().collect();
        for (line_index, (source_line, formatted_line)) in
            source_lines.iter().zip(&formatted_lines).enumerate()
        {
            if source_line != formatted_line {
                return Some(format!(
                    "document {} line {}: {} -> {}",
                    index + 1,
                    line_index + 1,
                    source_line,
                    formatted_line
                ));
            }
        }
        if source_lines.len() != formatted_lines.len() {
            let extra = if source_lines.len() > formatted_lines.len() {
                source_lines.get(formatted_lines.len())
            } else {
                formatted_lines.get(source_lines.len())
            };
            return Some(format!(
                "document {} line {}: {}",
                index + 1,
                source_lines.len().min(formatted_lines.len()) + 1,
                extra.copied().unwrap_or("")
            ));
        }
        return Some(format!("document {} fingerprint differs", index + 1));
    }
    if before.len() != after.len() {
        return Some(format!(
            "document count changed from {} to {}",
            before.len(),
            after.len()
        ));
    }
    None
}

fn guard(reason: &str) -> FormatError {
    FormatError::Guard(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fmt::classify;
    use crate::fmt::context::DocKind;
    use crate::fmt::order;

    struct Prepared {
        values: Vec<yaml_serde::Value>,
        collection: crate::SigmaCollection,
        fingerprint: Vec<String>,
        kinds: Vec<DocKind>,
    }

    fn prepare(source: &str) -> Prepared {
        let tree = parse_tree(source).unwrap();
        let values = deserialize_values(source).unwrap();
        let kinds = classify::classify(&values).unwrap();
        let collection = parse_sigma_yaml(source).unwrap();
        let mut model = cst::build(source, &tree, &values).unwrap();
        comments::attach(&mut model, source).unwrap();
        let plan = order::plan(&model, &kinds);
        let fingerprint = fingerprint(&model, &kinds, &plan);
        Prepared {
            values,
            collection,
            fingerprint,
            kinds,
        }
    }

    fn check_pair(source: &str, output: &str) -> Result<(), FormatError> {
        let prepared = prepare(source);
        let before = Before {
            values: &prepared.values,
            collection: &prepared.collection,
            fingerprint: prepared.fingerprint.clone(),
            kinds: &prepared.kinds,
        };
        check(&before, output)
    }

    const RULE: &str = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";

    #[test]
    fn accepts_identical_output() {
        assert!(check_pair(RULE, RULE).is_ok());
    }

    #[test]
    fn refuses_changed_value() {
        let output = RULE.replace("Field: value", "Field: other");
        let error = check_pair(RULE, &output).unwrap_err();
        assert!(matches!(
            error,
            FormatError::Guard(ref reason) if reason.contains("changed value")
        ));
    }

    #[test]
    fn refuses_reordered_sequence() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field:\n            - one\n            - two\n    condition: selection\n";
        let output = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field:\n            - two\n            - one\n    condition: selection\n";
        let error = check_pair(source, output).unwrap_err();
        assert!(matches!(
            error,
            FormatError::Guard(ref reason) if reason.contains("changed value")
        ));
    }

    #[test]
    fn refuses_dropped_comment() {
        let source = "title: Test # note\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let output = RULE;
        let error = check_pair(source, output).unwrap_err();
        assert!(matches!(
            error,
            FormatError::Guard(ref reason) if reason.contains(FINGERPRINT_REASON)
        ));
    }

    #[test]
    fn refuses_comment_moved_to_another_key() {
        let source = "title: Test\nlogsource: # note\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let output = "title: Test # note\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let error = check_pair(source, output).unwrap_err();
        assert!(matches!(
            error,
            FormatError::Guard(ref reason) if reason.contains(FINGERPRINT_REASON)
        ));
    }

    #[test]
    fn refuses_rebound_alias() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: &a one\n        Other: *a\n    condition: selection\n";
        let output = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Other: *a\n        Field: &a one\n    condition: selection\n";
        let error = check_pair(source, output).unwrap_err();
        assert!(matches!(error, FormatError::Guard(_)));
    }

    #[test]
    fn refuses_dropped_directive() {
        let source = "%YAML 1.2\n---\ntitle: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let output = RULE;
        let error = check_pair(source, output).unwrap_err();
        assert!(matches!(
            error,
            FormatError::Guard(ref reason) if reason.contains(FINGERPRINT_REASON)
        ));
    }

    #[test]
    fn refuses_changed_tag() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: !!str 123\n    condition: selection\n";
        let output = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: !!int 123\n    condition: selection\n";
        let error = check_pair(source, output).unwrap_err();
        assert!(matches!(error, FormatError::Guard(_)));
    }

    #[test]
    fn fingerprint_is_stable_across_key_order() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let reordered = "logsource:\n    category: test\ntitle: Test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let prepared = prepare(source);
        let before = Before {
            values: &prepared.values,
            collection: &prepared.collection,
            fingerprint: prepared.fingerprint.clone(),
            kinds: &prepared.kinds,
        };
        assert!(check(&before, reordered).is_ok());
    }
}
