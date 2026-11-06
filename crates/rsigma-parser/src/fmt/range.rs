//! Range formatting: rewrite the smallest block mapping that contains a range.

use crate::fmt::cst::{Model, NodeId, NodeKind, PathSeg, key_string};
use crate::fmt::{FormatError, guard, prepare};

/// A single splice that replaces one region of the source with canonical text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RangeEdit {
    /// Byte offset of the region start in the original source.
    pub start: usize,
    /// Byte offset of the region end (exclusive) in the original source.
    pub end: usize,
    /// The canonical text for the region.
    pub replacement: String,
}

/// Format only the smallest block mapping that contains `start..end`.
///
/// Returns `Ok(None)` when that mapping is already canonical. The spliced file
/// passes the same guard as [`format_yaml`](crate::format_yaml).
pub fn format_yaml_range(
    source: &str,
    start: usize,
    end: usize,
) -> Result<Option<RangeEdit>, FormatError> {
    if start > end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
    {
        return Err(FormatError::Range(
            "the range is outside the document or splits a character".to_string(),
        ));
    }

    let prepared = prepare(source)?;
    let bom = if prepared.had_bom {
        '\u{FEFF}'.len_utf8()
    } else {
        0
    };
    let stripped = source.strip_prefix('\u{FEFF}').unwrap_or(source);
    let start = start.saturating_sub(bom);
    let end = end.saturating_sub(bom);
    let (start, end) = trim_range(stripped, start, end);

    let document = select_document(&prepared.model, start, end)?;
    let mut maps = Vec::new();
    collect_maps(
        &prepared.model,
        stripped,
        prepared.model.docs[document].root,
        &[],
        0,
        &mut maps,
    );

    let region = maps
        .into_iter()
        .filter(|region| region.start <= start && end <= region.end)
        .max_by_key(|region| (region.depth, region.start))
        .ok_or_else(|| FormatError::Range("the range is not inside a mapping".to_string()))?;

    let span = prepared
        .rendered
        .spans
        .get(&(document, region.path.clone()))
        .ok_or_else(|| FormatError::Range("the range is not inside a mapping".to_string()))?;

    let replacement = build_replacement(&prepared.rendered.text, span, region.child_col);
    if replacement == stripped[region.start..region.end] {
        return Ok(None);
    }

    let mut spliced = String::with_capacity(stripped.len() + replacement.len());
    spliced.push_str(&stripped[..region.start]);
    spliced.push_str(&replacement);
    spliced.push_str(&stripped[region.end..]);
    let before = prepared.before();
    guard::check(&before, &spliced)?;

    Ok(Some(RangeEdit {
        start: region.start + bom,
        end: region.end + bom,
        replacement,
    }))
}

/// A block mapping's source region and the column of its first key.
struct MapRegion {
    path: Vec<PathSeg>,
    start: usize,
    end: usize,
    child_col: usize,
    depth: usize,
}

fn trim_range(source: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    let bytes = source.as_bytes();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
}

/// Pick the document that contains the range, or report that the range spans
/// more than one document.
fn select_document(model: &Model, start: usize, end: usize) -> Result<usize, FormatError> {
    let mut candidates = Vec::new();
    for (index, doc) in model.docs.iter().enumerate() {
        if doc.span.start <= end && start <= doc.span.end {
            candidates.push(index);
        }
    }
    match candidates.as_slice() {
        [index] => Ok(*index),
        [] => Err(FormatError::Range(
            "the range is not inside a mapping".to_string(),
        )),
        _ => Err(FormatError::Range(
            "the range spans more than one document".to_string(),
        )),
    }
}

fn collect_maps(
    model: &Model,
    source: &str,
    node: NodeId,
    path: &[PathSeg],
    depth: usize,
    out: &mut Vec<MapRegion>,
) {
    match &model.nodes[node as usize].kind {
        NodeKind::Map { entries, flow, .. } => {
            if !flow && !entries.is_empty() {
                let first = entries
                    .iter()
                    .min_by_key(|entry| entry.source_index)
                    .expect("non-empty mapping");
                let key = &model.nodes[first.key as usize];
                let mut start = key.span.start;
                if let Some(comment) = first.leading.first() {
                    start = start.min(comment.byte);
                }
                let mut content_end = structural_end(model, node);
                for comment in &first.leading {
                    content_end = content_end.max(comment.byte + comment.text.len());
                }
                content_end = content_end.max(comment_end(model, node));
                out.push(MapRegion {
                    path: path.to_vec(),
                    start,
                    end: line_end(source, content_end),
                    child_col: key.start.column,
                    depth,
                });
            }
            for entry in entries {
                let mut child_path = path.to_vec();
                child_path.push(PathSeg::Key(key_string(model, entry.key)));
                collect_maps(model, source, entry.value, &child_path, depth + 1, out);
            }
        }
        NodeKind::Seq { items, .. } => {
            for (index, item) in items.iter().enumerate() {
                let mut child_path = path.to_vec();
                child_path.push(PathSeg::Index(index));
                collect_maps(model, source, item.value, &child_path, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// The byte offset where the last structural child of a node ends, ignoring
/// comments that tree-sitter folds into collection spans.
fn structural_end(model: &Model, node: NodeId) -> usize {
    match &model.nodes[node as usize].kind {
        NodeKind::Map { entries, .. } => entries
            .iter()
            .map(|entry| {
                structural_end(model, entry.value).max(model.nodes[entry.key as usize].span.end)
            })
            .max()
            .unwrap_or(model.nodes[node as usize].span.start),
        NodeKind::Seq { items, .. } => items
            .iter()
            .map(|item| structural_end(model, item.value))
            .max()
            .unwrap_or(model.nodes[node as usize].span.start),
        _ => model.nodes[node as usize].span.end,
    }
}

/// The end of the last comment attached anywhere inside a node.
fn comment_end(model: &Model, node: NodeId) -> usize {
    match &model.nodes[node as usize].kind {
        NodeKind::Map {
            entries, dangling, ..
        } => {
            let mut end = dangling
                .iter()
                .map(|comment| comment.byte + comment.text.len())
                .max()
                .unwrap_or(0);
            for entry in entries {
                for comment in &entry.leading {
                    end = end.max(comment.byte + comment.text.len());
                }
                if let Some(comment) = &entry.trailing {
                    end = end.max(comment.byte + comment.text.len());
                }
                end = end.max(comment_end(model, entry.value));
            }
            end
        }
        NodeKind::Seq {
            items, dangling, ..
        } => {
            let mut end = dangling
                .iter()
                .map(|comment| comment.byte + comment.text.len())
                .max()
                .unwrap_or(0);
            for item in items {
                for comment in &item.leading {
                    end = end.max(comment.byte + comment.text.len());
                }
                if let Some(comment) = &item.trailing {
                    end = end.max(comment.byte + comment.text.len());
                }
                end = end.max(comment_end(model, item.value));
            }
            end
        }
        _ => 0,
    }
}

fn line_end(source: &str, position: usize) -> usize {
    match source[position..].find('\n') {
        Some(offset) => position + offset,
        None => source.len(),
    }
}

/// Re-indent the rendered region to the source mapping's child column. The
/// first line loses its rendered indentation because the source keeps the
/// indentation before the region start.
fn build_replacement(
    rendered: &str,
    span: &crate::fmt::render::SpanInfo,
    source_col: usize,
) -> String {
    let region = &rendered[span.start..span.end];
    let region = region.strip_suffix('\n').unwrap_or(region);
    let (first, rest) = match region.split_once('\n') {
        Some((first, rest)) => (first, rest),
        None => (region, ""),
    };
    let first = &first[span.child_col.min(first.len())..];
    let delta = source_col as isize - span.child_col as isize;

    let mut replacement = String::from(first);
    for line in rest.split('\n') {
        replacement.push('\n');
        if line.is_empty() {
            continue;
        }
        if delta > 0 {
            for _ in 0..delta {
                replacement.push(' ');
            }
            replacement.push_str(line);
        } else if delta < 0 {
            let mut line = line;
            let mut remove = (-delta) as usize;
            while remove > 0 && line.starts_with(' ') {
                line = &line[1..];
                remove -= 1;
            }
            replacement.push_str(line);
        } else {
            replacement.push_str(line);
        }
    }
    replacement
}

#[cfg(test)]
mod tests {
    use super::*;

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

    const RULE: &str = "logsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";

    #[test]
    fn a_selection_value_selects_the_selection_mapping() {
        let source = "title: Test\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: [one, two]\n  condition: selection\n";
        let (start, end) = range_of(source, "one");
        let output = apply(source, start, end).unwrap().expect("edit");
        assert_eq!(
            output,
            "title: Test\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field:\n        - one\n        - two\n  condition: selection\n"
        );
    }

    #[test]
    fn a_range_across_two_selections_selects_the_detection_mapping() {
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
    fn a_flow_list_selects_the_enclosing_root_mapping() {
        let source = "title: Test\ntags: [attack.execution, attack.discovery]\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";
        let (start, end) = range_of(source, "attack.execution");
        let output = apply(source, start, end).unwrap().expect("edit");
        assert_eq!(
            output,
            "title: Test\ntags:\n    - attack.execution\n    - attack.discovery\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n"
        );
    }

    #[test]
    fn a_cursor_on_a_comment_line_selects_its_mapping() {
        let source = "title: Test\ncustom:\n  nested:\n    # note\n    Deep: [one, two]\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";
        let start = source.find("# note").unwrap();
        let output = apply(source, start, start).unwrap().expect("edit");
        assert_eq!(
            output,
            "title: Test\ncustom:\n  nested:\n    # note\n    Deep:\n        - one\n        - two\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n"
        );
    }

    #[test]
    fn a_cursor_on_the_root_mapping_formats_the_whole_file() {
        let source = "title: Test\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";
        let start = source.find("title").unwrap();
        let output = apply(source, start, start).unwrap().expect("edit");
        assert_eq!(
            output,
            "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n"
        );
    }

    #[test]
    fn a_range_across_documents_is_refused() {
        let source = format!("title: First\n{RULE}---\ntitle: Second\n{RULE}");
        let start = source.find("First").unwrap();
        let end = source.find("Second").unwrap() + "Second".len();
        let error = apply(&source, start, end).unwrap_err();
        assert_eq!(
            error,
            FormatError::Range("the range spans more than one document".to_string())
        );
    }

    #[test]
    fn a_range_in_a_directive_is_refused() {
        let source = format!("%YAML 1.2\n---\ntitle: Test\n{RULE}");
        let error = apply(&source, 0, 0).unwrap_err();
        assert_eq!(
            error,
            FormatError::Range("the range is not inside a mapping".to_string())
        );
    }

    #[test]
    fn an_invalid_range_is_refused() {
        let source = format!("title: Test\n{RULE}");
        assert_eq!(
            format_yaml_range(&source, 5, 2).unwrap_err(),
            FormatError::Range(
                "the range is outside the document or splits a character".to_string()
            )
        );
        assert_eq!(
            format_yaml_range(&source, 0, source.len() + 1).unwrap_err(),
            FormatError::Range(
                "the range is outside the document or splits a character".to_string()
            )
        );
        let unicode = "title: Tést\n";
        let split = unicode.find('é').unwrap() + 1;
        assert_eq!(
            format_yaml_range(unicode, split, split).unwrap_err(),
            FormatError::Range(
                "the range is outside the document or splits a character".to_string()
            )
        );
    }

    #[test]
    fn a_bom_shifts_the_returned_offsets() {
        let body = "title: Test\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";
        let source = format!("\u{FEFF}{body}");
        let start = source.find("title").unwrap();
        let edit = format_yaml_range(&source, start, start)
            .unwrap()
            .expect("edit");
        assert_eq!(edit.start, start);
        assert!(source[edit.start..].starts_with("title:"));
        let mut spliced = String::new();
        spliced.push_str(&source[..edit.start]);
        spliced.push_str(&edit.replacement);
        spliced.push_str(&source[edit.end..]);
        assert_eq!(
            spliced,
            format!(
                "\u{FEFF}title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n"
            )
        );
    }

    #[test]
    fn a_canonical_range_returns_none() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let (start, end) = range_of(source, "selection:");
        assert_eq!(apply(source, start, end).unwrap(), None);
    }
}
