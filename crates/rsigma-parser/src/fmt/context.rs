//! Map and scalar contexts from the document kind and path.

use crate::fmt::cst::PathSeg;
use crate::style::{KeyCtx, ScalarCtx};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DocKind {
    Detection,
    Correlation,
    Filter,
    Common,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MapCtx {
    Root(DocKind),
    Logsource,
    Detection,
    CorrelationBody,
    FilterBody,
    RelatedItem,
    Selection,
    Other,
}

pub(crate) fn map_ctx(kind: DocKind, path: &[PathSeg]) -> MapCtx {
    if path.is_empty() {
        return MapCtx::Root(kind);
    }
    if is_key(path, "logsource") && path.len() == 1 {
        return MapCtx::Logsource;
    }
    if is_key(path, "detection") && path.len() == 1 {
        return MapCtx::Detection;
    }
    if is_key(path, "correlation") && path.len() == 1 {
        return MapCtx::CorrelationBody;
    }
    if is_key(path, "filter") && path.len() == 1 {
        return MapCtx::FilterBody;
    }
    if let [PathSeg::Key(key), PathSeg::Index(_)] = path
        && key == "related"
    {
        return MapCtx::RelatedItem;
    }
    if let [PathSeg::Key(root), PathSeg::Key(id), ..] = path
        && root == "detection"
        && id != "condition"
        && id != "timeframe"
    {
        return MapCtx::Selection;
    }
    if let [PathSeg::Key(root), PathSeg::Key(id), ..] = path
        && root == "filter"
        && id != "rules"
        && id != "condition"
    {
        return MapCtx::Selection;
    }
    MapCtx::Other
}

pub(crate) fn key_ctx(ctx: MapCtx) -> KeyCtx {
    match ctx {
        MapCtx::Selection => KeyCtx::FieldKey,
        _ => KeyCtx::Key,
    }
}

pub(crate) fn scalar_ctx(path: &[PathSeg]) -> ScalarCtx {
    match path {
        [PathSeg::Key(key)] if matches!(key.as_str(), "title" | "description" | "author" | "license") => {
            ScalarCtx::Prose
        }
        [PathSeg::Key(key), PathSeg::Key(name)] if key == "logsource" && name == "definition" => {
            ScalarCtx::Prose
        }
        [PathSeg::Key(key), PathSeg::Index(_)]
            if matches!(
                key.as_str(),
                "references" | "tags" | "falsepositives" | "fields" | "scope"
            ) =>
        {
            ScalarCtx::Prose
        }
        [PathSeg::Key(key), PathSeg::Key(name)] if key == "correlation" && name == "condition" => {
            ScalarCtx::Condition
        }
        _ if is_condition_path(path) => ScalarCtx::Condition,
        _ => ScalarCtx::Value,
    }
}

fn is_condition_path(path: &[PathSeg]) -> bool {
    let Some(PathSeg::Key(root)) = path.first() else {
        return false;
    };
    if root != "detection" && root != "filter" {
        return false;
    }
    path.iter()
        .skip(1)
        .any(|segment| matches!(segment, PathSeg::Key(key) if key == "condition"))
}

fn is_key(path: &[PathSeg], key: &str) -> bool {
    matches!(path.first(), Some(PathSeg::Key(name)) if name == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: &str) -> PathSeg {
        PathSeg::Key(value.to_string())
    }

    #[test]
    fn root_context() {
        assert_eq!(map_ctx(DocKind::Detection, &[]), MapCtx::Root(DocKind::Detection));
    }

    #[test]
    fn section_contexts() {
        assert_eq!(map_ctx(DocKind::Detection, &[key("logsource")]), MapCtx::Logsource);
        assert_eq!(map_ctx(DocKind::Detection, &[key("detection")]), MapCtx::Detection);
        assert_eq!(map_ctx(DocKind::Correlation, &[key("correlation")]), MapCtx::CorrelationBody);
        assert_eq!(map_ctx(DocKind::Filter, &[key("filter")]), MapCtx::FilterBody);
        assert_eq!(
            map_ctx(DocKind::Detection, &[key("related"), PathSeg::Index(0)]),
            MapCtx::RelatedItem
        );
    }

    #[test]
    fn selection_context() {
        assert_eq!(
            map_ctx(DocKind::Detection, &[key("detection"), key("selection")]),
            MapCtx::Selection
        );
        assert_eq!(
            map_ctx(
                DocKind::Detection,
                &[key("detection"), key("selection"), key("Field")]
            ),
            MapCtx::Selection
        );
        assert_eq!(
            map_ctx(DocKind::Filter, &[key("filter"), key("filter_main")]),
            MapCtx::Selection
        );
    }

    #[test]
    fn scalar_contexts() {
        assert_eq!(scalar_ctx(&[key("title")]), ScalarCtx::Prose);
        assert_eq!(scalar_ctx(&[key("references"), PathSeg::Index(0)]), ScalarCtx::Prose);
        assert_eq!(
            scalar_ctx(&[key("detection"), key("condition")]),
            ScalarCtx::Condition
        );
        assert_eq!(
            scalar_ctx(&[
                key("detection"),
                key("selection"),
                key("Field")
            ]),
            ScalarCtx::Value
        );
        assert_eq!(
            scalar_ctx(&[key("correlation"), key("condition")]),
            ScalarCtx::Condition
        );
    }
}
