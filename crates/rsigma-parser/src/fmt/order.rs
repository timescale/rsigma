//! Canonical mapping order with an anchor-binding fallback.

use std::collections::{BTreeMap, HashMap};

use crate::fmt::context::{DocKind, MapCtx, map_ctx};
use crate::fmt::cst::{Model, NodeId, NodeKind, PathSeg, Prop, key_string};
use crate::style::{
    COMMON_ROOT, CORRELATION_BODY, CORRELATION_ROOT, DETECTION_ROOT, FILTER_ROOT, LOGSOURCE,
    RELATED_ITEM, RSIGMA_ORDER,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct Plan {
    pub maps: HashMap<NodeId, Vec<usize>>,
}

impl Plan {
    pub(crate) fn order(&self, id: NodeId, len: usize) -> Vec<usize> {
        self.maps
            .get(&id)
            .cloned()
            .unwrap_or_else(|| (0..len).collect())
    }
}

#[derive(Debug, Clone)]
struct MapInfo {
    id: NodeId,
    ctx: MapCtx,
    start_byte: usize,
}

pub(crate) fn plan(model: &Model, kinds: &[DocKind]) -> Plan {
    let mut result = Plan::default();
    let mut maps_by_doc: Vec<Vec<MapInfo>> = vec![Vec::new(); model.docs.len()];
    for (doc, document) in model.docs.iter().enumerate() {
        collect_maps(
            model,
            kinds.get(doc).copied().unwrap_or(DocKind::Common),
            document.root,
            Vec::new(),
            &mut maps_by_doc[doc],
        );
    }
    for (doc, mut maps) in maps_by_doc.into_iter().enumerate() {
        maps.sort_by_key(|info| info.start_byte);
        let has_alias = document_has_alias(model, model.docs[doc].root);
        if !has_alias {
            for info in maps {
                let order = permutation(model, info.id, info.ctx);
                if order
                    .iter()
                    .enumerate()
                    .any(|(index, value)| index != *value)
                {
                    result.maps.insert(info.id, order);
                }
            }
            continue;
        }
        let source_bindings = bindings(model, None, model.docs[doc].root);
        let Some(source_bindings) = source_bindings else {
            continue;
        };
        for info in maps {
            let order = permutation(model, info.id, info.ctx);
            if order
                .iter()
                .enumerate()
                .all(|(index, value)| index == *value)
            {
                continue;
            }
            result.maps.insert(info.id, order);
            let planned = bindings(model, Some(&result), model.docs[doc].root);
            if planned.as_ref() != Some(&source_bindings) {
                result.maps.remove(&info.id);
            }
        }
    }
    result
}

fn collect_maps(
    model: &Model,
    kind: DocKind,
    id: NodeId,
    path: Vec<PathSeg>,
    out: &mut Vec<MapInfo>,
) {
    let node = &model.nodes[id as usize];
    match &node.kind {
        NodeKind::Map { entries, .. } => {
            out.push(MapInfo {
                id,
                ctx: map_ctx(kind, &path),
                start_byte: node.span.start,
            });
            for entry in entries {
                let mut entry_path = path.clone();
                entry_path.push(PathSeg::Key(key_string(model, entry.key)));
                collect_maps(model, kind, entry.value, entry_path, out);
            }
        }
        NodeKind::Seq { items, .. } => {
            for (index, item) in items.iter().enumerate() {
                let mut item_path = path.clone();
                item_path.push(PathSeg::Index(index));
                collect_maps(model, kind, item.value, item_path, out);
            }
        }
        _ => {}
    }
}

fn permutation(model: &Model, id: NodeId, ctx: MapCtx) -> Vec<usize> {
    let NodeKind::Map { entries, .. } = &model.nodes[id as usize].kind else {
        return Vec::new();
    };
    match ctx {
        MapCtx::Root(kind) => {
            let table = match kind {
                DocKind::Detection => DETECTION_ROOT,
                DocKind::Correlation => CORRELATION_ROOT,
                DocKind::Filter => FILTER_ROOT,
                DocKind::Common | DocKind::Reset => COMMON_ROOT,
            };
            let mut ranked: Vec<(usize, usize, usize)> = Vec::with_capacity(entries.len());
            for (index, entry) in entries.iter().enumerate() {
                let key = key_string(model, entry.key);
                let rank = if key == "action" {
                    (0, 0)
                } else if let Some(position) = table.iter().position(|candidate| *candidate == key)
                {
                    (1, position)
                } else if let Some(position) =
                    RSIGMA_ORDER.iter().position(|candidate| *candidate == key)
                {
                    (2, position)
                } else {
                    (3, entry.source_index)
                };
                ranked.push((rank.0, rank.1, index));
            }
            ranked.sort_by_key(|&(first, second, _)| (first, second));
            ranked.into_iter().map(|(_, _, index)| index).collect()
        }
        MapCtx::Logsource => table_permutation(model, entries, LOGSOURCE),
        MapCtx::CorrelationBody => table_permutation(model, entries, CORRELATION_BODY),
        MapCtx::RelatedItem => table_permutation(model, entries, RELATED_ITEM),
        MapCtx::Detection => {
            let mut ranked: Vec<(usize, usize, usize)> = entries
                .iter()
                .enumerate()
                .map(|(index, entry)| {
                    let key = key_string(model, entry.key);
                    let rank = match key.as_str() {
                        "condition" => (2, 0),
                        "timeframe" => (1, 0),
                        _ => (0, entry.source_index),
                    };
                    (rank.0, rank.1, index)
                })
                .collect();
            ranked.sort_by_key(|&(first, second, _)| (first, second));
            ranked.into_iter().map(|(_, _, index)| index).collect()
        }
        MapCtx::FilterBody => {
            let mut ranked: Vec<(usize, usize, usize)> = entries
                .iter()
                .enumerate()
                .map(|(index, entry)| {
                    let key = key_string(model, entry.key);
                    let rank = match key.as_str() {
                        "rules" => (0, 0),
                        "condition" => (2, 0),
                        _ => (1, entry.source_index),
                    };
                    (rank.0, rank.1, index)
                })
                .collect();
            ranked.sort_by_key(|&(first, second, _)| (first, second));
            ranked.into_iter().map(|(_, _, index)| index).collect()
        }
        MapCtx::Selection | MapCtx::Other => (0..entries.len()).collect(),
    }
}

fn table_permutation(
    model: &Model,
    entries: &[crate::fmt::cst::Entry],
    table: &[&str],
) -> Vec<usize> {
    let mut ranked: Vec<(usize, usize, usize)> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let key = key_string(model, entry.key);
            match table.iter().position(|candidate| *candidate == key) {
                Some(position) => (0, position, index),
                None => (1, entry.source_index, index),
            }
        })
        .collect();
    ranked.sort_by_key(|&(first, second, _)| (first, second));
    ranked.into_iter().map(|(_, _, index)| index).collect()
}

fn document_has_alias(model: &Model, id: NodeId) -> bool {
    match &model.nodes[id as usize].kind {
        NodeKind::Alias(_) => true,
        NodeKind::Map { entries, .. } => entries.iter().any(|entry| {
            document_has_alias(model, entry.value) || document_has_alias(model, entry.key)
        }),
        NodeKind::Seq { items, .. } => items
            .iter()
            .any(|item| document_has_alias(model, item.value)),
        _ => false,
    }
}

pub(crate) fn bindings(
    model: &Model,
    plan: Option<&Plan>,
    root: NodeId,
) -> Option<BTreeMap<Vec<PathSeg>, Vec<PathSeg>>> {
    let mut anchors: HashMap<String, Vec<PathSeg>> = HashMap::new();
    let mut result = BTreeMap::new();
    traverse_bindings(model, plan, root, Vec::new(), &mut anchors, &mut result)?;
    Some(result)
}

fn traverse_bindings(
    model: &Model,
    plan: Option<&Plan>,
    id: NodeId,
    path: Vec<PathSeg>,
    anchors: &mut HashMap<String, Vec<PathSeg>>,
    result: &mut BTreeMap<Vec<PathSeg>, Vec<PathSeg>>,
) -> Option<()> {
    let node = &model.nodes[id as usize];
    for prop in &node.props {
        if let Prop::Anchor(name) = prop {
            anchors.insert(name.clone(), path.clone());
        }
    }
    match &node.kind {
        NodeKind::Alias(name) => {
            let anchor = anchors.get(name)?;
            result.insert(path, anchor.clone());
        }
        NodeKind::Map { entries, .. } => {
            let order = plan.map_or_else(
                || (0..entries.len()).collect::<Vec<_>>(),
                |plan| plan.order(id, entries.len()),
            );
            for index in order {
                let entry = &entries[index];
                let mut entry_path = path.clone();
                entry_path.push(PathSeg::Key(key_string(model, entry.key)));
                let mut key_path = entry_path.clone();
                key_path.push(PathSeg::KeyNode);
                traverse_key(model, entry.key, key_path, anchors, result)?;
                traverse_bindings(model, plan, entry.value, entry_path, anchors, result)?;
            }
        }
        NodeKind::Seq { items, .. } => {
            for (index, item) in items.iter().enumerate() {
                let mut item_path = path.clone();
                item_path.push(PathSeg::Index(index));
                traverse_bindings(model, plan, item.value, item_path, anchors, result)?;
            }
        }
        _ => {}
    }
    Some(())
}

fn traverse_key(
    model: &Model,
    id: NodeId,
    path: Vec<PathSeg>,
    anchors: &mut HashMap<String, Vec<PathSeg>>,
    result: &mut BTreeMap<Vec<PathSeg>, Vec<PathSeg>>,
) -> Option<()> {
    let node = &model.nodes[id as usize];
    for prop in &node.props {
        if let Prop::Anchor(name) = prop {
            anchors.insert(name.clone(), path.clone());
        }
    }
    if let NodeKind::Alias(name) = &node.kind {
        let anchor = anchors.get(name)?;
        result.insert(path, anchor.clone());
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fmt::classify;
    use crate::fmt::cst;

    fn model(source: &str) -> Model {
        let mut parser = tree_sitter::Parser::new();
        let language: tree_sitter::Language = tree_sitter_yaml::LANGUAGE.into();
        parser.set_language(&language).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let values: Vec<yaml_serde::Value> = yaml_serde::Deserializer::from_str(source)
            .map(|doc| yaml_serde::Value::deserialize(doc).unwrap())
            .collect();
        cst::build(source, &tree, &values).unwrap()
    }

    use serde::Deserialize;

    fn keys(model: &Model, id: NodeId, plan: &Plan) -> Vec<String> {
        let NodeKind::Map { entries, .. } = &model.nodes[id as usize].kind else {
            return Vec::new();
        };
        plan.order(id, entries.len())
            .into_iter()
            .map(|index| key_string(model, entries[index].key))
            .collect()
    }

    #[test]
    fn root_order_puts_action_first() {
        let source = "action: global\ntitle: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let model = model(source);
        let plan = plan(&model, &[DocKind::Detection]);
        let root = model.docs[0].root;
        let keys = keys(&model, root, &plan);
        assert_eq!(keys[0], "action");
        assert_eq!(keys[1], "title");
    }

    #[test]
    fn detection_order_puts_condition_last() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    condition: selection\n    timeframe: 5m\n    selection:\n        Field: value\n";
        let model = model(source);
        let kinds = classify::classify(
            &yaml_serde::Deserializer::from_str(source)
                .map(|doc| yaml_serde::Value::deserialize(doc).unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let plan = plan(&model, &kinds);
        let root = model.docs[0].root;
        let NodeKind::Map { entries, .. } = &model.nodes[root as usize].kind else {
            panic!()
        };
        let detection = entries
            .iter()
            .find(|entry| key_string(&model, entry.key) == "detection")
            .unwrap()
            .value;
        assert_eq!(
            keys(&model, detection, &plan),
            ["selection", "timeframe", "condition"]
        );
    }

    #[test]
    fn selection_order_is_kept() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        B: 2\n        A: 1\n    condition: selection\n";
        let model = model(source);
        let kinds = classify::classify(
            &yaml_serde::Deserializer::from_str(source)
                .map(|doc| yaml_serde::Value::deserialize(doc).unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let plan = plan(&model, &kinds);
        let root = model.docs[0].root;
        let NodeKind::Map { entries, .. } = &model.nodes[root as usize].kind else {
            panic!()
        };
        let detection = entries
            .iter()
            .find(|entry| key_string(&model, entry.key) == "detection")
            .unwrap()
            .value;
        let NodeKind::Map { entries, .. } = &model.nodes[detection as usize].kind else {
            panic!()
        };
        let selection = entries
            .iter()
            .find(|entry| key_string(&model, entry.key) == "selection")
            .unwrap()
            .value;
        assert_eq!(keys(&model, selection, &plan), ["B", "A"]);
    }

    #[test]
    fn anchor_fallback_keeps_source_order() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection: &base\n        Field: value\n    condition: selection\ncustom: *base\n";
        let model = model(source);
        let kinds = classify::classify(
            &yaml_serde::Deserializer::from_str(source)
                .map(|doc| yaml_serde::Value::deserialize(doc).unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let plan = plan(&model, &kinds);
        let root = model.docs[0].root;
        let keys = keys(&model, root, &plan);
        assert_eq!(keys.last().map(String::as_str), Some("custom"));
    }
}
