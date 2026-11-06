//! Tree-sitter to arena model conversion, value alignment, and refusals.

use std::ops::Range;

use tree_sitter::{Node as TsNode, Point, Tree};

use crate::fmt::{FormatError, MAX_DEPTH};

pub(crate) type NodeId = u32;

/// A path to a node in a document, used by the guard and range formatting.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum PathSeg {
    Key(String),
    Index(usize),
    KeyNode,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Model {
    pub docs: Vec<Doc>,
    pub nodes: Vec<Node>,
    pub raw_comments: Vec<RawComment>,
}

#[derive(Debug, Clone)]
pub(crate) struct Doc {
    #[allow(dead_code)]
    pub span: Range<usize>,
    pub prelude: Vec<PreludeLine>,
    /// Byte offsets of the directive lines in `prelude`, parallel to the
    /// directive entries.
    pub directive_bytes: Vec<usize>,
    #[allow(dead_code)]
    pub explicit_start: bool,
    /// Byte offset and row of the `---` token when one is present.
    pub start_token: Option<(usize, usize)>,
    pub start_comment: Option<Comment>,
    pub header: Vec<Comment>,
    pub root: NodeId,
}

#[derive(Debug, Clone)]
pub(crate) enum PreludeLine {
    Directive(String),
    Comment(Comment),
}

#[derive(Debug, Clone)]
pub(crate) struct Node {
    pub span: Range<usize>,
    pub start: Point,
    pub end: Point,
    pub props: Vec<Prop>,
    pub kind: NodeKind,
}

#[derive(Debug, Clone)]
pub(crate) enum Prop {
    Anchor(String),
    Tag(String),
}

#[derive(Debug, Clone)]
pub(crate) enum NodeKind {
    Map {
        entries: Vec<Entry>,
        flow: bool,
        dangling: Vec<Comment>,
    },
    Seq {
        items: Vec<Item>,
        flow: bool,
        dangling: Vec<Comment>,
    },
    Scalar {
        text: String,
        decoded: Decoded,
        block: bool,
    },
    Alias(String),
    Empty,
}

#[derive(Debug, Clone)]
pub(crate) enum Decoded {
    Str(String),
    Verbatim,
}

#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub key: NodeId,
    pub value: NodeId,
    pub source_index: usize,
    pub leading: Vec<Comment>,
    pub trailing: Option<Comment>,
}

#[derive(Debug, Clone)]
pub(crate) struct Item {
    pub value: NodeId,
    #[allow(dead_code)]
    pub source_index: usize,
    pub leading: Vec<Comment>,
    pub trailing: Option<Comment>,
    /// Byte offset and row of the item's dash, or of its value for flow items.
    pub dash_byte: usize,
    pub dash: Point,
}

#[derive(Debug, Clone)]
pub(crate) struct Comment {
    pub text: String,
    pub byte: usize,
    pub row: usize,
    pub col: usize,
}

pub(crate) type RawComment = Comment;

pub(crate) fn build(
    source: &str,
    tree: &Tree,
    values: &[yaml_serde::Value],
) -> Result<Model, FormatError> {
    let mut builder = Builder {
        source,
        nodes: Vec::new(),
        raw_comments: Vec::new(),
    };
    let root = tree.root_node();
    let documents: Vec<TsNode> = root
        .children(&mut root.walk())
        .filter(|child| child.kind() == "document")
        .collect();
    if documents.len() != values.len() {
        return Err(FormatError::Unsupported {
            line: 1,
            construct: "a document layout the YAML parser reads differently".to_string(),
        });
    }
    let mut docs = Vec::with_capacity(documents.len());
    for (doc, value) in documents.into_iter().zip(values) {
        docs.push(builder.build_document(doc, value)?);
    }
    builder.collect_all_comments(root);
    Ok(Model {
        docs,
        nodes: builder.nodes,
        raw_comments: builder.raw_comments,
    })
}

struct Builder<'a> {
    source: &'a str,
    nodes: Vec<Node>,
    raw_comments: Vec<RawComment>,
}

impl Builder<'_> {
    fn build_document(
        &mut self,
        doc: TsNode<'_>,
        value: &yaml_serde::Value,
    ) -> Result<Doc, FormatError> {
        let mut prelude = Vec::new();
        let mut directive_bytes = Vec::new();
        let mut explicit_start = false;
        let mut start_token = None;
        let mut content = None;
        for child in doc.children(&mut doc.walk()) {
            match child.kind() {
                "comment" => {}
                "yaml_directive" | "tag_directive" | "reserved_directive" => {
                    let text = self.slice(child).trim_end().to_string();
                    directive_bytes.push(child.start_byte());
                    prelude.push(PreludeLine::Directive(text));
                }
                "---" => {
                    explicit_start = true;
                    start_token = Some((child.start_byte(), child.start_position().row));
                }
                "..." => {}
                "block_node" | "flow_node" => content = Some(child),
                _ => {}
            }
        }
        let (root, span) = match content {
            Some(node) => {
                let root = self.build_node(node, value, 0)?;
                (root, node.start_byte()..node.end_byte())
            }
            None => {
                let empty = self.push_node(
                    doc.start_byte()..doc.start_byte(),
                    doc.start_position(),
                    doc.start_position(),
                    Vec::new(),
                    NodeKind::Empty,
                );
                (empty, doc.start_byte()..doc.start_byte())
            }
        };
        Ok(Doc {
            span,
            prelude,
            directive_bytes,
            explicit_start,
            start_token,
            start_comment: None,
            header: Vec::new(),
            root,
        })
    }

    fn build_node(
        &mut self,
        node: TsNode<'_>,
        value: &yaml_serde::Value,
        depth: usize,
    ) -> Result<NodeId, FormatError> {
        match node.kind() {
            "block_node" | "flow_node" => self.build_annotated(node, value, depth),
            "block_mapping" | "flow_mapping" => self.build_mapping(node, value, depth),
            "block_sequence" | "flow_sequence" => self.build_sequence(node, value, depth),
            "block_scalar" | "plain_scalar" | "single_quote_scalar" | "double_quote_scalar" => {
                Ok(self.build_scalar(node, value, node.kind() == "block_scalar"))
            }
            "alias" => {
                let name = node
                    .children(&mut node.walk())
                    .find(|child| child.kind() == "alias_name")
                    .map(|child| self.slice(child).to_string())
                    .unwrap_or_else(|| {
                        let text = self.slice(node);
                        text.strip_prefix('*').unwrap_or(text).to_string()
                    });
                Ok(self.push_node(
                    node.start_byte()..node.end_byte(),
                    node.start_position(),
                    node.end_position(),
                    Vec::new(),
                    NodeKind::Alias(name),
                ))
            }
            other => Err(unsupported(node, format!("unsupported YAML node `{other}`"))),
        }
    }

    fn build_annotated(
        &mut self,
        node: TsNode<'_>,
        value: &yaml_serde::Value,
        depth: usize,
    ) -> Result<NodeId, FormatError> {
        let mut props = Vec::new();
        let mut content = None;
        for child in node.children(&mut node.walk()) {
            match child.kind() {
                "comment" => {}
                "anchor" => props.push(Prop::Anchor(self.anchor_name(child))),
                "tag" => props.push(Prop::Tag(self.slice(child).to_string())),
                _ => content = Some(child),
            }
        }
        match content {
            Some(child) => {
                let id = self.build_node(child, value, depth)?;
                let target = &mut self.nodes[id as usize];
                target.props = props;
                target.span = node.start_byte()..node.end_byte();
                target.start = node.start_position();
                target.end = node.end_position();
                if target.props.iter().any(|prop| matches!(prop, Prop::Tag(_)))
                    && let NodeKind::Scalar { decoded, .. } = &mut target.kind
                {
                    *decoded = Decoded::Verbatim;
                }
                Ok(id)
            }
            None => {
                if !matches!(value, yaml_serde::Value::Null) {
                    return Err(mismatch(node));
                }
                Ok(self.push_node(
                    node.start_byte()..node.end_byte(),
                    node.start_position(),
                    node.end_position(),
                    props,
                    NodeKind::Empty,
                ))
            }
        }
    }

    fn build_mapping(
        &mut self,
        node: TsNode<'_>,
        value: &yaml_serde::Value,
        depth: usize,
    ) -> Result<NodeId, FormatError> {
        let flow = node.kind() == "flow_mapping";
        if depth >= MAX_DEPTH {
            return Err(unsupported(
                node,
                "nesting deeper than 64 levels".to_string(),
            ));
        }
        if flow && contains_comment(node) {
            return Err(unsupported(
                node,
                "comment inside a flow collection".to_string(),
            ));
        }
        let mapping = match value {
            yaml_serde::Value::Mapping(mapping) => mapping,
            yaml_serde::Value::Tagged(tagged) => match &tagged.value {
                yaml_serde::Value::Mapping(mapping) => mapping,
                _ => return Err(mismatch(node)),
            },
            _ => return Err(mismatch(node)),
        };
        let mut pairs: Vec<TsNode> = Vec::new();
        let mut bare_keys: Vec<TsNode> = Vec::new();
        for child in node.children(&mut node.walk()) {
            match child.kind() {
                "comment" => {}
                "block_mapping_pair" | "flow_pair" => pairs.push(child),
                _ if child.is_named() => bare_keys.push(child),
                _ => {}
            }
        }
        let total = pairs.len() + bare_keys.len();
        if total != mapping.len() {
            return Err(mismatch(node));
        }
        let mut entries = Vec::with_capacity(total);
        let mut source_index = 0;
        let mut key_iter = mapping.iter();
        for pair in pairs {
            let (key_value, value_value) = key_iter.next().ok_or_else(|| mismatch(pair))?;
            if pair
                .children(&mut pair.walk())
                .any(|child| child.kind() == "?")
            {
                return Err(unsupported(
                    pair,
                    "explicit or empty mapping key".to_string(),
                ));
            }
            let key_node = pair
                .child_by_field_name("key")
                .ok_or_else(|| unsupported(pair, "explicit or empty mapping key".to_string()))?;
            let key = self.build_node(key_node, key_value, depth + 1)?;
            let value_node = match pair.child_by_field_name("value") {
                Some(value_node) => self.build_node(value_node, value_value, depth + 1)?,
                None => {
                    if !matches!(value_value, yaml_serde::Value::Null) {
                        return Err(mismatch(pair));
                    }
                    self.empty_at(key_node.end_byte(), key_node.end_position())
                }
            };
            entries.push(Entry {
                key,
                value: value_node,
                source_index,
                leading: Vec::new(),
                trailing: None,
            });
            source_index += 1;
        }
        for bare in bare_keys {
            let (key_value, value_value) = key_iter.next().ok_or_else(|| mismatch(bare))?;
            let key = self.build_node(bare, key_value, depth + 1)?;
            let value = if matches!(value_value, yaml_serde::Value::Null) {
                self.empty_at(bare.end_byte(), bare.end_position())
            } else {
                return Err(mismatch(bare));
            };
            entries.push(Entry {
                key,
                value,
                source_index,
                leading: Vec::new(),
                trailing: None,
            });
            source_index += 1;
        }
        Ok(self.push_node(
            node.start_byte()..node.end_byte(),
            node.start_position(),
            node.end_position(),
            Vec::new(),
            NodeKind::Map {
                entries,
                flow,
                dangling: Vec::new(),
            },
        ))
    }

    fn build_sequence(
        &mut self,
        node: TsNode<'_>,
        value: &yaml_serde::Value,
        depth: usize,
    ) -> Result<NodeId, FormatError> {
        let flow = node.kind() == "flow_sequence";
        if depth >= MAX_DEPTH {
            return Err(unsupported(
                node,
                "nesting deeper than 64 levels".to_string(),
            ));
        }
        if flow && contains_comment(node) {
            return Err(unsupported(
                node,
                "comment inside a flow collection".to_string(),
            ));
        }
        let sequence = match value {
            yaml_serde::Value::Sequence(sequence) => sequence,
            yaml_serde::Value::Tagged(tagged) => match &tagged.value {
                yaml_serde::Value::Sequence(sequence) => sequence,
                _ => return Err(mismatch(node)),
            },
            _ => return Err(mismatch(node)),
        };
        let mut children: Vec<TsNode> = Vec::new();
        for child in node.children(&mut node.walk()) {
            match child.kind() {
                "comment" => {}
                "block_sequence_item" => children.push(child),
                _ if child.is_named() => children.push(child),
                _ => {}
            }
        }
        if children.len() != sequence.len() {
            return Err(mismatch(node));
        }
        let mut items = Vec::with_capacity(children.len());
        for (source_index, child) in children.into_iter().enumerate() {
            let value = &sequence[source_index];
            let (item_value, dash, dash_byte) = if child.kind() == "block_sequence_item" {
                let content = child
                    .children(&mut child.walk())
                    .find(|c| c.kind() == "block_node" || c.kind() == "flow_node");
                let item_value = match content {
                    Some(content) => self.build_node(content, value, depth + 1)?,
                    None => {
                        if !matches!(value, yaml_serde::Value::Null) {
                            return Err(mismatch(child));
                        }
                        self.empty_at(child.start_byte(), child.start_position())
                    }
                };
                (item_value, child.start_position(), child.start_byte())
            } else if child.kind() == "flow_pair" {
                (
                    self.build_flow_pair_item(child, value, depth + 1)?,
                    child.start_position(),
                    child.start_byte(),
                )
            } else {
                (
                    self.build_node(child, value, depth + 1)?,
                    child.start_position(),
                    child.start_byte(),
                )
            };
            items.push(Item {
                value: item_value,
                source_index,
                leading: Vec::new(),
                trailing: None,
                dash,
                dash_byte,
            });
        }
        Ok(self.push_node(
            node.start_byte()..node.end_byte(),
            node.start_position(),
            node.end_position(),
            Vec::new(),
            NodeKind::Seq {
                items,
                flow,
                dangling: Vec::new(),
            },
        ))
    }

    /// A `flow_pair` inside a flow sequence is a one-entry block mapping.
    fn build_flow_pair_item(
        &mut self,
        pair: TsNode<'_>,
        value: &yaml_serde::Value,
        depth: usize,
    ) -> Result<NodeId, FormatError> {
        let mapping = match value {
            yaml_serde::Value::Mapping(mapping) => mapping,
            yaml_serde::Value::Tagged(tagged) => match &tagged.value {
                yaml_serde::Value::Mapping(mapping) => mapping,
                _ => return Err(mismatch(pair)),
            },
            _ => return Err(mismatch(pair)),
        };
        if mapping.len() != 1 {
            return Err(mismatch(pair));
        }
        if pair
            .children(&mut pair.walk())
            .any(|child| child.kind() == "?")
        {
            return Err(unsupported(
                pair,
                "explicit or empty mapping key".to_string(),
            ));
        }
        let (key_value, value_value) = mapping.iter().next().ok_or_else(|| mismatch(pair))?;
        let key_node = pair
            .child_by_field_name("key")
            .ok_or_else(|| unsupported(pair, "explicit or empty mapping key".to_string()))?;
        let key = self.build_node(key_node, key_value, depth + 1)?;
        let value_node = match pair.child_by_field_name("value") {
            Some(value_node) => self.build_node(value_node, value_value, depth + 1)?,
            None => {
                if !matches!(value_value, yaml_serde::Value::Null) {
                    return Err(mismatch(pair));
                }
                self.empty_at(key_node.end_byte(), key_node.end_position())
            }
        };
        let entry = Entry {
            key,
            value: value_node,
            source_index: 0,
            leading: Vec::new(),
            trailing: None,
        };
        Ok(self.push_node(
            pair.start_byte()..pair.end_byte(),
            pair.start_position(),
            pair.end_position(),
            Vec::new(),
            NodeKind::Map {
                entries: vec![entry],
                flow: false,
                dangling: Vec::new(),
            },
        ))
    }

    fn build_scalar(
        &mut self,
        node: TsNode<'_>,
        value: &yaml_serde::Value,
        block: bool,
    ) -> NodeId {
        let text = self.slice(node).to_string();
        let decoded = match value {
            yaml_serde::Value::String(s) => Decoded::Str(s.clone()),
            _ => Decoded::Verbatim,
        };
        self.push_node(
            node.start_byte()..node.end_byte(),
            node.start_position(),
            node.end_position(),
            Vec::new(),
            NodeKind::Scalar {
                text,
                decoded,
                block,
            },
        )
    }

    fn empty_at(&mut self, byte: usize, point: Point) -> NodeId {
        self.push_node(
            byte..byte,
            point,
            point,
            Vec::new(),
            NodeKind::Empty,
        )
    }

    fn push_node(
        &mut self,
        span: Range<usize>,
        start: Point,
        end: Point,
        props: Vec<Prop>,
        kind: NodeKind,
    ) -> NodeId {
        let id = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
        self.nodes.push(Node {
            span,
            start,
            end,
            props,
            kind,
        });
        id
    }

    fn collect_all_comments(&mut self, node: TsNode<'_>) {
        if node.kind() == "comment" {
            let text = self.slice(node).trim_end().to_string();
            let start = node.start_position();
            self.raw_comments.push(Comment {
                text,
                byte: node.start_byte(),
                row: start.row,
                col: start.column,
            });
        }
        for child in node.children(&mut node.walk()) {
            self.collect_all_comments(child);
        }
    }

    fn anchor_name(&self, anchor: TsNode<'_>) -> String {
        anchor
            .child_by_field_name("anchor_name")
            .map(|child| self.slice(child).to_string())
            .unwrap_or_else(|| {
                let text = self.slice(anchor);
                text.strip_prefix('&').unwrap_or(text).to_string()
            })
    }

    fn slice(&self, node: TsNode<'_>) -> &str {
        &self.source[node.start_byte()..node.end_byte()]
    }
}

fn mismatch(node: TsNode<'_>) -> FormatError {
    unsupported(node, "a node the YAML parser reads differently".to_string())
}

fn unsupported(node: TsNode<'_>, construct: String) -> FormatError {
    FormatError::Unsupported {
        line: node.start_position().row + 1,
        construct,
    }
}

fn contains_comment(node: TsNode<'_>) -> bool {
    if node.kind() == "comment" {
        return true;
    }
    node.children(&mut node.walk()).any(contains_comment)
}

/// The decoded key string of a key node, or its verbatim source text when the
/// key is not a string.
pub(crate) fn key_string(model: &Model, key: NodeId) -> String {
    match &model.nodes[key as usize].kind {
        NodeKind::Scalar {
            decoded: Decoded::Str(s),
            ..
        } => s.clone(),
        NodeKind::Scalar { text, .. } => text.clone(),
        NodeKind::Alias(name) => format!("*{name}"),
        _ => String::new(),
    }
}

/// The indentation (child column) of a mapping or sequence, in bytes.
pub(crate) fn child_column(model: &Model, id: NodeId) -> usize {
    match &model.nodes[id as usize].kind {
        NodeKind::Map { entries, .. } => entries
            .first()
            .map(|entry| model.nodes[entry.key as usize].start.column)
            .unwrap_or(0),
        NodeKind::Seq { items, .. } => items.first().map(|item| item.dash.column).unwrap_or(0),
        _ => 0,
    }
}

