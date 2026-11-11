//! Comment-preserving formatter for Sigma YAML.
//!
//! [`format_yaml`] rewrites a Sigma file into the canonical layout that
//! [`emit_rule_yaml`](crate::emit_rule_yaml) produces, keeping comments,
//! anchors, aliases, tags, and directives. Every result is checked against the
//! source: the YAML values, the parsed Sigma rules, and the attachment of every
//! comment must be unchanged, or the call fails with [`FormatError::Guard`].

use serde::Deserialize;
use tree_sitter::Tree;

use crate::diagnostic::DiagnosticSeverity;
use crate::fmt::context::DocKind;
use crate::parser::parse_sigma_yaml;

pub(crate) mod classify;
pub(crate) mod comments;
pub(crate) mod context;
pub(crate) mod cst;
pub(crate) mod guard;
pub(crate) mod order;
pub(crate) mod range;
pub(crate) mod render;

pub use range::{RangeEdit, format_yaml_range};

/// The deepest collection nesting the formatter accepts.
pub(crate) const MAX_DEPTH: usize = 64;

/// The result of formatting a whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FormatOutcome {
    /// The canonical text. Always ends with exactly one `\n`.
    pub formatted: String,
    /// True when `formatted` differs from the source bytes.
    pub changed: bool,
}

/// Why a file could not be formatted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FormatError {
    /// The source is not valid YAML. `line` and `column` are 1-based.
    #[error("YAML syntax error at line {line}, column {column}: {message}")]
    Yaml {
        line: usize,
        column: usize,
        message: String,
    },
    /// A document is not a Sigma document, so the whole file is left alone.
    /// `document` is zero-based.
    #[error("document {} is not a Sigma rule document: {reason}", .document + 1)]
    NotSigma { document: usize, reason: String },
    /// The file looks like Sigma but the parser reports an error.
    #[error("invalid Sigma{}: {message}", .document.map(|d| format!(" in document {}", d + 1)).unwrap_or_default())]
    InvalidSigma {
        document: Option<usize>,
        message: String,
    },
    /// Valid YAML that the formatter cannot lay out safely. `line` is 1-based.
    #[error("unsupported YAML at line {line}: {construct}")]
    Unsupported { line: usize, construct: String },
    /// The formatted text would change the meaning of the file.
    #[error("formatting would change the rule: {0}")]
    Guard(String),
    /// The requested range cannot be formatted on its own.
    #[error("the range cannot be formatted: {0}")]
    Range(String),
}

/// Format a whole Sigma YAML file.
///
/// The output uses the same canonical layout as
/// [`emit_rule_yaml`](crate::emit_rule_yaml): four-space indentation, canonical
/// key order, block collections, and canonical scalar quoting. Comments move
/// with the entries they are attached to.
///
/// ```
/// use rsigma_parser::format_yaml;
///
/// let source = "title: Test\n# note\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";
/// let outcome = format_yaml(source).unwrap();
/// assert!(outcome.formatted.contains("\n    category: test\n"));
/// assert_eq!(
///     outcome.formatted,
///     "title: Test\n# note\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n",
/// );
/// ```
pub fn format_yaml(source: &str) -> Result<FormatOutcome, FormatError> {
    let prepared = prepare(source)?;
    let formatted = prepared.rendered.text.clone();
    let changed = formatted != source;
    if !changed {
        return Ok(FormatOutcome {
            formatted,
            changed: false,
        });
    }
    let before = prepared.before();
    guard::check(&before, &formatted)?;
    Ok(FormatOutcome {
        formatted,
        changed: true,
    })
}

/// The source-derived state shared by whole-file and range formatting.
pub(crate) struct Prepared {
    pub model: cst::Model,
    pub kinds: Vec<DocKind>,
    pub collection: crate::SigmaCollection,
    pub values: Vec<yaml_serde::Value>,
    pub fingerprint: Vec<String>,
    pub rendered: render::Render,
    pub had_bom: bool,
}

impl Prepared {
    pub(crate) fn before(&self) -> guard::Before<'_> {
        guard::Before {
            values: &self.values,
            collection: &self.collection,
            fingerprint: self.fingerprint.clone(),
            kinds: &self.kinds,
        }
    }
}

/// Run the formatter pipeline up to (and including) rendering.
pub(crate) fn prepare(source: &str) -> Result<Prepared, FormatError> {
    let (stripped, had_bom) = match source.strip_prefix('\u{FEFF}') {
        Some(rest) => (rest, true),
        None => (source, false),
    };
    let tree = parse_tree(stripped)?;
    if tree.root_node().has_error() {
        let (line, column, message) = error_position(&tree);
        return Err(FormatError::Yaml {
            line,
            column,
            message,
        });
    }
    let values = deserialize_values(stripped)?;
    if values.is_empty() || document_count(&tree) == 0 {
        return Err(FormatError::NotSigma {
            document: 0,
            reason: "the file contains no YAML documents".to_string(),
        });
    }
    let kinds = classify::classify(&values)?;
    let collection = parse_sigma_yaml(stripped).map_err(|error| FormatError::InvalidSigma {
        document: None,
        message: error.to_string(),
    })?;
    if let Some(diagnostic) = collection
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        return Err(FormatError::InvalidSigma {
            document: diagnostic.document,
            message: diagnostic.message.clone(),
        });
    }
    let mut model = cst::build(stripped, &tree, &values)?;
    comments::attach(&mut model, stripped)?;
    let plan = order::plan(&model, &kinds);
    let fingerprint = guard::fingerprint(&model, &kinds, &plan);
    let rendered = render::render(&model, &kinds, &plan);
    let cap = stripped.len().saturating_mul(16).saturating_add(4096);
    if rendered.text.len() > cap {
        return Err(FormatError::Unsupported {
            line: 1,
            construct: "formatted output would be more than 16 times the input size".to_string(),
        });
    }
    Ok(Prepared {
        model,
        kinds,
        collection,
        values,
        fingerprint,
        rendered,
        had_bom,
    })
}

fn document_count(tree: &Tree) -> usize {
    let root = tree.root_node();
    root.children(&mut root.walk())
        .filter(|child| child.kind() == "document")
        .count()
}

pub(crate) fn parse_tree(source: &str) -> Result<Tree, FormatError> {
    let mut parser = tree_sitter::Parser::new();
    let language: tree_sitter::Language = tree_sitter_yaml::LANGUAGE.into();
    parser
        .set_language(&language)
        .map_err(|_| FormatError::Yaml {
            line: 1,
            column: 1,
            message: "could not load the YAML grammar".to_string(),
        })?;
    parser.parse(source, None).ok_or_else(|| FormatError::Yaml {
        line: 1,
        column: 1,
        message: "syntax error".to_string(),
    })
}

pub(crate) fn deserialize_values(source: &str) -> Result<Vec<yaml_serde::Value>, FormatError> {
    let mut values = Vec::new();
    for document in yaml_serde::Deserializer::from_str(source) {
        match yaml_serde::Value::deserialize(document) {
            Ok(value) => values.push(value),
            Err(error) => {
                let (line, column) = error
                    .location()
                    .map(|location| (location.line(), location.column()))
                    .unwrap_or((1, 1));
                return Err(FormatError::Yaml {
                    line,
                    column,
                    message: error.to_string(),
                });
            }
        }
    }
    Ok(values)
}

fn error_position(tree: &Tree) -> (usize, usize, String) {
    if let Some((node, missing)) = first_error(tree.root_node()) {
        let position = node.start_position();
        let message = if missing {
            format!("missing {}", node.kind())
        } else {
            "syntax error".to_string()
        };
        return (position.row + 1, position.column + 1, message);
    }
    (1, 1, "syntax error".to_string())
}

fn first_error(node: tree_sitter::Node<'_>) -> Option<(tree_sitter::Node<'_>, bool)> {
    if node.is_error() {
        return Some((node, false));
    }
    if node.is_missing() {
        return Some((node, true));
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = first_error(child) {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_yaml_syntax_position() {
        let error = format_yaml("title: [unclosed\n").unwrap_err();
        assert!(matches!(error, FormatError::Yaml { line: 1, .. }));
    }

    #[test]
    fn drops_bom() {
        let source = "\u{FEFF}title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let outcome = format_yaml(source).unwrap();
        assert!(outcome.changed);
        assert!(outcome.formatted.starts_with("title: Test\n"));
    }

    #[test]
    fn unchanged_canonical_input_is_not_changed() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let outcome = format_yaml(source).unwrap();
        assert!(!outcome.changed);
        assert_eq!(outcome.formatted, source);
    }
}
