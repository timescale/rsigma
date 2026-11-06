//! LSP formatting and range formatting backed by the parser's formatter.

use tower_lsp_server::ls_types::{MessageType, Position, Range, TextEdit};

use rsigma_parser::{FormatError, format_yaml, format_yaml_range};

use crate::position::LineIndex;

#[derive(Debug)]
pub(crate) enum Outcome {
    Edits(Vec<TextEdit>),
    Declined {
        message: String,
        level: MessageType,
        show: bool,
    },
}

pub(crate) fn document_edits(text: &str) -> Outcome {
    match format_yaml(text) {
        Ok(outcome) => {
            if !outcome.changed {
                return Outcome::Edits(Vec::new());
            }
            let index = LineIndex::new(text);
            let range = Range::new(Position::new(0, 0), index.position_at(text, text.len()));
            Outcome::Edits(vec![TextEdit::new(range, outcome.formatted)])
        }
        Err(error) => decline(error),
    }
}

pub(crate) fn range_edits(text: &str, range: Range) -> Outcome {
    let index = LineIndex::new(text);
    let start = index.offset_at(text, range.start);
    let end = index.offset_at(text, range.end);
    let (start, end) = if start <= end {
        (start, end)
    } else {
        (end, start)
    };

    match format_yaml_range(text, start, end) {
        Ok(None) => Outcome::Edits(Vec::new()),
        Ok(Some(edit)) => {
            let range = Range::new(
                index.position_at(text, edit.start),
                index.position_at(text, edit.end),
            );
            Outcome::Edits(vec![TextEdit::new(range, edit.replacement)])
        }
        Err(error) => decline(error),
    }
}

fn decline(error: FormatError) -> Outcome {
    let (level, show) = match error {
        FormatError::NotSigma { .. } => (MessageType::INFO, false),
        FormatError::Range(_) => (MessageType::LOG, false),
        FormatError::Guard(_) => (MessageType::WARNING, true),
        _ => (MessageType::WARNING, false),
    };
    Outcome::Declined {
        message: format!("rsigma: not formatting: {error}"),
        level,
        show,
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_debug_snapshot;

    use super::*;

    const BAD_LAYOUT: &str = "title: Test\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";

    const CANONICAL: &str = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";

    #[test]
    fn document_edits_rewrite_a_badly_indented_rule() {
        assert_debug_snapshot!(document_edits(BAD_LAYOUT), @r###"
        Edits(
            [
                TextEdit {
                    range: Range {
                        start: Position {
                            line: 0,
                            character: 0,
                        },
                        end: Position {
                            line: 7,
                            character: 0,
                        },
                    },
                    new_text: "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n",
                },
            ],
        )
        "###);
    }

    #[test]
    fn document_edits_are_empty_for_canonical_text() {
        assert_debug_snapshot!(document_edits(CANONICAL), @r###"
        Edits(
            [],
        )
        "###);
    }

    #[test]
    fn range_edits_format_a_selection() {
        let range = Range::new(Position::new(4, 2), Position::new(4, 11));
        assert_debug_snapshot!(range_edits(BAD_LAYOUT, range), @r###"
        Edits(
            [
                TextEdit {
                    range: Range {
                        start: Position {
                            line: 4,
                            character: 2,
                        },
                        end: Position {
                            line: 6,
                            character: 22,
                        },
                    },
                    new_text: "selection:\n      Field: value\n  condition: selection",
                },
            ],
        )
        "###);
    }

    #[test]
    fn range_edits_use_utf16_positions() {
        let text = "title: Tést\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";
        let range = Range::new(Position::new(4, 2), Position::new(4, 11));
        assert_debug_snapshot!(range_edits(text, range), @r###"
        Edits(
            [
                TextEdit {
                    range: Range {
                        start: Position {
                            line: 4,
                            character: 2,
                        },
                        end: Position {
                            line: 6,
                            character: 22,
                        },
                    },
                    new_text: "selection:\n      Field: value\n  condition: selection",
                },
            ],
        )
        "###);
    }

    #[test]
    fn non_sigma_yaml_is_declined() {
        assert_debug_snapshot!(document_edits("name: test\npipeline:\n    - id: one\n"), @r###"
        Declined {
            message: "rsigma: not formatting: document 1 is not a Sigma rule document: no `detection`, `logsource`, `correlation`, or `filter` key",
            level: Info,
            show: false,
        }
        "###);
    }
}
