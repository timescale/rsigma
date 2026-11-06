//! Resolve JSON-pointer-style paths (e.g. `/status`, `/tags/2`,
//! `/detection/selection/CommandLine|contains`) to line ranges in raw YAML text.
//!
//! This is intentionally heuristic: we scan the text for key occurrences using
//! indentation-aware matching. When a path cannot be resolved, we fall back to
//! line 0.

use tower_lsp_server::ls_types::{Position, Range};

/// A pre-computed line index for fast offset -> line/col lookups.
pub struct LineIndex {
    /// Byte offset of the start of each line.
    line_starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(text: &str) -> Self {
        let mut line_starts = vec![0usize];
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    /// Convert a byte offset to an LSP `Position`.
    pub fn position_of(&self, offset: usize) -> Position {
        let line = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let col = offset - self.line_starts[line];
        Position::new(line as u32, col as u32)
    }

    /// Get the byte range for a full line (excluding newline).
    pub fn line_range(&self, line: usize) -> (usize, usize) {
        let start = self.line_starts.get(line).copied().unwrap_or(0);
        let end = self
            .line_starts
            .get(line + 1)
            .map(|&s| s.saturating_sub(1))
            .unwrap_or(start);
        (start, end)
    }

    /// Byte offset of an LSP position whose `character` counts UTF-16 code units.
    ///
    /// A line past the end gives `text.len()`; a character past the end of its
    /// line gives the end of the line before `\r\n` or `\n`; a position inside
    /// a surrogate pair snaps to the start of that character.
    pub fn offset_at(&self, text: &str, position: Position) -> usize {
        let Some(&line_start) = self.line_starts.get(position.line as usize) else {
            return text.len();
        };
        let line_end = self
            .line_starts
            .get(position.line as usize + 1)
            .map(|&start| start.saturating_sub(1))
            .unwrap_or(text.len());
        let content_end = if line_end > line_start && text.as_bytes()[line_end - 1] == b'\r' {
            line_end - 1
        } else {
            line_end
        };
        let content = &text[line_start..content_end];

        let mut units: u64 = 0;
        for (byte, character) in content.char_indices() {
            let width = character.len_utf16() as u64;
            if units + width > position.character as u64 {
                return line_start + byte;
            }
            units += width;
            if units >= position.character as u64 {
                return line_start + byte + character.len_utf8();
            }
        }
        content_end
    }

    /// LSP position (UTF-16 `character`) of a byte offset, clamped to
    /// `text.len()` and to the previous char boundary.
    pub fn position_at(&self, text: &str, offset: usize) -> Position {
        let mut offset = offset.min(text.len());
        while !text.is_char_boundary(offset) {
            offset -= 1;
        }
        let line = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let line_start = self.line_starts[line];
        let character = text[line_start..offset].encode_utf16().count() as u32;
        Position::new(line as u32, character)
    }
}

/// Resolve a JSON-pointer path (from `LintWarning.path`) to an LSP `Range`.
///
/// The path looks like `/status`, `/tags/2`, `/detection/condition`, etc.
/// We walk the YAML text line-by-line, tracking indentation to follow the
/// path segments. Returns a range covering the matched line, or line 0 as
/// fallback.
pub fn resolve_path(text: &str, index: &LineIndex, path: &str) -> Range {
    if path == "/" || path.is_empty() {
        // Root — highlight the first non-empty line
        return first_content_line_range(text, index);
    }

    let segments: Vec<&str> = path.strip_prefix('/').unwrap_or(path).split('/').collect();

    if segments.is_empty() {
        return first_content_line_range(text, index);
    }

    let lines: Vec<&str> = text.lines().collect();

    // Walk segments: for each segment we find the matching YAML key at the
    // expected indentation level.
    let mut current_indent: i32 = -1; // start before any indentation
    let mut search_start_line = 0usize;

    let mut last_matched_line: Option<usize> = None;

    for segment in &segments {
        // Is this segment a numeric index (e.g. the `2` in `/tags/2`)?
        let array_index: Option<usize> = segment.parse().ok();

        let mut found = false;

        let mut line_num = search_start_line;
        while line_num < lines.len() {
            let line = lines[line_num];
            let trimmed = line.trim();

            // Skip empty / comment lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                line_num += 1;
                continue;
            }

            let indent = (line.len() - line.trim_start().len()) as i32;

            // Must be deeper than parent
            if indent <= current_indent && found {
                break;
            }

            if indent <= current_indent {
                line_num += 1;
                continue;
            }

            if let Some(idx) = array_index {
                // Look for the idx-th `- ` list item at this indent level
                if trimmed.starts_with("- ") && indent > current_indent {
                    // Count list items at this level
                    let mut count = 0usize;
                    for (offset, sl) in lines[search_start_line..].iter().enumerate() {
                        let scan_line = search_start_line + offset;
                        let st = sl.trim();
                        if st.is_empty() || st.starts_with('#') {
                            continue;
                        }
                        let si = (sl.len() - sl.trim_start().len()) as i32;
                        if si < indent {
                            continue;
                        }
                        if si == indent && st.starts_with("- ") {
                            if count == idx {
                                last_matched_line = Some(scan_line);
                                search_start_line = scan_line + 1;
                                current_indent = indent;
                                found = true;
                                break;
                            }
                            count += 1;
                        }
                        if si < indent && count > 0 {
                            break;
                        }
                    }
                    break;
                }
            } else {
                // Match a key: `segment:` at the start of the trimmed line
                let key_pattern = format!("{segment}:");
                if trimmed.starts_with(&key_pattern) || trimmed == *segment {
                    last_matched_line = Some(line_num);
                    search_start_line = line_num + 1;
                    current_indent = indent;
                    found = true;
                    break;
                }
            }

            line_num += 1;
        }

        if !found && last_matched_line.is_none() {
            break;
        }
    }

    match last_matched_line {
        Some(line_num) => {
            let (start, end) = index.line_range(line_num);
            Range::new(index.position_of(start), index.position_of(end))
        }
        None => first_content_line_range(text, index),
    }
}

/// Fallback: range of the first non-empty, non-comment line.
fn first_content_line_range(text: &str, index: &LineIndex) -> Range {
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') && trimmed != "---" {
            let (start, end) = index.line_range(i);
            return Range::new(index.position_of(start), index.position_of(end));
        }
    }
    // Truly empty file
    Range::new(Position::new(0, 0), Position::new(0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_root_path() {
        let text = "title: Test\nstatus: test\n";
        let index = LineIndex::new(text);
        let range = resolve_path(text, &index, "/");
        // Should point to first content line ("title: Test")
        assert_eq!(range.start.line, 0);
    }

    #[test]
    fn resolve_top_level_key() {
        let text = "title: Test\nstatus: experimental\nlevel: high\n";
        let index = LineIndex::new(text);

        let range = resolve_path(text, &index, "/status");
        assert_eq!(range.start.line, 1);

        let range = resolve_path(text, &index, "/level");
        assert_eq!(range.start.line, 2);
    }

    #[test]
    fn resolve_nested_key() {
        let text = "\
title: Test
logsource:
    category: test
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
";
        let index = LineIndex::new(text);

        let range = resolve_path(text, &index, "/logsource/category");
        assert_eq!(range.start.line, 2);

        let range = resolve_path(text, &index, "/detection/condition");
        assert_eq!(range.start.line, 7);
    }

    #[test]
    fn resolve_array_index() {
        let text = "\
title: Test
tags:
    - attack.execution
    - attack.t1059
    - cve.2024.1234
";
        let index = LineIndex::new(text);

        let range = resolve_path(text, &index, "/tags/1");
        assert_eq!(range.start.line, 3);
    }

    #[test]
    fn offset_at_counts_ascii_units() {
        let text = "title: Test\n";
        let index = LineIndex::new(text);
        assert_eq!(index.offset_at(text, Position::new(0, 5)), 5);
    }

    #[test]
    fn offset_at_counts_utf16_units() {
        let text = "éx";
        let index = LineIndex::new(text);
        assert_eq!(index.offset_at(text, Position::new(0, 1)), 2);
        assert_eq!(index.position_at(text, 2), Position::new(0, 1));

        let text = "€x";
        let index = LineIndex::new(text);
        assert_eq!(index.offset_at(text, Position::new(0, 1)), 3);
        assert_eq!(index.position_at(text, 3), Position::new(0, 1));
    }

    #[test]
    fn offset_at_snaps_inside_a_surrogate_pair() {
        let text = "😀x";
        let index = LineIndex::new(text);
        assert_eq!(index.offset_at(text, Position::new(0, 1)), 0);
        assert_eq!(index.offset_at(text, Position::new(0, 2)), 4);
        assert_eq!(index.position_at(text, 4), Position::new(0, 2));
        assert_eq!(index.position_at(text, 2), Position::new(0, 0));
    }

    #[test]
    fn offset_at_stops_at_the_line_end() {
        let text = "a\r\nb\n";
        let index = LineIndex::new(text);
        assert_eq!(index.offset_at(text, Position::new(0, 1)), 1);
        assert_eq!(index.offset_at(text, Position::new(0, 50)), 1);
        assert_eq!(index.offset_at(text, Position::new(1, 0)), 3);
        assert_eq!(index.offset_at(text, Position::new(9, 0)), text.len());
    }

    #[test]
    fn position_round_trips_on_char_boundaries() {
        let text = "é€😀\nabc\r\n";
        let index = LineIndex::new(text);
        for offset in 0..=text.len() {
            // A newline byte has no distinct LSP position: it maps to the end
            // of its line, which `offset_at` resolves back to the line end.
            if text.is_char_boundary(offset) && text.as_bytes().get(offset) != Some(&b'\n') {
                let position = index.position_at(text, offset);
                assert_eq!(index.offset_at(text, position), offset);
            }
        }
    }
}
