//! Resolve JSON-pointer-style paths (e.g. `/status`, `/tags/2`,
//! `/detection/selection/CommandLine|contains`) to line ranges in raw YAML text.
//!
//! This is intentionally heuristic: `serde_yaml::Value` does not carry source
//! positions, so we scan the text for key occurrences using indentation-aware
//! matching. When a path cannot be resolved, we fall back to line 0.

use tower_lsp::lsp_types::{Position, Range};

/// A pre-computed line index for fast offset → line/col lookups.
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

    /// Total number of lines.
    #[allow(dead_code)]
    pub fn line_count(&self) -> usize {
        self.line_starts.len()
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

                // Also try matching YAML keys that contain `|` (field modifiers)
                // e.g. `CommandLine|contains:` matches segment `CommandLine|contains`
                if trimmed.contains('|') && trimmed.starts_with(&key_pattern) {
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
}
