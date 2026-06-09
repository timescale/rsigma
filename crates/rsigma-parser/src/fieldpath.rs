//! Field-path helpers shared by the parser, evaluator, and converters.
//!
//! Array selectors (`[any]`, `[all]`, `[N]`, ...) are written in brackets on a
//! field path. To keep a literal bracket expressible in a field name, a literal
//! `[` or `]` is escaped as `\[` / `\]` (mirroring Sigma's `\*` / `\?` wildcard
//! escaping). Only an *unescaped* bracket opens a selector; an escaped one is a
//! literal part of the field name and is unescaped before the field is resolved.

use std::borrow::Cow;

/// Unescape `\[` and `\]` into literal `[` and `]`. Any other backslash is left
/// untouched. Returns a borrow when there is nothing to unescape (the common
/// case), so non-escaped field names never allocate.
pub fn unescape_brackets(s: &str) -> Cow<'_, str> {
    if !s.contains('\\') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && matches!(chars.peek(), Some('[') | Some(']')) {
            out.push(chars.next().expect("peeked"));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Escape every *unescaped* `[` and `]` as `\[` / `\]`, leaving already-escaped
/// brackets and every other character untouched. The inverse of
/// [`unescape_brackets`]. Used to render a field name whose brackets must be
/// read literally (for example below the array-matching spec version), so the
/// escape-aware field resolver does not treat a trailing `[...]` as a selector.
/// Returns a borrow when there is nothing to escape (the common case).
pub fn escape_brackets(s: &str) -> Cow<'_, str> {
    let bytes = s.as_bytes();
    let is_unescaped_bracket =
        |i: usize| (bytes[i] == b'[' || bytes[i] == b']') && (i == 0 || bytes[i - 1] != b'\\');
    if !(0..bytes.len()).any(is_unescaped_bracket) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.char_indices() {
        if is_unescaped_bracket(i) {
            out.push('\\');
        }
        out.push(c);
    }
    Cow::Owned(out)
}

/// Index of the first occurrence of the ASCII byte `ch` that is not escaped by
/// an immediately preceding backslash. `ch` must be ASCII (`[` or `]` here);
/// scanning bytes is safe because those never appear inside a UTF-8 multibyte
/// sequence.
pub fn first_unescaped(s: &str, ch: u8) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == ch && (i == 0 || bytes[i - 1] != b'\\') {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Whether `s` ends with the ASCII byte `ch` and that byte is not escaped.
pub fn ends_with_unescaped(s: &str, ch: u8) -> bool {
    let bytes = s.as_bytes();
    match bytes.len() {
        0 => false,
        1 => bytes[0] == ch,
        n => bytes[n - 1] == ch && bytes[n - 2] != b'\\',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_only_brackets() {
        assert_eq!(unescape_brackets("plain"), "plain");
        assert_eq!(unescape_brackets("args\\[0\\]"), "args[0]");
        assert_eq!(unescape_brackets("a\\[b\\]c"), "a[b]c");
        // A backslash not before a bracket is preserved.
        assert_eq!(unescape_brackets("a\\b"), "a\\b");
    }

    #[test]
    fn escape_only_unescaped_brackets() {
        assert_eq!(escape_brackets("plain"), "plain");
        assert_eq!(escape_brackets("args[0]"), "args\\[0\\]");
        assert_eq!(escape_brackets("connections[any]"), "connections\\[any\\]");
        // Already-escaped brackets are left as-is (no double escaping).
        assert_eq!(escape_brackets("args\\[0\\]"), "args\\[0\\]");
        // Round-trips with unescape_brackets.
        assert_eq!(unescape_brackets(&escape_brackets("a[b]c")), "a[b]c");
    }

    #[test]
    fn finds_first_unescaped_bracket() {
        assert_eq!(first_unescaped("args[0]", b'['), Some(4));
        assert_eq!(first_unescaped("args\\[0\\]", b'['), None);
        assert_eq!(first_unescaped("a\\[b[any]", b'['), Some(4));
    }

    #[test]
    fn unescaped_trailing_close() {
        assert!(ends_with_unescaped("args[0]", b']'));
        assert!(!ends_with_unescaped("args\\[0\\]", b']'));
        assert!(!ends_with_unescaped("args", b']'));
    }
}
