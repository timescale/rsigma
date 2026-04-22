//! Zero-dependency logfmt parser.
//!
//! Parses the [logfmt](https://brandur.org/logfmt) key=value format used by
//! Heroku, Go's `logrus`, and many other structured logging libraries.
//!
//! Supported syntax:
//!
//! | Input               | Key      | Value          |
//! |---------------------|----------|----------------|
//! | `key=value`         | `key`    | `"value"`      |
//! | `key="quoted val"`  | `key`    | `"quoted val"` |
//! | `key=`              | `key`    | `""`           |
//! | `key`               | `key`    | `"true"`       |
//! | `key="esc\"ape"`    | `key`    | `esc"ape`      |
//! | `key="back\\slash"` | `key`    | `back\slash`   |
//!
//! # Example
//!
//! ```
//! use rsigma_runtime::parse::logfmt::parse;
//!
//! let pairs = parse(r#"level=info msg="request handled" duration=12ms"#);
//! assert_eq!(pairs.len(), 3);
//! assert_eq!(pairs[0], ("level".into(), "info".into()));
//! assert_eq!(pairs[1], ("msg".into(), "request handled".into()));
//! assert_eq!(pairs[2], ("duration".into(), "12ms".into()));
//! ```

/// Parse a logfmt line into key-value pairs.
///
/// Bare keys (no `=`) are mapped to the value `"true"`.
/// Empty values (`key=`) are mapped to `""`.
/// Returns an empty vec for blank input.
pub fn parse(input: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut pos = 0;

    while pos < len {
        // Skip whitespace between pairs.
        if bytes[pos] == b' ' || bytes[pos] == b'\t' {
            pos += 1;
            continue;
        }

        // Parse key: everything up to '=' or whitespace.
        let key_start = pos;
        while pos < len && bytes[pos] != b'=' && bytes[pos] != b' ' && bytes[pos] != b'\t' {
            pos += 1;
        }

        // Empty key (e.g. leading `=`) — skip to next whitespace.
        if pos == key_start {
            while pos < len && bytes[pos] != b' ' && bytes[pos] != b'\t' {
                pos += 1;
            }
            continue;
        }

        let key = input[key_start..pos].to_string();

        // Bare key (no `=` follows): value is "true".
        if pos >= len || bytes[pos] != b'=' {
            pairs.push((key, "true".to_string()));
            continue;
        }

        // Skip the '='.
        pos += 1;

        // Parse value.
        let value = if pos < len && bytes[pos] == b'"' {
            // Quoted value: consume until closing unescaped `"`.
            pos += 1; // skip opening quote
            parse_quoted(bytes, &mut pos)
        } else {
            // Unquoted value: consume until whitespace or end.
            let val_start = pos;
            while pos < len && bytes[pos] != b' ' && bytes[pos] != b'\t' {
                pos += 1;
            }
            input[val_start..pos].to_string()
        };

        pairs.push((key, value));
    }

    pairs
}

/// Parse a quoted value starting just after the opening `"`.
///
/// Handles `\"` and `\\` escape sequences. Advances `pos` past the closing
/// quote (or to end-of-input if the closing quote is missing).
fn parse_quoted(bytes: &[u8], pos: &mut usize) -> String {
    let mut buf = String::new();
    let len = bytes.len();

    while *pos < len {
        let b = bytes[*pos];
        match b {
            b'\\' if *pos + 1 < len => {
                let next = bytes[*pos + 1];
                match next {
                    b'"' | b'\\' => {
                        buf.push(next as char);
                        *pos += 2;
                    }
                    // Unknown escape — preserve the backslash literally.
                    _ => {
                        buf.push('\\');
                        *pos += 1;
                    }
                }
            }
            b'"' => {
                *pos += 1; // skip closing quote
                return buf;
            }
            _ => {
                buf.push(b as char);
                *pos += 1;
            }
        }
    }

    // Unterminated quote — return what we have.
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_pairs() {
        let pairs = parse("level=info msg=hello");
        assert_eq!(
            pairs,
            vec![
                ("level".into(), "info".into()),
                ("msg".into(), "hello".into()),
            ]
        );
    }

    #[test]
    fn quoted_value() {
        let pairs = parse(r#"msg="hello world""#);
        assert_eq!(pairs, vec![("msg".into(), "hello world".into())]);
    }

    #[test]
    fn escaped_quote_in_value() {
        let pairs = parse(r#"msg="say \"hi\"""#);
        assert_eq!(pairs, vec![("msg".into(), r#"say "hi""#.into())]);
    }

    #[test]
    fn escaped_backslash_in_value() {
        let pairs = parse(r#"path="C:\\Users\\admin""#);
        assert_eq!(pairs, vec![("path".into(), r"C:\Users\admin".into())]);
    }

    #[test]
    fn unknown_escape_preserved() {
        let pairs = parse(r#"msg="hello\nworld""#);
        assert_eq!(pairs, vec![("msg".into(), r"hello\nworld".into())]);
    }

    #[test]
    fn bare_key() {
        let pairs = parse("debug level=info");
        assert_eq!(
            pairs,
            vec![
                ("debug".into(), "true".into()),
                ("level".into(), "info".into()),
            ]
        );
    }

    #[test]
    fn empty_value() {
        let pairs = parse("key=");
        assert_eq!(pairs, vec![("key".into(), String::new())]);
    }

    #[test]
    fn empty_quoted_value() {
        let pairs = parse(r#"key="""#);
        assert_eq!(pairs, vec![("key".into(), String::new())]);
    }

    #[test]
    fn multiple_spaces_between_pairs() {
        let pairs = parse("a=1   b=2");
        assert_eq!(
            pairs,
            vec![("a".into(), "1".into()), ("b".into(), "2".into())]
        );
    }

    #[test]
    fn tabs_as_separators() {
        let pairs = parse("a=1\tb=2");
        assert_eq!(
            pairs,
            vec![("a".into(), "1".into()), ("b".into(), "2".into())]
        );
    }

    #[test]
    fn leading_and_trailing_whitespace() {
        let pairs = parse("  a=1 b=2  ");
        assert_eq!(
            pairs,
            vec![("a".into(), "1".into()), ("b".into(), "2".into())]
        );
    }

    #[test]
    fn empty_input() {
        assert!(parse("").is_empty());
    }

    #[test]
    fn whitespace_only() {
        assert!(parse("   ").is_empty());
    }

    #[test]
    fn unterminated_quote() {
        let pairs = parse(r#"msg="hello world"#);
        assert_eq!(pairs, vec![("msg".into(), "hello world".into())]);
    }

    #[test]
    fn leading_equals_skipped() {
        let pairs = parse("=garbage a=1");
        assert_eq!(pairs, vec![("a".into(), "1".into())]);
    }

    #[test]
    fn mixed_types() {
        let pairs = parse(r#"ts=2024-01-15T10:30:00Z level=error msg="disk full" retry=3 fatal"#);
        assert_eq!(
            pairs,
            vec![
                ("ts".into(), "2024-01-15T10:30:00Z".into()),
                ("level".into(), "error".into()),
                ("msg".into(), "disk full".into()),
                ("retry".into(), "3".into()),
                ("fatal".into(), "true".into()),
            ]
        );
    }

    #[test]
    fn real_world_heroku_log() {
        let line = r#"at=info method=GET path="/" host=example.com request_id=abc-123 fwd="10.0.0.1" dyno=web.1 connect=1ms service=4ms status=200 bytes=1234"#;
        let pairs = parse(line);
        assert_eq!(pairs.len(), 11);
        assert_eq!(pairs[0], ("at".into(), "info".into()));
        assert_eq!(pairs[2], ("path".into(), "/".into()));
        assert_eq!(pairs[4], ("request_id".into(), "abc-123".into()));
        assert_eq!(pairs[5], ("fwd".into(), "10.0.0.1".into()));
        assert_eq!(pairs[10], ("bytes".into(), "1234".into()));
    }

    #[test]
    fn real_world_go_logrus() {
        let line =
            r#"time="2024-01-15T10:30:00Z" level=warning msg="connection reset" component=db"#;
        let pairs = parse(line);
        assert_eq!(pairs.len(), 4);
        assert_eq!(pairs[0], ("time".into(), "2024-01-15T10:30:00Z".into()));
        assert_eq!(pairs[1], ("level".into(), "warning".into()));
        assert_eq!(pairs[2], ("msg".into(), "connection reset".into()));
    }

    #[test]
    fn consecutive_bare_keys() {
        let pairs = parse("verbose debug trace");
        assert_eq!(
            pairs,
            vec![
                ("verbose".into(), "true".into()),
                ("debug".into(), "true".into()),
                ("trace".into(), "true".into()),
            ]
        );
    }

    #[test]
    fn value_with_equals_sign() {
        // In unquoted values, `=` is just a regular character after the first split.
        // `key=a=b` should give key="a=b" (greedy unquoted value up to whitespace).
        let pairs = parse("expr=a=b");
        assert_eq!(pairs, vec![("expr".into(), "a=b".into())]);
    }

    #[test]
    fn quoted_value_with_spaces_and_equals() {
        let pairs = parse(r#"filter="status=200 method=GET""#);
        assert_eq!(
            pairs,
            vec![("filter".into(), "status=200 method=GET".into())]
        );
    }
}
