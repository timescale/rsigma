//! YAML scalar and key styling shared by the emitter and the formatter.

/// One indentation level (four spaces, matching the SigmaHQ house style).
pub(crate) const STEP: &str = "    ";

/// Where a scalar sits, which decides how loosely it may stay plain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScalarCtx {
    Prose,
    Value,
    Condition,
}

/// How a mapping key is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyCtx {
    Key,
    FieldKey,
}

/// The chosen YAML form of a string scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Encoded {
    Plain(String),
    Single(String),
    Double(String),
    Literal { header: String, lines: Vec<String> },
}

/// Where a scalar is written: after `key:` or after `- `.
pub(crate) enum Lead<'a> {
    Key(&'a str),
    Dash,
}

/// True when a plain `s` would not read back as exactly the string `s` in
/// yaml_serde or in a YAML 1.1 reader (PyYAML, which pySigma uses).
pub(crate) fn coerces(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    if matches!(
        s.to_ascii_lowercase().as_str(),
        "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "~"
    ) {
        return true;
    }
    if s.parse::<f64>().is_ok() {
        return true;
    }
    match yaml_serde::from_str::<yaml_serde::Value>(s) {
        Ok(yaml_serde::Value::String(ref v)) if v == s => {}
        // A plain scalar is never a collection in block context; `plain_safe`
        // rejects the spellings (`: `, trailing `:`) that would make it one.
        Ok(yaml_serde::Value::Mapping(_)) | Ok(yaml_serde::Value::Sequence(_)) => {}
        _ => return true,
    }
    is_yaml_1_1_number(s)
}

/// The YAML block-context plain rule, applied before style-specific
/// restrictions.
pub(crate) fn plain_safe(s: &str) -> bool {
    if s.is_empty() || s.starts_with(char::is_whitespace) || s.ends_with(char::is_whitespace) {
        return false;
    }
    let Some(first) = s.chars().next() else {
        return false;
    };
    if matches!(
        first,
        '-' | '?'
            | ':'
            | ','
            | '['
            | ']'
            | '{'
            | '}'
            | '#'
            | '&'
            | '*'
            | '!'
            | '|'
            | '>'
            | '\''
            | '"'
            | '%'
            | '@'
            | '`'
    ) {
        return false;
    }
    if s.contains(": ") || s.contains(" #") || s.ends_with(':') {
        return false;
    }
    if s.starts_with("---") || s.starts_with("...") {
        return false;
    }
    if s.chars()
        .any(|c| c.is_control() || matches!(c, '\u{FEFF}' | '\u{85}' | '\u{2028}' | '\u{2029}'))
    {
        return false;
    }
    !coerces(s)
}

/// Choose the YAML form of a string scalar for the given context.
pub(crate) fn encode(s: &str, ctx: ScalarCtx) -> Encoded {
    if s.contains('\n') && literal_ok(s) {
        return literal(s);
    }
    if s.chars().any(single_quote_cannot_carry) {
        return Encoded::Double(double_quote(s));
    }
    if plain_allowed(s, ctx) {
        return Encoded::Plain(s.to_string());
    }
    Encoded::Single(single_quote(s))
}

/// Write a mapping key in the given context.
pub(crate) fn encode_key(s: &str, ctx: KeyCtx) -> String {
    if s == "<<" {
        return "<<".to_string();
    }
    if s.chars().any(single_quote_cannot_carry) {
        return double_quote(s);
    }
    let safe = match ctx {
        KeyCtx::Key => {
            plain_safe(s)
                && s.chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        }
        KeyCtx::FieldKey => {
            plain_safe(s)
                && s.chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/'))
                && s.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        || matches!(c, '_' | '-' | '.' | '/' | '[' | ']' | '@' | '|')
                })
        }
    };
    if safe { s.to_string() } else { single_quote(s) }
}

/// Wrap a string in single quotes, doubling embedded single quotes.
pub(crate) fn single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Wrap a string in double quotes, escaping characters YAML requires escaped.
pub(crate) fn double_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\0' => out.push_str("\\0"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\x0B' => out.push_str("\\v"),
            '\x0C' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '\x1B' => out.push_str("\\e"),
            '\u{85}' => out.push_str("\\N"),
            '\u{A0}' => out.push('\u{A0}'),
            '\u{2028}' => out.push_str("\\L"),
            '\u{2029}' => out.push_str("\\P"),
            '\u{FEFF}' => out.push_str("\\uFEFF"),
            c if c.is_control() => {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\x{:02X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Write `{indent}{key}: token` or `{indent}- token`, or a literal block whose
/// content sits at `{indent}{STEP}`.
pub(crate) fn push_scalar(out: &mut String, indent: &str, lead: Lead<'_>, s: &str, ctx: ScalarCtx) {
    let prefix = match lead {
        Lead::Key(key) => format!("{indent}{key}:"),
        Lead::Dash => format!("{indent}-"),
    };
    match encode(s, ctx) {
        Encoded::Plain(token) | Encoded::Single(token) | Encoded::Double(token) => {
            out.push_str(&prefix);
            out.push(' ');
            out.push_str(&token);
            out.push('\n');
        }
        Encoded::Literal { header, lines } => {
            out.push_str(&prefix);
            out.push(' ');
            out.push_str(&header);
            out.push('\n');
            for line in lines {
                if !line.is_empty() {
                    out.push_str(indent);
                    out.push_str(STEP);
                    out.push_str(&line);
                }
                out.push('\n');
            }
        }
    }
}

fn single_quote_cannot_carry(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\u{FEFF}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    ) || (c.is_control() && c != '\t')
}

/// Lines that end in a space or tab stay quoted: editors and pre-commit hooks
/// that trim trailing whitespace would silently change a literal block.
fn literal_ok(s: &str) -> bool {
    if !s.chars().any(|c| c != '\n') {
        return false;
    }
    if s.split('\n').any(|line| line.ends_with([' ', '\t'])) {
        return false;
    }
    !s.chars().any(|c| {
        c == '\r'
            || (c.is_control() && c != '\t' && c != '\n')
            || matches!(c, '\u{FEFF}' | '\u{85}' | '\u{2028}' | '\u{2029}')
    })
}

fn literal(s: &str) -> Encoded {
    let trailing = s.chars().rev().take_while(|&c| c == '\n').count();
    let chomp = match trailing {
        0 => "-",
        1 => "",
        _ => "+",
    };
    let body = &s[..s.len() - trailing];
    let mut lines: Vec<String> = body.split('\n').map(str::to_string).collect();
    if trailing >= 2 {
        for _ in 0..trailing - 1 {
            lines.push(String::new());
        }
    }
    let indent_indicator = lines
        .iter()
        .find(|line| !line.is_empty())
        .is_some_and(|line| line.starts_with(' '));
    let header = if indent_indicator {
        format!("|4{chomp}")
    } else {
        format!("|{chomp}")
    };
    Encoded::Literal { header, lines }
}

fn plain_allowed(s: &str, ctx: ScalarCtx) -> bool {
    if !plain_safe(s) {
        return false;
    }
    match ctx {
        ScalarCtx::Value => s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/')),
        ScalarCtx::Prose => s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()),
        ScalarCtx::Condition => true,
    }
}

fn is_yaml_1_1_number(s: &str) -> bool {
    let s = s
        .strip_prefix('+')
        .or_else(|| s.strip_prefix('-'))
        .unwrap_or(s);
    if s.is_empty() {
        return false;
    }
    if s.starts_with("0b") || s.starts_with("0x") {
        let digits = &s[2..];
        return digits.contains('_')
            && digits
                .chars()
                .all(|c| c == '_' || c.is_ascii_digit() || c.is_ascii_hexdigit());
    }
    if s.chars().all(|c| c == '_' || c.is_ascii_digit()) {
        return s.contains('_') && s.chars().any(|c| c.is_ascii_digit());
    }
    let Some((head, rest)) = s.split_once(':') else {
        return false;
    };
    if head.is_empty() || !head.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let mut groups: Vec<&str> = rest.split(':').collect();
    if let Some(last) = groups.last_mut()
        && let Some((digits, frac)) = last.split_once('.')
    {
        if digits.is_empty()
            || digits.len() > 2
            || !digits.chars().all(|c| c.is_ascii_digit())
            || frac.is_empty()
            || !frac.chars().all(|c| c.is_ascii_digit())
        {
            return false;
        }
        *last = digits;
    }
    !groups.is_empty()
        && groups
            .iter()
            .all(|g| !g.is_empty() && g.len() <= 2 && g.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(feature = "fmt")]
pub(crate) const DETECTION_ROOT: &[&str] = &[
    "title",
    "id",
    "name",
    "status",
    "description",
    "references",
    "author",
    "date",
    "modified",
    "related",
    "tags",
    "sigma-version",
    "logsource",
    "detection",
    "fields",
    "falsepositives",
    "level",
    "scope",
    "license",
    "taxonomy",
];
#[cfg(feature = "fmt")]
pub(crate) const CORRELATION_ROOT: &[&str] = &[
    "title",
    "id",
    "name",
    "status",
    "description",
    "references",
    "author",
    "date",
    "modified",
    "related",
    "tags",
    "sigma-version",
    "correlation",
    "generate",
    "fields",
    "falsepositives",
    "level",
    "scope",
    "license",
    "taxonomy",
];
#[cfg(feature = "fmt")]
pub(crate) const FILTER_ROOT: &[&str] = &[
    "title",
    "id",
    "name",
    "status",
    "description",
    "references",
    "author",
    "date",
    "modified",
    "related",
    "tags",
    "sigma-version",
    "logsource",
    "filter",
    "fields",
    "falsepositives",
    "level",
    "scope",
    "license",
    "taxonomy",
];
#[cfg(feature = "fmt")]
pub(crate) const COMMON_ROOT: &[&str] = &[
    "title",
    "id",
    "name",
    "status",
    "description",
    "references",
    "author",
    "date",
    "modified",
    "related",
    "tags",
    "sigma-version",
    "fields",
    "falsepositives",
    "level",
    "scope",
    "license",
    "taxonomy",
];
pub(crate) const RSIGMA_ORDER: &[&str] = &[
    "rsigma.window",
    "rsigma.gap",
    "rsigma.timestamp_field",
    "rsigma.suppress",
    "rsigma.action",
    "rsigma.correlation_event_mode",
    "rsigma.max_correlation_events",
    "rsigma.max_group_entries",
    "rsigma.include_event",
    "rsigma.risk_score",
    "rsigma.exemplars",
    "rsigma.ads.strategy",
    "rsigma.ads.technical_context",
    "rsigma.ads.blind_spots",
    "rsigma.ads.validation",
    "rsigma.ads.priority",
    "rsigma.ads.response",
    "rsigma.ads.exempt",
];
#[cfg(feature = "fmt")]
pub(crate) const LOGSOURCE: &[&str] = &["category", "product", "service", "definition"];
#[cfg(feature = "fmt")]
pub(crate) const CORRELATION_BODY: &[&str] = &[
    "type",
    "rules",
    "aliases",
    "group-by",
    "timespan",
    "timeframe",
    "window",
    "gap",
    "condition",
    "generate",
];
#[cfg(feature = "fmt")]
pub(crate) const RELATED_ITEM: &[&str] = &["id", "type"];

/// Sort keys so the ones named in `table` come first in table order and the
/// rest keep their source order.
#[cfg(all(test, feature = "fmt"))]
pub(crate) fn sort_by_table<'a>(keys: &[&'a str], table: &[&str]) -> Vec<&'a str> {
    let mut ranked: Vec<(usize, usize, &str)> = keys
        .iter()
        .enumerate()
        .map(
            |(index, key)| match table.iter().position(|candidate| candidate == key) {
                Some(position) => (0, position, *key),
                None => (1, index, *key),
            },
        )
        .collect();
    ranked.sort_by_key(|&(rank, position, _)| (rank, position));
    ranked.into_iter().map(|(_, _, key)| key).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coerces_table() {
        for s in [
            "",
            "true",
            "True",
            "TRUE",
            "yes",
            "No",
            "on",
            "OFF",
            "~",
            "null",
            "Null",
            "1",
            "-1",
            "+1",
            "1.5",
            "1e3",
            ".inf",
            "-.inf",
            ".NaN",
            "0x1F",
            "0o17",
            "0b101",
            "0123",
            "1_000",
            "0x_1F",
            "1:30",
            "190:20:30.15",
        ] {
            assert!(coerces(s), "expected {s:?} to coerce");
        }
        for s in ["whoami", "2024-01-01", "0x", "attack.t1059", "C:", "a:b"] {
            assert!(!coerces(s), "expected {s:?} not to coerce");
        }
    }

    #[test]
    fn encode_value_table() {
        assert_eq!(
            encode("whoami", ScalarCtx::Value),
            Encoded::Plain("whoami".into())
        );
        assert_eq!(
            encode(r"C:\Windows\", ScalarCtx::Value),
            Encoded::Single(r"'C:\Windows\'".into())
        );
        assert_eq!(
            encode("https://example.com/a?b=c", ScalarCtx::Value),
            Encoded::Single("'https://example.com/a?b=c'".into())
        );
        assert_eq!(
            encode("a: b", ScalarCtx::Value),
            Encoded::Single("'a: b'".into())
        );
        assert_eq!(
            encode("tab\there", ScalarCtx::Value),
            Encoded::Single("'tab\there'".into())
        );
        assert_eq!(
            encode("  indented\nx", ScalarCtx::Value),
            Encoded::Literal {
                header: "|4-".into(),
                lines: vec!["  indented".into(), "x".into()],
            }
        );
    }

    #[test]
    fn encode_prose_table() {
        assert_eq!(
            encode("whoami", ScalarCtx::Prose),
            Encoded::Plain("whoami".into())
        );
        assert_eq!(
            encode("https://example.com/a?b=c", ScalarCtx::Prose),
            Encoded::Plain("https://example.com/a?b=c".into())
        );
        assert_eq!(
            encode("Joe's tool", ScalarCtx::Prose),
            Encoded::Plain("Joe's tool".into())
        );
        assert_eq!(
            encode("True", ScalarCtx::Prose),
            Encoded::Single("'True'".into())
        );
    }

    #[test]
    fn encode_condition_table() {
        assert_eq!(
            encode("1 of selection_*", ScalarCtx::Condition),
            Encoded::Plain("1 of selection_*".into())
        );
        assert_eq!(
            encode("a: b", ScalarCtx::Condition),
            Encoded::Single("'a: b'".into())
        );
    }

    #[test]
    fn encode_literal_table() {
        assert_eq!(
            encode("x  \ny", ScalarCtx::Value),
            Encoded::Double("\"x  \\ny\"".into())
        );
        assert_eq!(
            encode("x\t\ny", ScalarCtx::Value),
            Encoded::Double("\"x\\t\\ny\"".into())
        );
        assert_eq!(
            encode("a\nb", ScalarCtx::Value),
            Encoded::Literal {
                header: "|-".into(),
                lines: vec!["a".into(), "b".into()],
            }
        );
        assert_eq!(
            encode("a\n", ScalarCtx::Value),
            Encoded::Literal {
                header: "|".into(),
                lines: vec!["a".into()],
            }
        );
        assert_eq!(
            encode("a\n\n", ScalarCtx::Value),
            Encoded::Literal {
                header: "|+".into(),
                lines: vec!["a".into(), String::new()],
            }
        );
        assert_eq!(
            encode("\n", ScalarCtx::Value),
            Encoded::Double("\"\\n\"".into())
        );
        assert_eq!(
            encode("bell\x07", ScalarCtx::Value),
            Encoded::Double("\"bell\\a\"".into())
        );
    }

    #[test]
    fn encode_keys() {
        assert_eq!(encode_key("title", KeyCtx::Key), "title");
        assert_eq!(encode_key("a b", KeyCtx::Key), "'a b'");
        assert_eq!(
            encode_key("CommandLine|contains|all", KeyCtx::FieldKey),
            "CommandLine|contains|all"
        );
        assert_eq!(
            encode_key("Product Name|contains", KeyCtx::FieldKey),
            "'Product Name|contains'"
        );
        assert_eq!(encode_key("@timestamp", KeyCtx::FieldKey), "'@timestamp'");
        assert_eq!(encode_key("<<", KeyCtx::Key), "<<");
    }
}

#[cfg(all(test, feature = "fmt"))]
mod order_tests {
    use super::*;

    fn shuffled<'a>(table: &'a [&'a str]) -> Vec<&'a str> {
        let mut keys: Vec<&str> = table.to_vec();
        keys.reverse();
        keys
    }

    #[test]
    fn detection_root_order() {
        let keys = shuffled(DETECTION_ROOT);
        assert_eq!(sort_by_table(&keys, DETECTION_ROOT), DETECTION_ROOT);
    }

    #[test]
    fn correlation_root_order() {
        let keys = shuffled(CORRELATION_ROOT);
        assert_eq!(sort_by_table(&keys, CORRELATION_ROOT), CORRELATION_ROOT);
    }

    #[test]
    fn filter_root_order() {
        let keys = shuffled(FILTER_ROOT);
        assert_eq!(sort_by_table(&keys, FILTER_ROOT), FILTER_ROOT);
    }

    #[test]
    fn common_root_order() {
        let keys = shuffled(COMMON_ROOT);
        assert_eq!(sort_by_table(&keys, COMMON_ROOT), COMMON_ROOT);
    }

    #[test]
    fn rsigma_order() {
        let keys = shuffled(RSIGMA_ORDER);
        assert_eq!(sort_by_table(&keys, RSIGMA_ORDER), RSIGMA_ORDER);
    }

    #[test]
    fn logsource_order() {
        let keys = shuffled(LOGSOURCE);
        assert_eq!(sort_by_table(&keys, LOGSOURCE), LOGSOURCE);
    }

    #[test]
    fn correlation_body_order() {
        let keys = shuffled(CORRELATION_BODY);
        assert_eq!(sort_by_table(&keys, CORRELATION_BODY), CORRELATION_BODY);
    }

    #[test]
    fn related_item_order() {
        let keys = shuffled(RELATED_ITEM);
        assert_eq!(sort_by_table(&keys, RELATED_ITEM), RELATED_ITEM);
    }

    #[test]
    fn unknown_keys_keep_source_order() {
        let keys = ["zzz", "title", "aaa", "level"];
        assert_eq!(
            sort_by_table(&keys, DETECTION_ROOT),
            ["title", "level", "zzz", "aaa"]
        );
    }
}
