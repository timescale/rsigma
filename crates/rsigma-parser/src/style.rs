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
    // PyYAML resolves a plain `=` to the value tag and a plain `<<` to the
    // merge tag; `safe_load` cannot construct either as a scalar.
    s == "=" || s == "<<" || is_yaml_1_1_typed(s)
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

/// True when PyYAML's YAML 1.1 implicit resolvers (`yaml/resolver.py`) read a
/// plain `s` as an int, a float, or a timestamp.
pub(crate) fn is_yaml_1_1_typed(s: &str) -> bool {
    let b = s.as_bytes();
    yaml_1_1_int(b) || yaml_1_1_float(b) || yaml_1_1_timestamp(b)
}

fn count_while(b: &[u8], i: usize, f: impl Fn(u8) -> bool) -> usize {
    b.get(i..)
        .unwrap_or_default()
        .iter()
        .take_while(|&&c| f(c))
        .count()
}

fn digit_or_underscore(c: u8) -> bool {
    c.is_ascii_digit() || c == b'_'
}

fn blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn strip_sign(b: &[u8]) -> &[u8] {
    match b {
        [b'+' | b'-', rest @ ..] => rest,
        _ => b,
    }
}

/// End of `(?::[0-5]?[0-9])+` starting at `i`, or `None` when it does not match.
fn sexagesimal_end(b: &[u8], mut i: usize) -> Option<usize> {
    let start = i;
    while b.get(i) == Some(&b':') {
        let n = count_while(b, i + 1, |c| c.is_ascii_digit());
        if !(n == 1 || (n == 2 && b[i + 1] <= b'5')) {
            return None;
        }
        i += 1 + n;
    }
    (i > start).then_some(i)
}

/// End of an optional `[eE][-+][0-9]+` at `i`.
fn exponent_end(b: &[u8], i: usize) -> usize {
    match b.get(i..) {
        Some([b'e' | b'E', b'+' | b'-', ..]) => {
            let n = count_while(b, i + 2, |c| c.is_ascii_digit());
            if n > 0 { i + 2 + n } else { i }
        }
        _ => i,
    }
}

/// `[-+]?(0b[0-1_]+ | 0[0-7_]+ | 0 | [1-9][0-9_]* | 0x[0-9a-fA-F_]+ | [1-9][0-9_]*(:[0-5]?[0-9])+)`
fn yaml_1_1_int(b: &[u8]) -> bool {
    let b = strip_sign(b);
    match b {
        [b'0', b'b', rest @ ..] if !rest.is_empty() => {
            rest.iter().all(|&c| matches!(c, b'0' | b'1' | b'_'))
        }
        [b'0', b'x', rest @ ..] if !rest.is_empty() => {
            rest.iter().all(|&c| c.is_ascii_hexdigit() || c == b'_')
        }
        [b'0', rest @ ..] => rest.iter().all(|&c| matches!(c, b'0'..=b'7' | b'_')),
        [b'1'..=b'9', ..] => {
            let n = 1 + count_while(b, 1, digit_or_underscore);
            n == b.len() || sexagesimal_end(b, n) == Some(b.len())
        }
        _ => false,
    }
}

/// `[-+]?[0-9][0-9_]*\.[0-9_]*([eE][-+][0-9]+)? | \.[0-9][0-9_]*([eE][-+][0-9]+)?
/// | [-+]?[0-9][0-9_]*(:[0-5]?[0-9])+\.[0-9_]* | [-+]?\.(inf|Inf|INF) | \.(nan|NaN|NAN)`
fn yaml_1_1_float(b: &[u8]) -> bool {
    if let [b'.', rest @ ..] = b {
        if matches!(rest, b"nan" | b"NaN" | b"NAN") {
            return true;
        }
        if rest.first().is_some_and(u8::is_ascii_digit) {
            let n = 1 + count_while(rest, 1, digit_or_underscore);
            return exponent_end(rest, n) == rest.len();
        }
    }
    let b = strip_sign(b);
    if let [b'.', rest @ ..] = b {
        return matches!(rest, b"inf" | b"Inf" | b"INF");
    }
    if !b.first().is_some_and(u8::is_ascii_digit) {
        return false;
    }
    let whole = 1 + count_while(b, 1, digit_or_underscore);
    let dot = sexagesimal_end(b, whole).unwrap_or(whole);
    if b.get(dot) != Some(&b'.') {
        return false;
    }
    let end = dot + 1 + count_while(b, dot + 1, digit_or_underscore);
    if dot == whole {
        exponent_end(b, end) == b.len()
    } else {
        end == b.len()
    }
}

/// `YYYY-MM-DD`, or `YYYY-M-D` followed by `T`, `t`, or blanks, `H:MM:SS`, an
/// optional fraction, and an optional `Z` or `[-+]H(:MM)?` zone.
fn yaml_1_1_timestamp(b: &[u8]) -> bool {
    let digits = |i: usize| count_while(b, i, |c| c.is_ascii_digit());
    if digits(0) != 4 || b.get(4) != Some(&b'-') {
        return false;
    }
    let month = digits(5);
    if !(1..=2).contains(&month) || b.get(5 + month) != Some(&b'-') {
        return false;
    }
    let day_start = 6 + month;
    let day = digits(day_start);
    let mut i = day_start + day;
    if i == b.len() {
        return month == 2 && day == 2;
    }
    if !(1..=2).contains(&day) {
        return false;
    }
    match b[i] {
        b'T' | b't' => i += 1,
        c if blank(c) => i += count_while(b, i, blank),
        _ => return false,
    }
    let hour = digits(i);
    if !(1..=2).contains(&hour) || b.get(i + hour) != Some(&b':') {
        return false;
    }
    i += hour + 1;
    if digits(i) != 2 || b.get(i + 2) != Some(&b':') {
        return false;
    }
    i += 3;
    if digits(i) != 2 {
        return false;
    }
    i += 2;
    if b.get(i) == Some(&b'.') {
        i += 1 + digits(i + 1);
    }
    if i == b.len() {
        return true;
    }
    i += count_while(b, i, blank);
    match b.get(i) {
        Some(b'Z') => i + 1 == b.len(),
        Some(b'+' | b'-') => {
            let zone_hour = digits(i + 1);
            if !(1..=2).contains(&zone_hour) {
                return false;
            }
            let after = i + 1 + zone_hour;
            after == b.len()
                || (b.get(after) == Some(&b':') && digits(after + 1) == 2 && after + 3 == b.len())
        }
        _ => false,
    }
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

#[cfg(all(test, feature = "fmt"))]
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
            "1_000.5",
            "1.5_0",
            "1_0.",
            ".5_0",
            "1:30.",
            "-1:30",
            "0_7",
            "2024-01-01",
            "2024-1-1T10:00:00Z",
            "2024-01-01 10:00:00",
            "2024-01-01t10:00:00.5 +01:00",
            "=",
            "<<",
        ] {
            assert!(coerces(s), "expected {s:?} to coerce");
        }
        for s in [
            "whoami",
            "0x",
            "0b",
            "attack.t1059",
            "C:",
            "a:b",
            "1:70",
            "1:300",
            "1e3e",
            "2024-01-1",
            "2024-001-01",
            "2024-01-01T10:00",
            "2024-01-01 10:00:00 +001",
            "4688a",
        ] {
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
        assert_eq!(encode_key("<<", KeyCtx::Key), "'<<'");
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
