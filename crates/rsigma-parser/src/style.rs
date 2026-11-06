//! YAML scalar and key styling shared by the emitter and the formatter.

/// One indentation level (four spaces, matching the SigmaHQ house style).
pub(crate) const STEP: &str = "    ";

/// Quote a value scalar in Sigma's single-quote convention unless it is a
/// bare-safe token.
pub(crate) fn scalar(s: &str) -> String {
    if is_bare_safe(s) {
        s.to_string()
    } else {
        quote(s)
    }
}

/// Looser quoting for prose scalars (title, description, author): plain YAML
/// permits internal spaces, so common values stay unquoted.
pub(crate) fn scalar_prose(s: &str) -> String {
    let bare = !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && !s.ends_with(' ')
        && !s.contains(": ")
        && !s.contains(" #")
        && !s.contains('\n')
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | ',' | '(' | ')' | '/')
        });
    if bare { s.to_string() } else { quote(s) }
}

pub(crate) fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn is_bare_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
        && !s.starts_with('-')
        && s.parse::<f64>().is_err()
        && !matches!(
            s.to_ascii_lowercase().as_str(),
            "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "~"
        )
}

/// A mapping key (metadata key, custom-attribute key, or logsource custom
/// field). Quoted only when it contains characters unsafe in a plain key.
pub(crate) fn key_token(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if safe { s.to_string() } else { quote(s) }
}

/// A detection field name used inside a key (bare identifiers, dotted paths,
/// and array/index markers pass through; anything else is quoted).
pub(crate) fn field_token(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '[' | ']' | '@')
        });
    if safe { s.to_string() } else { quote(s) }
}
