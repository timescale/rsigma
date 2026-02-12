use std::fmt;

use serde::Serialize;

use crate::error::{Result, SigmaParserError};

// =============================================================================
// SigmaString — string values with wildcard support
// =============================================================================
// Reference: pySigma types.py SigmaString
//
// Sigma values use `*` for multi-character wildcards and `?` for single-character
// wildcards. Backslash `\` escapes the next character.

/// Special characters that can appear in a Sigma string value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SpecialChar {
    /// Multi-character wildcard (`*`)
    WildcardMulti,
    /// Single-character wildcard (`?`)
    WildcardSingle,
}

/// A part of a [`SigmaString`] — either plain text or a special character.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum StringPart {
    Plain(String),
    Special(SpecialChar),
}

/// A Sigma string value that may contain wildcards.
///
/// When Sigma rules specify string values, `*` and `?` are interpreted as
/// wildcards unless escaped with `\`. This type preserves the structure so
/// downstream consumers (evaluators, converters) can handle wildcards
/// appropriately.
///
/// ## Escape semantics
///
/// Backslash (`\`) is the escape character. Its behavior depends on what follows:
///
/// | Input | Parsed as | Rationale |
/// |-------|-----------|-----------|
/// | `\*`  | literal `*` | Escapes the wildcard — backslash consumed |
/// | `\?`  | literal `?` | Escapes the wildcard — backslash consumed |
/// | `\\`  | literal `\` | Escapes itself — backslash consumed |
/// | `\W`  | literal `\W` (both kept) | Non-special char — backslash preserved |
///
/// This matches the pySigma `SigmaString` behavior: backslash only consumes
/// itself when followed by a Sigma-special character (`*`, `?`, `\`).
/// Before non-special characters it is treated as a literal backslash,
/// which is important for patterns like `\Windows\` in file paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SigmaString {
    pub parts: Vec<StringPart>,
    pub original: String,
}

impl SigmaString {
    /// Parse a string, interpreting `*` and `?` as wildcards and `\` as escape.
    pub fn new(s: &str) -> Self {
        let mut parts: Vec<StringPart> = Vec::new();
        let mut acc = String::new();
        let mut escaped = false;

        for c in s.chars() {
            if escaped {
                if c == '*' || c == '?' || c == '\\' {
                    acc.push(c);
                } else {
                    // backslash before non-special char: keep both
                    acc.push('\\');
                    acc.push(c);
                }
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '*' {
                if !acc.is_empty() {
                    parts.push(StringPart::Plain(std::mem::take(&mut acc)));
                }
                parts.push(StringPart::Special(SpecialChar::WildcardMulti));
            } else if c == '?' {
                if !acc.is_empty() {
                    parts.push(StringPart::Plain(std::mem::take(&mut acc)));
                }
                parts.push(StringPart::Special(SpecialChar::WildcardSingle));
            } else {
                acc.push(c);
            }
        }

        if escaped {
            acc.push('\\');
        }
        if !acc.is_empty() {
            parts.push(StringPart::Plain(acc));
        }

        SigmaString {
            parts,
            original: s.to_string(),
        }
    }

    /// Create from a raw string with no wildcard parsing (e.g. for `re` modifier).
    pub fn from_raw(s: &str) -> Self {
        SigmaString {
            parts: if s.is_empty() {
                Vec::new()
            } else {
                vec![StringPart::Plain(s.to_string())]
            },
            original: s.to_string(),
        }
    }

    /// Returns `true` if the string contains no wildcards.
    pub fn is_plain(&self) -> bool {
        self.parts.iter().all(|p| matches!(p, StringPart::Plain(_)))
    }

    /// Returns `true` if the string contains any wildcard characters.
    pub fn contains_wildcards(&self) -> bool {
        self.parts
            .iter()
            .any(|p| matches!(p, StringPart::Special(_)))
    }

    /// Get the plain string content (without wildcards). Returns `None` if wildcards present.
    pub fn as_plain(&self) -> Option<String> {
        if !self.is_plain() {
            return None;
        }
        Some(
            self.parts
                .iter()
                .filter_map(|p| match p {
                    StringPart::Plain(s) => Some(s.as_str()),
                    _ => None,
                })
                .collect(),
        )
    }
}

impl fmt::Display for SigmaString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.original)
    }
}

// =============================================================================
// SigmaValue — typed values in detection items
// =============================================================================

/// A typed value from a Sigma detection item.
///
/// Detection items can contain strings (with wildcards), numbers, booleans,
/// or null. The `re` modifier converts strings to regex, and `cidr` to CIDR.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum SigmaValue {
    /// String value (may contain wildcards)
    String(SigmaString),
    /// Integer value
    Integer(i64),
    /// Floating point value
    Float(f64),
    /// Boolean value
    Bool(bool),
    /// Null / empty value
    Null,
}

impl SigmaValue {
    /// Create a SigmaValue from a serde_yaml::Value.
    pub fn from_yaml(v: &serde_yaml::Value) -> Self {
        match v {
            serde_yaml::Value::String(s) => SigmaValue::String(SigmaString::new(s)),
            serde_yaml::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    SigmaValue::Integer(i)
                } else if let Some(f) = n.as_f64() {
                    SigmaValue::Float(f)
                } else {
                    SigmaValue::Null
                }
            }
            serde_yaml::Value::Bool(b) => SigmaValue::Bool(*b),
            serde_yaml::Value::Null => SigmaValue::Null,
            _ => SigmaValue::String(SigmaString::new(&format!("{v:?}"))),
        }
    }

    /// Create from a raw string (no wildcard parsing — for `re` modifier).
    pub fn from_raw_string(s: &str) -> Self {
        SigmaValue::String(SigmaString::from_raw(s))
    }
}

impl fmt::Display for SigmaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigmaValue::String(s) => write!(f, "{s}"),
            SigmaValue::Integer(n) => write!(f, "{n}"),
            SigmaValue::Float(n) => write!(f, "{n}"),
            SigmaValue::Bool(b) => write!(f, "{b}"),
            SigmaValue::Null => write!(f, "null"),
        }
    }
}

// =============================================================================
// Timespan — duration values used in correlations and timeframe
// =============================================================================

/// Unit of time for a [`Timespan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TimespanUnit {
    Second,
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl fmt::Display for TimespanUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = match self {
            TimespanUnit::Second => "s",
            TimespanUnit::Minute => "m",
            TimespanUnit::Hour => "h",
            TimespanUnit::Day => "d",
            TimespanUnit::Week => "w",
            TimespanUnit::Month => "M",
            TimespanUnit::Year => "y",
        };
        write!(f, "{c}")
    }
}

/// A parsed timespan like `1h`, `15s`, `30m`, `7d`.
///
/// Reference: pySigma correlations.py SigmaCorrelationTimespan
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Timespan {
    pub count: u64,
    pub unit: TimespanUnit,
    /// Equivalent duration in seconds (approximate for Month/Year).
    pub seconds: u64,
    /// Original string representation.
    pub original: String,
}

impl Timespan {
    /// Parse a timespan string like `"1h"`, `"15s"`, `"30m"`, `"7d"`.
    ///
    /// Supported units: `s` (second), `m` (minute), `h` (hour), `d` (day),
    /// `w` (week), `M` (month ≈ 30.44 days), `y` (year ≈ 365.25 days).
    pub fn parse(s: &str) -> Result<Self> {
        if s.len() < 2 {
            return Err(SigmaParserError::InvalidTimespan(s.to_string()));
        }
        let (count_str, unit_str) = s.split_at(s.len() - 1);
        let count: u64 = count_str
            .parse()
            .map_err(|_| SigmaParserError::InvalidTimespan(s.to_string()))?;

        let (unit, multiplier) = match unit_str {
            "s" => (TimespanUnit::Second, 1u64),
            "m" => (TimespanUnit::Minute, 60),
            "h" => (TimespanUnit::Hour, 3600),
            "d" => (TimespanUnit::Day, 86400),
            "w" => (TimespanUnit::Week, 604800),
            "M" => (TimespanUnit::Month, 2_629_746), // ~30.44 days
            "y" => (TimespanUnit::Year, 31_556_952), // ~365.25 days
            _ => return Err(SigmaParserError::InvalidTimespan(s.to_string())),
        };

        Ok(Timespan {
            count,
            unit,
            seconds: count * multiplier,
            original: s.to_string(),
        })
    }
}

impl fmt::Display for Timespan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigma_string_plain() {
        let s = SigmaString::new("hello world");
        assert!(s.is_plain());
        assert!(!s.contains_wildcards());
        assert_eq!(s.as_plain(), Some("hello world".to_string()));
    }

    #[test]
    fn test_sigma_string_wildcards() {
        let s = SigmaString::new("*admin*");
        assert!(!s.is_plain());
        assert!(s.contains_wildcards());
        assert_eq!(s.parts.len(), 3);
        assert_eq!(s.parts[0], StringPart::Special(SpecialChar::WildcardMulti));
        assert_eq!(s.parts[1], StringPart::Plain("admin".to_string()));
        assert_eq!(s.parts[2], StringPart::Special(SpecialChar::WildcardMulti));
    }

    #[test]
    fn test_sigma_string_escaped_wildcard_is_literal() {
        // In Sigma, \* escapes the wildcard — it becomes a literal asterisk
        // (matches pySigma behavior: escape_char = "\\")
        let s = SigmaString::new(r"C:\Windows\*");
        assert!(!s.contains_wildcards()); // \* is escaped → literal *
        assert!(s.is_plain());
        // \W is non-special, so both \ and W are kept; \* is special, only * kept
        assert_eq!(s.as_plain(), Some(r"C:\Windows*".to_string()));
    }

    #[test]
    fn test_sigma_string_unescaped_wildcard_in_path() {
        // Without backslash before *, the * IS a wildcard
        let s = SigmaString::new(r"C:\Windows*");
        assert!(s.contains_wildcards());
        assert_eq!(s.parts.len(), 2);
        assert_eq!(s.parts[0], StringPart::Plain(r"C:\Windows".to_string()));
        assert_eq!(s.parts[1], StringPart::Special(SpecialChar::WildcardMulti));
    }

    #[test]
    fn test_sigma_string_leading_wildcard_path() {
        // Common Sigma pattern: *\cmd.exe
        let s = SigmaString::new(r"*\cmd.exe");
        assert!(s.contains_wildcards());
        assert_eq!(s.parts.len(), 2);
        assert_eq!(s.parts[0], StringPart::Special(SpecialChar::WildcardMulti));
        assert_eq!(s.parts[1], StringPart::Plain(r"\cmd.exe".to_string()));
    }

    #[test]
    fn test_sigma_string_escaped_wildcard() {
        let s = SigmaString::new(r"test\*value");
        assert!(s.is_plain());
        assert_eq!(s.as_plain(), Some("test*value".to_string()));
    }

    #[test]
    fn test_sigma_string_single_wildcard() {
        let s = SigmaString::new("user?admin");
        assert!(s.contains_wildcards());
        assert_eq!(s.parts.len(), 3);
    }

    #[test]
    fn test_timespan_parse() {
        let ts = Timespan::parse("1h").unwrap();
        assert_eq!(ts.count, 1);
        assert_eq!(ts.unit, TimespanUnit::Hour);
        assert_eq!(ts.seconds, 3600);

        let ts = Timespan::parse("15s").unwrap();
        assert_eq!(ts.count, 15);
        assert_eq!(ts.unit, TimespanUnit::Second);
        assert_eq!(ts.seconds, 15);

        let ts = Timespan::parse("30m").unwrap();
        assert_eq!(ts.seconds, 1800);

        let ts = Timespan::parse("7d").unwrap();
        assert_eq!(ts.seconds, 604800);
    }

    #[test]
    fn test_timespan_invalid() {
        assert!(Timespan::parse("x").is_err());
        assert!(Timespan::parse("1x").is_err());
        assert!(Timespan::parse("").is_err());
    }
}
