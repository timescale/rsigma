//! Sigma specification version targeting (the `sigma-version` attribute).
//!
//! A Sigma document declares the specification MAJOR version it targets via the
//! optional top-level `sigma-version` attribute (for example `sigma-version: 3`).
//! Only the major is significant, because breaking spec changes occur only at
//! major bumps. When the attribute is absent, the document resolves to a fixed
//! floor ([`SPEC_VERSION_FLOOR`]): a constant defined by the specification rather
//! than "the latest a tool supports", so an absent attribute means the same
//! thing on every tool and the existing corpus is never silently reinterpreted.
//!
//! Version-sensitive interpretation is gated on the resolved major. The first
//! such behavior is array-matching bracket semantics: a trailing `[...]` on a
//! field path is an array selector only at [`SPEC_VERSION_ARRAY_MATCHING`] or
//! later; below it, brackets are literal field-name characters. See
//! [`array_matching_enabled`].

use yaml_serde::Value;

/// The fixed floor an absent `sigma-version` resolves to: the v2.x line that is
/// current immediately before array matching (the first versioned breaking
/// change). Existing rules carry no `sigma-version`, so they resolve here and
/// keep their pre-array-matching semantics.
pub const SPEC_VERSION_FLOOR: u32 = 2;

/// The major in which array-matching bracket selectors become active. A rule
/// must declare `sigma-version: 3` (or higher) to read `field[any]`, `args[0]`,
/// and the other selectors as array selectors rather than literal field names.
pub const SPEC_VERSION_ARRAY_MATCHING: u32 = 3;

/// The highest specification major this build implements. A document declaring a
/// major above this targets semantics the tool does not know, and should be
/// rejected or skipped rather than interpreted under older rules.
pub const SPEC_VERSION_SUPPORTED: u32 = 3;

/// Resolve a declared major to its effective value: the declared major, or the
/// fixed floor ([`SPEC_VERSION_FLOOR`]) when absent (`None`).
#[must_use]
pub fn resolve_major(declared: Option<u32>) -> u32 {
    declared.unwrap_or(SPEC_VERSION_FLOOR)
}

/// Whether array-matching bracket selectors are enabled at the resolved major.
#[must_use]
pub fn array_matching_enabled(declared: Option<u32>) -> bool {
    resolve_major(declared) >= SPEC_VERSION_ARRAY_MATCHING
}

/// Whether a declared major exceeds what this build supports
/// ([`SPEC_VERSION_SUPPORTED`]). An absent version (`None`) is always supported,
/// since it resolves to the floor.
#[must_use]
pub fn is_unsupported(declared: Option<u32>) -> bool {
    matches!(declared, Some(major) if major > SPEC_VERSION_SUPPORTED)
}

/// Extract the specification major from a `sigma-version` YAML value.
///
/// Accepts an integer major (`3`), a float whose integer part is the major
/// (`2.1` -> `2`), or a release string (`"3"`, `"2.1.0"`, `"v3"`). Only the
/// major component is read. Returns `None` when the value cannot be interpreted
/// as a version, so the caller can warn and treat it as absent.
#[must_use]
pub fn major_from_value(value: &Value) -> Option<u32> {
    match value {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                u32::try_from(u).ok()
            } else if let Some(i) = n.as_i64() {
                u32::try_from(i).ok()
            } else if let Some(f) = n.as_f64() {
                // A float like `2.1`: the integer part is the major.
                if f.is_finite() && f >= 0.0 {
                    Some(f.trunc() as u32)
                } else {
                    None
                }
            } else {
                None
            }
        }
        Value::String(s) => major_from_str(s),
        _ => None,
    }
}

/// Parse the major component out of a release string: the leading integer of the
/// dotted version, ignoring an optional `v`/`V` prefix (`"v3.1"` -> `3`).
#[must_use]
pub fn major_from_str(s: &str) -> Option<u32> {
    let head = s
        .trim()
        .trim_start_matches(['v', 'V'])
        .split('.')
        .next()
        .unwrap_or("");
    head.parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_and_gating() {
        assert_eq!(resolve_major(None), SPEC_VERSION_FLOOR);
        assert_eq!(resolve_major(Some(3)), 3);
        assert!(!array_matching_enabled(None));
        assert!(!array_matching_enabled(Some(2)));
        assert!(array_matching_enabled(Some(3)));
        assert!(array_matching_enabled(Some(4)));
    }

    #[test]
    fn unsupported_major() {
        assert!(!is_unsupported(None));
        assert!(!is_unsupported(Some(SPEC_VERSION_SUPPORTED)));
        assert!(is_unsupported(Some(SPEC_VERSION_SUPPORTED + 1)));
    }

    #[test]
    fn major_parsing() {
        assert_eq!(major_from_str("3"), Some(3));
        assert_eq!(major_from_str("2.1.0"), Some(2));
        assert_eq!(major_from_str("v3.1"), Some(3));
        assert_eq!(major_from_str(" 2 "), Some(2));
        assert_eq!(major_from_str("abc"), None);
        assert_eq!(major_from_str(""), None);
    }
}
