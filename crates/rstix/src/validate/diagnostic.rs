//! STIX validation diagnostic codes and severity levels.

use crate::core::StixId;

/// Diagnostic severity (ascending importance).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Lowest-priority hint.
    Hint = 0,
    /// Informational finding (never fails validation alone).
    Info = 1,
    /// Normative guidance deviation (SHOULD).
    Warning = 2,
    /// Hard violation (MUST or profile policy).
    Error = 3,
}

/// OASIS-style diagnostic code (`STIX-Exxxx`, `STIX-Wxxxx`, `STIX-Ixxxx`, `STIX-Hxxxx`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DiagnosticCode(&'static str);

impl DiagnosticCode {
    /// All diagnostic codes currently emitted by the validation pipeline.
    pub const ALL: [Self; 39] = [
        Self::E0001,
        Self::E0002,
        Self::E0003,
        Self::E0004,
        Self::E0005,
        Self::E0006,
        Self::E0007,
        Self::E0008,
        Self::E0009,
        Self::E0010,
        Self::E0011,
        Self::E0012,
        Self::E0013,
        Self::E0014,
        Self::E0015,
        Self::E0020,
        Self::E0021,
        Self::E0022,
        Self::E0023,
        Self::E0024,
        Self::E0030,
        Self::E0031,
        Self::E0040,
        Self::E0041,
        Self::E0050,
        Self::E0051,
        Self::E0052,
        Self::W0002,
        Self::W0003,
        Self::W0004,
        Self::W0010,
        Self::W0020,
        Self::W0030,
        Self::W0031,
        Self::W0040,
        Self::I0001,
        Self::I0002,
        Self::I0010,
        Self::H0001,
    ];

    // STIX-E0xxx — JSON/schema structural errors
    /// JSON parse failure.
    pub const E0001: Self = Self("STIX-E0001");
    /// Unknown type with `allow_custom = false`.
    pub const E0002: Self = Self("STIX-E0002");
    /// Missing required field.
    pub const E0003: Self = Self("STIX-E0003");
    /// Malware missing `is_family`.
    pub const E0004: Self = Self("STIX-E0004");
    /// ExtensionDefinition missing `created_by_ref`.
    pub const E0005: Self = Self("STIX-E0005");
    /// Reserved property name in custom properties.
    pub const E0006: Self = Self("STIX-E0006");
    /// ObservedData has both `objects` and `object_refs`.
    pub const E0007: Self = Self("STIX-E0007");
    /// ObservedData has neither `objects` nor `object_refs`.
    pub const E0008: Self = Self("STIX-E0008");
    /// EmailMessage has both `body` and `body_multipart`.
    pub const E0009: Self = Self("STIX-E0009");

    // STIX-E001x — pattern parse/semantic errors
    /// Indicator STIX pattern parse failure.
    pub const E0010: Self = Self("STIX-E0010");
    /// Indicator STIX pattern type-check failure.
    pub const E0011: Self = Self("STIX-E0011");
    /// `created`/`modified` timestamp has fewer than three fractional digits.
    pub const E0012: Self = Self("STIX-E0012");
    /// Unknown closed vocabulary value.
    pub const E0013: Self = Self("STIX-E0013");
    /// Integer outside ±2^53.
    pub const E0014: Self = Self("STIX-E0014");
    /// `modified` before `created`.
    pub const E0015: Self = Self("STIX-E0015");

    // STIX-E002x — reference errors
    /// `sighting_of_ref` points to an SCO (must be SDO).
    pub const E0020: Self = Self("STIX-E0020");
    /// Wrong target type for typed reference.
    pub const E0021: Self = Self("STIX-E0021");
    /// `object_marking_refs` element is not a marking-definition.
    pub const E0022: Self = Self("STIX-E0022");
    /// GranularMarking `marking_ref` is not a marking-definition.
    pub const E0023: Self = Self("STIX-E0023");
    /// Granular marking selector invalid or non-existent.
    pub const E0024: Self = Self("STIX-E0024");

    // STIX-E003x — extension schema errors
    /// Extension schema mismatch.
    pub const E0030: Self = Self("STIX-E0030");
    /// Top-level vs nested property-extension serialization inconsistency.
    pub const E0031: Self = Self("STIX-E0031");

    // STIX-E004x — granular marking errors
    /// GranularMarking missing both `lang` and `marking_ref`.
    pub const E0040: Self = Self("STIX-E0040");
    /// GranularMarking has both `lang` and `marking_ref`.
    pub const E0041: Self = Self("STIX-E0041");

    // STIX-E005x — custom type/property name errors
    /// Custom type name length outside 3–250.
    pub const E0050: Self = Self("STIX-E0050");
    /// Custom type name has invalid characters.
    pub const E0051: Self = Self("STIX-E0051");
    /// Custom type name contains double hyphens.
    pub const E0052: Self = Self("STIX-E0052");

    // STIX-W0xxx — normative guidance deviations
    /// SCO ID is not UUIDv5.
    pub const W0002: Self = Self("STIX-W0002");
    /// New version of revoked object.
    pub const W0003: Self = Self("STIX-W0003");
    /// Third party creating new version of another identity's object.
    pub const W0004: Self = Self("STIX-W0004");
    /// Unresolved reference (dangling `_ref`).
    pub const W0010: Self = Self("STIX-W0010");
    /// Unknown extension.
    pub const W0020: Self = Self("STIX-W0020");
    /// TLP 2.0 `amber+stict` typo.
    pub const W0030: Self = Self("STIX-W0030");
    /// Deprecated TLP 1.x encoding.
    pub const W0031: Self = Self("STIX-W0031");
    /// SCO object has unexpected SDO-only property.
    pub const W0040: Self = Self("STIX-W0040");

    // STIX-I0xxx — info
    /// Open vocabulary extension value used.
    pub const I0001: Self = Self("STIX-I0001");
    /// Unknown `relationship_type`.
    pub const I0002: Self = Self("STIX-I0002");
    /// Custom type name does not start with `x-`.
    pub const I0010: Self = Self("STIX-I0010");
    // STIX-H0xxx — hints
    /// General style or remediation hint.
    pub const H0001: Self = Self("STIX-H0001");

    /// Returns the wire code string (for example `STIX-E0001`).
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// Default severity for this code in the validation pipeline.
    pub fn default_severity(self) -> Severity {
        match self.0.as_bytes().get(5) {
            Some(b'E') => Severity::Error,
            Some(b'W') => Severity::Warning,
            Some(b'I') => Severity::Info,
            Some(b'H') => Severity::Hint,
            _ => Severity::Hint,
        }
    }
}

impl std::fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Source location for a diagnostic (JSON or pattern text).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSpan {
    /// Byte offset when available.
    pub byte_offset: Option<usize>,
    /// One-based line number when available.
    pub line: Option<usize>,
    /// One-based column number when available.
    pub column: Option<usize>,
}

/// Maps a one-based line/column (Unicode scalar values, matching `serde_json`) to a byte offset.
pub(crate) fn byte_offset_from_line_column(
    input: &str,
    line: usize,
    column: usize,
) -> Option<usize> {
    if line == 0 || column == 0 {
        return None;
    }

    let mut current_line = 1usize;
    let mut line_start = 0usize;

    for (byte_idx, ch) in input.char_indices() {
        if current_line == line {
            let column_in_line = input[line_start..byte_idx].chars().count() + 1;
            if column_in_line == column {
                return Some(byte_idx);
            }
        }
        if ch == '\n' {
            if current_line == line {
                let column_in_line = input[line_start..byte_idx].chars().count() + 1;
                if column_in_line == column {
                    return Some(byte_idx);
                }
            }
            current_line += 1;
            line_start = byte_idx + ch.len_utf8();
        }
    }

    if current_line == line {
        let column_in_line = input[line_start..].chars().count() + 1;
        if column_in_line == column {
            return Some(input.len());
        }
    }

    None
}

/// A single validation finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// Severity of this finding.
    pub severity: Severity,
    /// Machine-readable code.
    pub code: DiagnosticCode,
    /// Human-readable explanation.
    pub message: String,
    /// STIX object id when known.
    pub object_id: Option<StixId>,
    /// JSON property path or selector when applicable.
    pub property_path: Option<String>,
    /// Source location when applicable.
    pub span: Option<SourceSpan>,
    /// Optional remediation hint.
    pub fix_suggestion: Option<String>,
}

impl Diagnostic {
    /// Build an error diagnostic with the code's default severity (Error for `STIX-E*`).
    pub fn new(code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            severity: code.default_severity(),
            code,
            message: message.into(),
            object_id: None,
            property_path: None,
            span: None,
            fix_suggestion: None,
        }
    }

    /// Attach an object id.
    pub fn with_object_id(mut self, id: StixId) -> Self {
        self.object_id = Some(id);
        self
    }

    /// Attach a property path.
    pub fn with_property_path(mut self, path: impl Into<String>) -> Self {
        self.property_path = Some(path.into());
        self
    }

    /// Attach a source span.
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = Some(span);
        self
    }

    /// Attach a fix suggestion.
    pub fn with_fix_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.fix_suggestion = Some(suggestion.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_default_to_error_severity() {
        assert_eq!(DiagnosticCode::E0001.default_severity(), Severity::Error);
        assert_eq!(DiagnosticCode::W0031.default_severity(), Severity::Warning);
        assert_eq!(DiagnosticCode::I0001.default_severity(), Severity::Info);
        assert_eq!(DiagnosticCode::H0001.default_severity(), Severity::Hint);
    }

    #[test]
    fn byte_offset_from_line_column_matches_serde_json_columns() {
        let json = "{\n  \"type\": not\n}";
        let err = serde_json::from_str::<serde_json::Value>(json).unwrap_err();
        let offset =
            byte_offset_from_line_column(json, err.line(), err.column()).expect("byte offset");
        assert!(json.is_char_boundary(offset));
        assert!(offset < json.len());
        assert_eq!(
            offset,
            byte_offset_from_line_column(json, err.line(), err.column()).expect("stable")
        );
    }

    #[test]
    fn code_strings_follow_taxonomy_prefix() {
        for code in DiagnosticCode::ALL {
            let s = code.as_str();
            assert!(s.starts_with("STIX-"));
            assert_eq!(s.len(), 10);
        }
    }

    #[test]
    fn every_code_has_expected_default_severity() {
        for code in DiagnosticCode::ALL {
            let expected = match code.as_str().as_bytes()[5] {
                b'E' => Severity::Error,
                b'W' => Severity::Warning,
                b'I' => Severity::Info,
                b'H' => Severity::Hint,
                _ => unreachable!("unexpected code prefix"),
            };
            assert_eq!(code.default_severity(), expected, "{}", code.as_str());
        }
    }
}
