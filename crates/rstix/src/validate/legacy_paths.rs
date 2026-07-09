//! Stable `property_path` values for DD-VP-001 legacy [`ValidationCode`] mapping.
//!
//! These paths are the contract between [`super::semantic`] emitters and
//! [`super::legacy::legacy_validation_code`]. Do not encode finding meaning in
//! free-form diagnostic messages.

/// `external_references` CAPEC advisory (`InvalidCapecExternalReference`).
pub const EXTERNAL_REF_CAPEC: &str = "external_references.capec";

/// `external_references` CVE advisory (`InvalidCveExternalReference`).
pub const EXTERNAL_REF_CVE: &str = "external_references.cve";

/// Prefix for unresolved granular selector paths (`GranularSelectorSemanticInvalid`).
pub const GRANULAR_SELECTOR_UNRESOLVED_PREFIX: &str = "granular_markings.selectors.unresolved[";

/// Prefix for language-content unknown target field paths (`LanguageContentFieldUnknown`).
pub const LANGUAGE_CONTENT_UNKNOWN_PREFIX: &str = "contents.unknown.";

/// Prefix for language-content type/length mismatch paths (`LanguageContentValueMismatch`).
pub const LANGUAGE_CONTENT_MISMATCH_PREFIX: &str = "contents.mismatch.";

/// Build the property path for an unresolved granular selector.
pub fn granular_selector_unresolved(selector: &str) -> String {
    format!("{GRANULAR_SELECTOR_UNRESOLVED_PREFIX}{selector}]")
}

/// Build the property path for a granular selector syntax error (pipeline-only).
pub fn granular_selector_syntax(selector: &str) -> String {
    format!("granular_markings.selectors.syntax[{selector}]")
}

/// Build the property path for a language-content unknown target field.
pub fn language_content_unknown(lang: &str, field: &str) -> String {
    format!("{LANGUAGE_CONTENT_UNKNOWN_PREFIX}{lang}.{field}")
}

/// Build the property path for a language-content translation mismatch.
pub fn language_content_mismatch(lang: &str, field: &str) -> String {
    format!("{LANGUAGE_CONTENT_MISMATCH_PREFIX}{lang}.{field}")
}
