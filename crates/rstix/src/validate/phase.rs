//! Validation pipeline check identifiers.

/// One selectable check in the STIX 2.1 validation pipeline.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValidationPhase {
    /// JSON well-formedness.
    JsonWellFormedness,
    /// `type` discrimination and custom type names.
    TypeDiscrimination,
    /// Schema, required fields, mutual exclusion.
    Schema,
    /// ID structure and SCO UUIDv5 advisory.
    IdStructure,
    /// Property types, timestamps, hashes, closed vocab.
    PropertyTypes,
    /// Open vocabulary (info only).
    OpenVocabulary,
    /// Indicator STIX pattern parse.
    PatternParse,
    /// Indicator STIX pattern type-check.
    PatternSemantic,
    /// Reference resolution and versioning.
    References,
    /// Cross-object semantics and granular selectors.
    CrossObjectSemantic,
    /// Extension resolution.
    ExtensionResolution,
    /// TLP marking computation.
    TlpMarkingComputation,
}

impl ValidationPhase {
    /// All twelve checks in pipeline order.
    pub const ALL: [Self; 12] = [
        Self::JsonWellFormedness,
        Self::TypeDiscrimination,
        Self::Schema,
        Self::IdStructure,
        Self::PropertyTypes,
        Self::OpenVocabulary,
        Self::PatternParse,
        Self::PatternSemantic,
        Self::References,
        Self::CrossObjectSemantic,
        Self::ExtensionResolution,
        Self::TlpMarkingComputation,
    ];

    /// Checks that currently perform validation logic.
    pub const IMPLEMENTED: [Self; 12] = Self::ALL;

    /// Whether this check performs validation logic today.
    pub const fn is_implemented(self) -> bool {
        true
    }

    /// Human-readable check name for diagnostics and logging.
    pub const fn label(self) -> &'static str {
        match self {
            Self::JsonWellFormedness => "JSON well-formedness",
            Self::TypeDiscrimination => "type discrimination",
            Self::Schema => "schema",
            Self::IdStructure => "ID structure",
            Self::PropertyTypes => "property types",
            Self::OpenVocabulary => "open vocabulary",
            Self::PatternParse => "pattern parse",
            Self::PatternSemantic => "pattern semantic",
            Self::References => "references",
            Self::CrossObjectSemantic => "cross-object semantic",
            Self::ExtensionResolution => "extension resolution",
            Self::TlpMarkingComputation => "TLP marking computation",
        }
    }
}
