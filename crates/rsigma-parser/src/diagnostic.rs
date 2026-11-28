//! Problems the parser reports while building a
//! [`SigmaCollection`](crate::SigmaCollection).
//!
//! A collection keeps every document it could parse and records one
//! [`CollectionDiagnostic`] per problem. An error means a document was
//! dropped; a warning means the document was kept but part of it was ignored.
//!
//! # Examples
//!
//! ```
//! use rsigma_parser::{DiagnosticKind, DiagnosticSeverity, parse_sigma_yaml};
//!
//! let collection = parse_sigma_yaml(
//!     r#"
//! title: Kept with a warning
//! status: unknown
//! logsource:
//!     category: test
//! detection:
//!     selection:
//!         field: value
//!     condition: selection
//! "#,
//! )
//! .unwrap();
//!
//! assert_eq!(collection.rules.len(), 1);
//! assert!(!collection.has_errors());
//! let warning = &collection.diagnostics[0];
//! assert_eq!(warning.severity, DiagnosticSeverity::Warning);
//! assert_eq!(warning.kind, DiagnosticKind::Metadata);
//! assert_eq!(warning.to_string(), "invalid status: 'unknown'");
//! ```

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{SigmaParserError, SigmaParserErrorKind, SourceLocation};

/// How serious a [`CollectionDiagnostic`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    /// The document, file, or rest of the stream was dropped.
    Error,
    /// The document was kept, but an invalid value in it was ignored.
    Warning,
}

impl fmt::Display for DiagnosticSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DiagnosticSeverity::Error => "error",
            DiagnosticSeverity::Warning => "warning",
        })
    }
}

/// What a [`CollectionDiagnostic`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DiagnosticKind {
    /// The YAML stream is malformed. Parsing stops at the first such error.
    YamlSyntax,
    /// A document is not a YAML mapping.
    NotAMapping,
    /// A collection `action` is not a string, is unknown, or is `repeat`
    /// without a previous document.
    CollectionAction,
    /// A document could not be parsed into a rule, correlation, or filter.
    Document(SigmaParserErrorKind),
    /// A `status`, `level`, `related`, or `sigma-version` value is invalid
    /// and was ignored.
    Metadata,
    /// An entry of the `custom_attributes:` block is named after a standard key
    /// of a detection, correlation, or filter document, or the collection
    /// `action` key. It was kept as a custom attribute.
    CustomAttribute,
    /// A file could not be read or parsed at all.
    File(SigmaParserErrorKind),
    /// A directory walk passed over an entry, such as a link that resolves
    /// outside the directory being loaded. The file was not opened.
    SkippedPath,
}

/// A problem found while building a [`SigmaCollection`](crate::SigmaCollection).
///
/// `Display` prints [`message`](Self::message).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct CollectionDiagnostic {
    pub kind: DiagnosticKind,
    pub severity: DiagnosticSeverity,
    pub message: String,
    /// Zero-based index of the YAML document within its file or string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<usize>,
    /// The file the problem was found in, when the collection was read from
    /// disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Position within the document, for YAML syntax and condition errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
}

impl CollectionDiagnostic {
    /// An error diagnostic.
    pub fn error(kind: DiagnosticKind, message: impl Into<String>) -> Self {
        Self::new(kind, DiagnosticSeverity::Error, message.into())
    }

    /// A warning diagnostic.
    pub fn warning(kind: DiagnosticKind, message: impl Into<String>) -> Self {
        Self::new(kind, DiagnosticSeverity::Warning, message.into())
    }

    /// An error for a document the parser rejected.
    pub fn document(error: &SigmaParserError) -> Self {
        Self::error(DiagnosticKind::Document(error.kind()), error.to_string())
            .with_location(error.location())
    }

    /// An error for a file that could not be read or parsed at all.
    pub fn file(path: &Path, error: &SigmaParserError) -> Self {
        Self::error(
            DiagnosticKind::File(error.kind()),
            format!("{}: {error}", path.display()),
        )
        .with_path(path)
        .with_location(error.location())
    }

    /// A warning for an entry a directory walk passed over.
    pub fn skipped(entry: &crate::walk::SkippedEntry) -> Self {
        Self::warning(DiagnosticKind::SkippedPath, entry.to_string()).with_path(&entry.path)
    }

    fn new(kind: DiagnosticKind, severity: DiagnosticSeverity, message: String) -> Self {
        Self {
            kind,
            severity,
            message,
            document: None,
            path: None,
            location: None,
        }
    }

    /// Set the zero-based index of the YAML document.
    pub fn with_document(mut self, index: usize) -> Self {
        self.document = Some(index);
        self
    }

    /// Set the file the problem was found in.
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set the position within the document.
    pub fn with_location(mut self, location: Option<SourceLocation>) -> Self {
        self.location = location;
        self
    }

    /// True for [`DiagnosticSeverity::Error`].
    pub fn is_error(&self) -> bool {
        self.severity == DiagnosticSeverity::Error
    }
}

impl fmt::Display for CollectionDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
