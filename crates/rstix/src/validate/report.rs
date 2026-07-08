//! Aggregated validation output.

use super::Leniency;
use super::diagnostic::{Diagnostic, Severity};

/// Validation pipeline output (distinct from advisory [`crate::model::ValidationReport`]).
///
/// When both report types are in scope, prefer the crate-root alias
/// [`crate::PipelineValidationReport`]. Migration of overlapping `Bundle::validate()`
/// findings into this pipeline is tracked in follow-up validation work (see **DD-VP-001**
/// in the crate README).
#[doc(alias = "PipelineValidationReport")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationReport {
    diagnostics: Vec<Diagnostic>,
    leniency: Leniency,
}

impl Default for ValidationReport {
    fn default() -> Self {
        Self {
            diagnostics: Vec::new(),
            leniency: Leniency::Standard,
        }
    }
}

impl ValidationReport {
    /// Empty report with standard leniency.
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty report with the given leniency policy.
    pub fn with_leniency(leniency: Leniency) -> Self {
        Self {
            diagnostics: Vec::new(),
            leniency,
        }
    }

    /// Leniency policy applied when evaluating [`Self::is_valid`].
    pub fn leniency(&self) -> Leniency {
        self.leniency
    }

    /// Append a diagnostic.
    pub fn push(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    /// True when no diagnostics fail validation under the report leniency policy.
    pub fn is_valid(&self) -> bool {
        !self
            .diagnostics
            .iter()
            .any(|d| self.leniency.fails_validation(d.severity))
    }

    /// All diagnostics in insertion order.
    pub fn diagnostics(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics.iter()
    }

    /// Error-severity diagnostics only.
    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
    }

    /// Warning-severity diagnostics only.
    pub fn warnings(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Warning)
    }

    /// Info-severity diagnostics only.
    pub fn infos(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Info)
    }

    /// Hint-severity diagnostics only.
    pub fn hints(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Hint)
    }

    /// Diagnostics with the given code.
    pub fn with_code(&self, code: super::DiagnosticCode) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics.iter().filter(move |d| d.code == code)
    }

    /// Number of diagnostics recorded.
    pub fn len(&self) -> usize {
        self.diagnostics.len()
    }

    /// True when the report contains no diagnostics.
    pub fn is_empty(&self) -> bool {
        self.diagnostics.is_empty()
    }
}
