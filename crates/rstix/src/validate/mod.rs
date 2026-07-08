//! STIX 2.1 validation pipeline (`validate` feature).
//!
//! # Validation Pipeline vs `Bundle::validate()`
//!
//! **Design decision DD-VP-001:** [`crate::model::Bundle::validate`] returns
//! [`crate::model::ValidationReport`] with warning-only SHOULD findings (`ValidationCode`
//! enum). This module introduces the profile-based **Validation Pipeline** with
//! Error / Warning / Info / Hint severities and OASIS-style `STIX-E/W/I/H` string codes
//! ([`DiagnosticCode`], [`ValidationReport`]).
//!
//! - Use [`Validator`] for untrusted ingest, named profiles, and structured diagnostics.
//! - Use [`Bundle::validate`](crate::model::Bundle::validate) for advisory checks on
//!   already-parsed bundles until overlapping rules migrate into the pipeline.
//!
//! All checks except JSON well-formedness are wired through the dispatcher; remaining logic is follow-up work.

mod checks;
mod diagnostic;
mod parse_bridge;
mod phase;
mod profiles;
mod report;
mod validator;

pub use diagnostic::{Diagnostic, DiagnosticCode, Severity, SourceSpan};
pub use phase::ValidationPhase;
pub use profiles::Leniency;
pub use report::ValidationReport;
pub use validator::{Validator, ValidatorBuilder};

pub use crate::model::ParseOptions;
