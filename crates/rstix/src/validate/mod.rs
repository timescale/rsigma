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
//!   already-parsed bundles; when the `validate` feature is enabled it delegates to
//!   the same semantic helpers as phases 10 and 12.
//!
//! All checks are wired through the dispatcher and share helpers under
//! `model_bridge`, `object_validate`, `semantic`, and `wire`.

mod checks;
mod diagnostic;
pub(crate) mod legacy;
mod legacy_paths;
mod model_bridge;
mod object_validate;
mod parse_bridge;
mod phase;
mod profiles;
mod report;
mod semantic;
mod validator;
mod wire;

pub use diagnostic::{Diagnostic, DiagnosticCode, Severity, SourceSpan};
pub use phase::ValidationPhase;
pub use profiles::Leniency;
pub use report::ValidationReport;
pub use validator::{Validator, ValidatorBuilder};

pub use crate::model::ParseOptions;
