//! # rsigma-ir
//!
//! Intermediate representation for Sigma rules — a shared canonical form
//! between evaluation and conversion backends.
//!
//! The IR lives between the parser AST (rsigma-parser) and the eval engine
//! and convert backends:
//!
//! ```text
//! YAML ─► parser(AST) ─► pipeline(AST transformations) ─► lower(HIR) ─► compile(CompiledRule)
//!                                                              │
//!                                                          convert(Backend queries)
//! ```
//!
//! The HIR captures modifier resolution, selector collapse, and array-scope
//! detections in a serializable form.  Compiled matchers (`Regex`, `IpNet`)
//! are elided from the IR; they are materialised in the compile step.
//!
//! ## Architecture
//!
//! - **`IrRule`** — the top-level shape, a superset of `SigmaRule` metadata
//!   with a resolution-free detection tree (`IrDetection`) and conditions
//!   (`IrCondition`) that carry no `Selector` variant.
//!
//! - **`IrMatcher`** — modifier-resolved matchers.  Each field modifier that
//!   changes comparison (contains, startswith, endswith, cidr, re, numeric
//!   operators, exists, fieldref, timestamp parts) produces an explicit enum
//!   variant rather than being encoded as a combination of raw values and an
//!   opaque `Modifiers` bitfield.
//!
//! - **`IrDetection`** — mirrors the compiler's `CompiledDetection` at the
//!   semantic level: `AllOf`, `AnyOf`, `Keywords`, `ArrayMatch`, `And`, and
//!   `Conditional`.  Array-scope quantifiers (`any`/`all`/`all-or-empty`/`none`)
//!   are preserved.
//!
//! - **`IrMatcher`** — a faithful, lossless match model. String matches keep a
//!   wildcard-aware, original-case [`hir::IrPattern`]; encoding modifiers stay
//!   explicit as [`hir::IrEncoding`] steps. Nothing is lowercased,
//!   regex-compiled, or encoding-expanded during lowering, so both eval (at
//!   compile time) and convert (at emit time) can render it exactly.
//!
//! ## Constraints
//!
//! - Sync-only. No tokio, reqwest, or other async-runtime dependencies.
//! - HIR values are literal-only on the default lowering path; deferred
//!   `DynamicSourceRef` values are produced only when
//!   [`lower::LowerOptions::permissive_placeholders`] is enabled.

pub mod error;
pub mod hir;
pub mod lower;

pub use error::IrError;
pub use hir::*;
pub use lower::{LowerOptions, lower_conditions, lower_rule};
