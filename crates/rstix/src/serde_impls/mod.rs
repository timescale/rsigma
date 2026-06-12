//! Hand-written serde implementations, gated behind the `serde` feature.
//!
//! Layout matches the Phase 2 plan: bundle/object dispatch, streaming parse, and
//! core type serializers live here rather than beside domain logic. This slice
//! hosts plain-string [`StixId`](crate::core::StixId) serialization and
//! precision-preserving timestamp formats. Typed-ID serde is generated in the
//! [`define_typed_id!`](crate::core::id) macro so the 42-type list stays
//! single-sourced. Later slices add type-discriminated object dispatch,
//! extension-map routing, and streaming readers here.

mod stix_id;
mod timestamp;
