//! STIX 2.1 data model: typed objects and the common property structures they
//! share.
//!
//! This module is being built incrementally across Phase 2. The current slice
//! provides the common property containers (`common`) shared by every STIX
//! object family; the typed object enums and `Bundle` land in later slices.

pub mod common;
mod error;

pub use error::ModelError;
