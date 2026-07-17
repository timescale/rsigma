//! STIX 2.1 data model: typed objects and the common property structures they
//! share.
//!
//! The **Data Model + Serialization** phase provides common property containers
//! (`common`), all typed object layers (meta, SDO, SRO, SCO), top-level
//! [`StixObject`] dispatch, and [`Bundle`] parsing with bundle-scoped reference
//! validation.

#[cfg(feature = "serde")]
pub mod bundle;
pub mod cast;
pub mod common;
mod error;
#[cfg(feature = "serde")]
mod json_limits;
pub mod meta;
pub mod parse_options;
#[cfg(feature = "serde")]
pub(crate) mod ref_paths;
#[cfg(feature = "serde")]
mod rfc2047;
pub mod sco;
pub mod sdo;
#[cfg(feature = "serde")]
mod serde_error;
pub mod sro;
#[cfg(feature = "serde")]
pub mod stix_object;
#[cfg(feature = "serde")]
pub(crate) mod type_check;
pub mod validate;
#[cfg(feature = "serde")]
pub mod validation;

#[cfg(feature = "serde")]
pub use bundle::{Bundle, QueryableContainer};
pub use cast::BundleObjectCast;
pub use error::ModelError;
pub use meta::MetaObject;
pub use parse_options::{ParseOptions, TypeRegistry};
pub use sco::ScoObject;
pub use sdo::SdoObject;
pub use sro::SroObject;
#[cfg(feature = "serde")]
pub use stix_object::{CustomStixObject, StixObject};
#[cfg(feature = "serde")]
pub use validation::{ValidationCode, ValidationFinding, ValidationReport};
