//! Graph construction and traversal errors.

/// Errors building or querying a [`StixGraph`](super::StixGraph).
#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GraphError {
    /// A bundle object is missing the required `id` property.
    #[error("bundle object missing required id")]
    MissingObjectId,
    /// Two objects in the same bundle share an `id`.
    #[error("duplicate bundle object id `{0}`")]
    DuplicateObjectId(String),
}
