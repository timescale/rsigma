//! Overlay provenance types.

use std::fmt;
use std::path::PathBuf;

/// Where an applied overlay came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum OverlayOrigin {
    /// An inline entry at this index in the spec.
    Inline { index: usize },
    /// An entry at this index in an overlay file.
    File { path: PathBuf, index: usize },
}

impl fmt::Display for OverlayOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline { index } => write!(f, "inline:{index}"),
            Self::File { path, index } => write!(f, "{}:{index}", path.display()),
        }
    }
}

/// An overlay that was applied to a kept document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedOverlay {
    pub origin: OverlayOrigin,
    /// Key paths that were set, such as `level` or
    /// `custom_attributes.rsigma.exemplars`.
    pub set: Vec<String>,
    /// Key paths that were appended.
    pub appended: Vec<String>,
}
