//! TLP 1.x level enum (legacy encoding).

/// TLP 1.x levels — deprecated; parse-only.
#[deprecated(note = "TLP 1.x is deprecated. Use TlpV2Level.")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TlpV1Level {
    /// TLP:WHITE
    White,
    /// TLP:GREEN
    Green,
    /// TLP:AMBER
    Amber,
    /// TLP:RED
    Red,
}

#[allow(deprecated)]
impl TlpV1Level {
    /// Map a predefined TLP 1.x marking-definition id to a level.
    pub fn from_marking_id(id: &str) -> Option<Self> {
        use crate::model::meta::{TLP1_AMBER_ID, TLP1_GREEN_ID, TLP1_RED_ID, TLP1_WHITE_ID};
        match id {
            TLP1_WHITE_ID => Some(Self::White),
            TLP1_GREEN_ID => Some(Self::Green),
            TLP1_AMBER_ID => Some(Self::Amber),
            TLP1_RED_ID => Some(Self::Red),
            _ => None,
        }
    }

    /// Equivalent TLP 2.0 level for restriction comparison.
    pub fn to_v2(self) -> super::tlp2::TlpV2Level {
        use super::tlp2::TlpV2Level;
        match self {
            Self::White => TlpV2Level::Clear,
            Self::Green => TlpV2Level::Green,
            Self::Amber => TlpV2Level::Amber,
            Self::Red => TlpV2Level::Red,
        }
    }
}
