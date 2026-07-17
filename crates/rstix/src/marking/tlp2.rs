//! TLP 2.0 level enum and disclosure rules.

use crate::core::MarkingDefinitionId;

/// Audience context for TLP disclosure checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisclosureContext {
    /// Recipient is within the same organization/community as the producer.
    SameOrganization,
    /// Recipient is outside the defined organization (third party).
    ThirdParty,
}

/// TLP 2.0 levels — normative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TlpV2Level {
    /// TLP:CLEAR
    Clear,
    /// TLP:GREEN
    Green,
    /// TLP:AMBER
    Amber,
    /// TLP:AMBER+STRICT
    AmberStrict,
    /// TLP:RED
    Red,
}

impl TlpV2Level {
    /// Determine level from a predefined [`MarkingDefinition`](crate::model::meta::MarkingDefinition) id.
    pub fn from_id(id: &MarkingDefinitionId) -> Option<Self> {
        Self::from_marking_id_str(id.as_stix_id().as_str())
    }

    /// Determine level from a marking-definition id string.
    pub fn from_marking_id_str(id: &str) -> Option<Self> {
        use crate::model::meta::{
            TLP2_AMBER_ID, TLP2_AMBER_STRICT_ID, TLP2_CLEAR_ID, TLP2_GREEN_ID, TLP2_RED_ID,
        };
        match id {
            TLP2_CLEAR_ID => Some(Self::Clear),
            TLP2_GREEN_ID => Some(Self::Green),
            TLP2_AMBER_ID => Some(Self::Amber),
            TLP2_AMBER_STRICT_ID => Some(Self::AmberStrict),
            TLP2_RED_ID => Some(Self::Red),
            _ => None,
        }
    }

    /// Parse TLP 2.0 extension value (`clear`, `green`, `amber`, `amber+strict`, `red`).
    pub fn from_extension_value(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "clear" | "white" => Some(Self::Clear),
            "green" => Some(Self::Green),
            "amber" => Some(Self::Amber),
            "amber+strict" => Some(Self::AmberStrict),
            "red" => Some(Self::Red),
            _ => None,
        }
    }

    /// True if this level permits disclosure to the given audience context.
    pub fn permits_disclosure(&self, context: DisclosureContext) -> bool {
        match (self, context) {
            (Self::Red, _) => false,
            (Self::AmberStrict, DisclosureContext::ThirdParty) => false,
            (Self::Amber, DisclosureContext::ThirdParty) => true,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::meta::{
        TLP2_AMBER_ID, TLP2_AMBER_STRICT_ID, TLP2_CLEAR_ID, TLP2_GREEN_ID, TLP2_RED_ID,
    };

    #[test]
    fn all_predefined_ids_map_to_levels() {
        assert_eq!(
            TlpV2Level::from_marking_id_str(TLP2_CLEAR_ID),
            Some(TlpV2Level::Clear)
        );
        assert_eq!(
            TlpV2Level::from_marking_id_str(TLP2_GREEN_ID),
            Some(TlpV2Level::Green)
        );
        assert_eq!(
            TlpV2Level::from_marking_id_str(TLP2_AMBER_ID),
            Some(TlpV2Level::Amber)
        );
        assert_eq!(
            TlpV2Level::from_marking_id_str(TLP2_AMBER_STRICT_ID),
            Some(TlpV2Level::AmberStrict)
        );
        assert_eq!(
            TlpV2Level::from_marking_id_str(TLP2_RED_ID),
            Some(TlpV2Level::Red)
        );
    }
}

#[cfg(test)]
mod amber_strict {
    use super::*;

    #[test]
    fn blocks_third_party() {
        assert!(!TlpV2Level::AmberStrict.permits_disclosure(DisclosureContext::ThirdParty));
        assert!(TlpV2Level::AmberStrict.permits_disclosure(DisclosureContext::SameOrganization));
    }

    #[test]
    fn distinct_from_amber() {
        use crate::model::meta::{TLP2_AMBER_ID, TLP2_AMBER_STRICT_ID};
        let amber = TlpV2Level::from_marking_id_str(TLP2_AMBER_ID).expect("amber");
        let strict = TlpV2Level::from_marking_id_str(TLP2_AMBER_STRICT_ID).expect("strict");
        assert_ne!(amber, strict);
        assert!(TlpV2Level::Amber.permits_disclosure(DisclosureContext::ThirdParty));
    }
}
