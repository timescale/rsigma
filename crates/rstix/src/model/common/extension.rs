//! STIX extension container types.

use std::collections::BTreeMap;

/// The five STIX 2.1 extension types (`extension_type` enum).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExtensionType {
    /// `new-sdo`: the extension defines a new SDO type.
    NewSdo,
    /// `new-sro`: the extension defines a new SRO type.
    NewSro,
    /// `new-sco`: the extension defines a new SCO type.
    NewSco,
    /// `property-extension`: the extension adds nested properties.
    PropertyExtension,
    /// `toplevel-property-extension`: the extension adds top-level properties.
    ToplevelPropertyExtension,
}

impl ExtensionType {
    /// The STIX string form of this extension type.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NewSdo => "new-sdo",
            Self::NewSro => "new-sro",
            Self::NewSco => "new-sco",
            Self::PropertyExtension => "property-extension",
            Self::ToplevelPropertyExtension => "toplevel-property-extension",
        }
    }

    /// Parse from the STIX `extension_type` enum string.
    pub fn from_str_value(value: &str) -> Option<Self> {
        match value {
            "new-sdo" => Some(Self::NewSdo),
            "new-sro" => Some(Self::NewSro),
            "new-sco" => Some(Self::NewSco),
            "property-extension" => Some(Self::PropertyExtension),
            "toplevel-property-extension" => Some(Self::ToplevelPropertyExtension),
            _ => None,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ExtensionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ExtensionType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_str_value(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown extension_type: {raw}")))
    }
}

/// A single entry inside an object's `extensions` map.
///
/// The optional `extension_type` discriminant is preserved, and any remaining
/// properties are retained verbatim for lossless round-tripping.
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtensionEntry {
    /// The `extension_type` discriminant, when present.
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub extension_type: Option<ExtensionType>,
    /// All other properties of the extension object.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub properties: BTreeMap<String, serde_json::Value>,
}

/// The `extensions` property: a map from extension definition id to entry.
///
/// # Examples
///
/// ```
/// use rstix::model::common::{ExtensionEntry, ExtensionMap, ExtensionType};
///
/// let mut map = ExtensionMap::default();
/// map.0.insert(
///     "extension-definition--00000000-0000-0000-0000-000000000001".into(),
///     ExtensionEntry {
///         extension_type: Some(ExtensionType::PropertyExtension),
///         properties: Default::default(),
///     },
/// );
/// assert_eq!(map.len(), 1);
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct ExtensionMap(pub BTreeMap<String, ExtensionEntry>);

impl ExtensionMap {
    /// Returns true when no extensions are present.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of extension entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Borrow an entry by extension id.
    pub fn get(&self, id: &str) -> Option<&ExtensionEntry> {
        self.0.get(id)
    }
}
