//! STIX specification version markers.

/// STIX specification version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpecVersion {
    /// STIX 2.1.
    V2_1,
}

impl SpecVersion {
    /// String form used in serialized STIX objects.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2_1 => "2.1",
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SpecVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SpecVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        match value.as_str() {
            "2.1" => Ok(SpecVersion::V2_1),
            _ => Err(serde::de::Error::custom(format!(
                "unsupported spec version: {value}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn as_str() {
        assert_eq!(super::SpecVersion::V2_1.as_str(), "2.1");
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_round_trip() {
        use super::SpecVersion;

        let encoded = serde_json::to_string(&SpecVersion::V2_1).expect("serialize");
        assert_eq!(encoded, "\"2.1\"");
        let decoded: SpecVersion = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, SpecVersion::V2_1);
    }
}
