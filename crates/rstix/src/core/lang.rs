//! RFC 5646-ish language tag support.

use crate::core::error::LanguageTagError;

/// Language tag newtype.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LanguageTag(String);

impl LanguageTag {
    /// Parse and validate a language tag.
    pub fn parse(value: &str) -> Result<Self, LanguageTagError> {
        if value.trim().is_empty() {
            return Err(LanguageTagError::Empty);
        }
        let mut parts = value.split('-');
        let Some(primary) = parts.next() else {
            return Err(LanguageTagError::Empty);
        };
        if !(2..=8).contains(&primary.len()) || !primary.chars().all(|ch| ch.is_ascii_alphabetic())
        {
            return Err(LanguageTagError::Invalid(value.to_owned()));
        }
        for part in parts {
            if part.is_empty()
                || part.len() > 8
                || !part.chars().all(|ch| ch.is_ascii_alphanumeric())
            {
                return Err(LanguageTagError::Invalid(value.to_owned()));
            }
        }
        Ok(Self(value.to_owned()))
    }

    /// Access underlying tag.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for LanguageTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for LanguageTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_basic_rfc5646_forms() {
        assert!(LanguageTag::parse("en").is_ok());
        assert!(LanguageTag::parse("en-US").is_ok());
    }

    #[test]
    fn rejects_invalid_tags() {
        assert!(LanguageTag::parse("").is_err());
        assert!(LanguageTag::parse("1n").is_err());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_round_trips_and_validates() {
        let tag = LanguageTag::parse("en-US").expect("valid");
        let encoded = serde_json::to_string(&tag).expect("serialize");
        assert_eq!(encoded, "\"en-US\"");
        let decoded: LanguageTag = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, tag);
        assert!(serde_json::from_str::<LanguageTag>("\"1n\"").is_err());
    }
}
