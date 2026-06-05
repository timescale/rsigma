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
}
