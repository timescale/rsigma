//! The STIX `granular-marking` data type (STIX §7.2.3).

use crate::core::{LanguageTag, MarkingDefinitionId};
use crate::model::ModelError;

/// A granular marking applies a marking-definition reference *or* a language to
/// a set of selectors within an object.
///
/// STIX requires that **exactly one** of `marking_ref` or `lang` be present and
/// that `selectors` be non-empty. The invariants are enforced by [`new`] and on
/// deserialization.
///
/// # Examples
///
/// ```
/// use rstix::core::{LanguageTag, MarkingDefinitionId, StixId};
/// use rstix::model::common::GranularMarking;
///
/// let marking_id = MarkingDefinitionId::from_stix_id(StixId::generate("marking-definition"))
///     .expect("typed id");
/// let marking = GranularMarking::new(vec!["description".into()], Some(marking_id), None)
///     .expect("valid marking");
/// assert!(marking.lang.is_none());
/// ```
///
/// [`new`]: GranularMarking::new
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GranularMarking {
    /// Selectors (STIX selector syntax) the marking applies to.
    pub selectors: Vec<String>,
    /// Marking-definition reference (mutually exclusive with `lang`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub marking_ref: Option<MarkingDefinitionId>,
    /// Language tag (mutually exclusive with `marking_ref`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub lang: Option<LanguageTag>,
}

impl GranularMarking {
    /// Construct a marking carrying a marking-definition reference.
    pub fn with_marking_ref(
        selectors: Vec<String>,
        marking_ref: MarkingDefinitionId,
    ) -> Result<Self, ModelError> {
        Self::new(selectors, Some(marking_ref), None)
    }

    /// Construct a marking carrying a language tag.
    pub fn with_lang(selectors: Vec<String>, lang: LanguageTag) -> Result<Self, ModelError> {
        Self::new(selectors, None, Some(lang))
    }

    /// Construct from raw optional parts, enforcing the `marking_ref` XOR `lang`
    /// invariant.
    ///
    /// Returns [`ModelError::GranularMarkingMissingRefAndLang`] or
    /// [`ModelError::GranularMarkingBothRefAndLang`] when the XOR invariant
    /// fails, or [`ModelError::GranularMarkingEmptySelectors`] when
    /// `selectors` is empty.
    pub fn new(
        selectors: Vec<String>,
        marking_ref: Option<MarkingDefinitionId>,
        lang: Option<LanguageTag>,
    ) -> Result<Self, ModelError> {
        let marking = Self {
            selectors,
            marking_ref,
            lang,
        };
        marking.validate()?;
        Ok(marking)
    }

    /// Check selector and `marking_ref` XOR `lang` invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.selectors.is_empty() {
            return Err(ModelError::GranularMarkingEmptySelectors);
        }
        for selector in &self.selectors {
            crate::model::validate::validate_granular_selector_syntax(selector)?;
        }
        match (self.marking_ref.is_some(), self.lang.is_some()) {
            (true, false) | (false, true) => Ok(()),
            (false, false) => Err(ModelError::GranularMarkingMissingRefAndLang),
            (true, true) => Err(ModelError::GranularMarkingBothRefAndLang),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for GranularMarking {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            selectors: Vec<String>,
            #[serde(default)]
            marking_ref: Option<MarkingDefinitionId>,
            #[serde(default)]
            lang: Option<LanguageTag>,
        }

        let raw = Raw::deserialize(deserializer)?;
        GranularMarking::new(raw.selectors, raw.marking_ref, raw.lang)
            .map_err(serde::de::Error::custom)
    }
}
