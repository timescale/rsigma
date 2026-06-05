//! STIX vocabulary tables.

mod closed;
mod open;

pub use closed::*;
pub use open::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_vocabulary_membership_examples() {
        assert!(OPINION_ENUM.contains("agree"));
        assert!(!OPINION_ENUM.contains("unknown-value"));
        assert!(HASH_ALGORITHM_ENUM.contains("SHA-256"));
    }

    #[test]
    fn open_vocabulary_membership_examples() {
        assert!(INDICATOR_TYPE_OV.contains("malicious-activity"));
        assert!(MALWARE_TYPE_OV.contains("ransomware"));
        assert!(IMPLEMENTATION_LANGUAGE_OV.contains("rust"));
    }

    #[test]
    fn opinion_ordering_is_stable() {
        assert!(OpinionValue::Agree > OpinionValue::Neutral);
        assert!(OpinionValue::StronglyDisagree < OpinionValue::Disagree);
    }
}
