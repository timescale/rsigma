//! Named validation profiles and leniency policy.

use super::phase::ValidationPhase;

/// How strictly MUST vs SHOULD violations are treated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Leniency {
    /// Standard profile behavior: only Error-severity diagnostics fail [`super::ValidationReport::is_valid`].
    #[default]
    Standard,
    /// OASIS interoperability gate: Error- and Warning-severity diagnostics fail `is_valid()`.
    Zero,
}

impl Leniency {
    /// Whether a diagnostic at this severity fails validation under this policy.
    pub fn fails_validation(self, severity: super::Severity) -> bool {
        match self {
            Self::Standard => severity == super::Severity::Error,
            Self::Zero => matches!(severity, super::Severity::Error | super::Severity::Warning),
        }
    }
}

/// Check sets for the four named profiles.
pub(crate) fn consumer_permissive_phases() -> Vec<ValidationPhase> {
    vec![
        ValidationPhase::JsonWellFormedness,
        ValidationPhase::TypeDiscrimination,
        ValidationPhase::Schema,
        ValidationPhase::References,
    ]
}

pub(crate) fn consumer_strict_phases() -> Vec<ValidationPhase> {
    ValidationPhase::ALL.to_vec()
}

pub(crate) fn producer_strict_phases() -> Vec<ValidationPhase> {
    ValidationPhase::ALL
        .iter()
        .copied()
        .filter(|phase| *phase != ValidationPhase::References)
        .collect()
}

pub(crate) fn interop_strict_phases() -> Vec<ValidationPhase> {
    ValidationPhase::ALL.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn phase_set(phases: &[ValidationPhase]) -> HashSet<ValidationPhase> {
        phases.iter().copied().collect()
    }

    #[test]
    fn consumer_permissive_runs_json_type_schema_refs() {
        let set = phase_set(&consumer_permissive_phases());
        assert_eq!(set.len(), 4);
        assert!(set.contains(&ValidationPhase::JsonWellFormedness));
        assert!(set.contains(&ValidationPhase::TypeDiscrimination));
        assert!(set.contains(&ValidationPhase::Schema));
        assert!(set.contains(&ValidationPhase::References));
        assert!(!set.contains(&ValidationPhase::PatternParse));
        assert!(!set.contains(&ValidationPhase::TlpMarkingComputation));
    }

    #[test]
    fn consumer_strict_runs_all_twelve() {
        assert_eq!(consumer_strict_phases().len(), 12);
    }

    #[test]
    fn producer_strict_skips_references() {
        let set = phase_set(&producer_strict_phases());
        assert_eq!(set.len(), 11);
        assert!(!set.contains(&ValidationPhase::References));
        assert!(set.contains(&ValidationPhase::PatternParse));
        assert!(set.contains(&ValidationPhase::TlpMarkingComputation));
    }

    #[test]
    fn interop_strict_runs_all_twelve() {
        assert_eq!(interop_strict_phases().len(), 12);
    }

    #[test]
    fn zero_leniency_fails_on_warnings() {
        assert!(Leniency::Zero.fails_validation(crate::validate::Severity::Warning));
        assert!(!Leniency::Standard.fails_validation(crate::validate::Severity::Warning));
    }
}
