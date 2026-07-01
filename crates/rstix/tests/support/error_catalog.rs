//! Catalog of evaluation-time error scenarios for integration tests.

use rstix::pattern::PatternMatchError;

/// One expected [`PatternMatchError`] scenario.
#[derive(Clone, Copy)]
pub struct ErrorCase {
    pub id: &'static str,
    pub make_error: fn() -> PatternMatchError,
}

macro_rules! error_cases {
    ($($id:literal => $expr:expr,)*) => {
        pub const ALL: &[ErrorCase] = &[
            $(ErrorCase { id: $id, make_error: || $expr }),*
        ];
    };
}

error_cases! {
    "missing-timestamp" => PatternMatchError::MissingTimestamp,
    "unsupported-operator-like" => rstix::pattern::test_pattern_match_error_unsupported_operator_like(),
    "non-stix-pattern-snort" => rstix::pattern::test_pattern_match_error_non_stix_pattern("snort"),
    "regex-compile-invalid" => PatternMatchError::RegexCompile { msg: "invalid regex".into() },
    "regex-compile-oversized" => PatternMatchError::RegexCompile { msg: "Compiled program too big".into() },
    "ref-resolution-bundle-required" => PatternMatchError::RefResolution {
        path: "process:image_ref._ref.name".into(),
        msg: "bundle required for _ref dereference".into(),
    },
    "ref-resolution-object-not-found" => PatternMatchError::RefResolution {
        path: "process:image_ref._ref.name".into(),
        msg: "object `file--00000000-0000-0000-0000-000000009999` not found in bundle".into(),
    },
    "ref-resolution-not-sco" => PatternMatchError::RefResolution {
        path: "process:image_ref._ref.name".into(),
        msg: "object `identity--00000000-0000-0000-0000-000000000001` is not an SCO".into(),
    },
    "ref-resolution-property-absent" => PatternMatchError::RefResolution {
        path: "process:image_ref._ref.name".into(),
        msg: "property `image_ref` is absent or not a reference".into(),
    },
    "not-single-observation" => PatternMatchError::NotSingleObservation,
    "too-many-observations" => PatternMatchError::TooManyObservations {
        count: 257,
        max: rstix::pattern::MAX_OBSERVATIONS,
    },
    "observed-data-missing-object" => PatternMatchError::RefResolution {
        path: "observed-data.object_refs".into(),
        msg: "missing object `ipv4-addr--00000000-0000-0000-0000-000000009999`".into(),
    },
    "observed-data-not-sco" => PatternMatchError::RefResolution {
        path: "observed-data.object_refs".into(),
        msg: "object `relationship--00000000-0000-0000-0000-000000000001` has type `relationship`, expected an SCO".into(),
    },
    "observed-data-embedded-sro" => PatternMatchError::RefResolution {
        path: "observed-data.objects".into(),
        msg: "embedded SRO objects are not supported".into(),
    },
}
