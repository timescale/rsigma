//! One integration case per [`DiagnosticCode::ALL`] entry (T4.E1).

#![cfg(feature = "validate")]

#[path = "support/fixtures_root.rs"]
mod fixtures_root;

use std::collections::BTreeSet;

use fixtures_root::load_fixture;
use rstix::{DiagnosticCode, Validator};

#[derive(Clone, Copy)]
enum Profile {
    ConsumerStrict,
    InteropStrict,
}

enum JsonSource {
    /// Complete bundle JSON baked into the test binary.
    Static(&'static str),
    Fixture(&'static str),
    Dynamic(fn() -> String),
}

struct CoverageCase {
    code: DiagnosticCode,
    source: JsonSource,
    profile: Profile,
    label: &'static str,
}

macro_rules! bundle_object {
    ($object:expr) => {
        JsonSource::Dynamic(|| wrap_object($object))
    };
}

fn validator(profile: Profile) -> Validator {
    match profile {
        Profile::ConsumerStrict => Validator::consumer_strict(),
        Profile::InteropStrict => Validator::interop_strict(),
    }
}

fn load_json(source: &JsonSource) -> String {
    match source {
        JsonSource::Static(json) => (*json).to_owned(),
        JsonSource::Fixture(path) => load_fixture(path),
        JsonSource::Dynamic(build) => build(),
    }
}

fn wrap_object(object_json: &str) -> String {
    format!(
        r#"{{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[{object_json}]}}"#
    )
}

fn wrap_fixture_object(relative_path: &str) -> String {
    wrap_object(&load_fixture(relative_path))
}

fn long_custom_type_bundle() -> String {
    let type_name = format!("x-{}", "a".repeat(249));
    format!(
        r#"{{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[{{"type":"{type_name}","id":"{type_name}--00000000-0000-0000-0000-000000000001"}}]}}"#
    )
}

fn coverage_cases() -> Vec<CoverageCase> {
    vec![
        CoverageCase {
            code: DiagnosticCode::E0001,
            source: JsonSource::Static("{not-json"),
            profile: Profile::ConsumerStrict,
            label: "malformed json",
        },
        CoverageCase {
            code: DiagnosticCode::E0002,
            source: JsonSource::Static("{}"),
            profile: Profile::ConsumerStrict,
            label: "missing root type",
        },
        CoverageCase {
            code: DiagnosticCode::E0003,
            source: JsonSource::Fixture("conformance/invalid/missing_object_id.json"),
            profile: Profile::ConsumerStrict,
            label: "missing object id",
        },
        CoverageCase {
            code: DiagnosticCode::E0004,
            source: bundle_object!(
                r#"{"type":"malware","spec_version":"2.1","id":"malware--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","is_family":true}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "malware family missing name",
        },
        CoverageCase {
            code: DiagnosticCode::E0005,
            source: JsonSource::Dynamic(|| {
                wrap_fixture_object("spec/meta/extension-definition-missing-created-by-ref.json")
            }),
            profile: Profile::ConsumerStrict,
            label: "extension-definition missing created_by_ref",
        },
        CoverageCase {
            code: DiagnosticCode::E0006,
            source: bundle_object!(
                r#"{"type":"identity","spec_version":"2.1","id":"identity--11111111-1111-4111-8111-111111111111","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"x","identity_class":"organization","severity":"high"}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "reserved custom property",
        },
        CoverageCase {
            code: DiagnosticCode::E0007,
            source: JsonSource::Dynamic(|| {
                wrap_fixture_object("spec/sdo/observed-data-both-content.json")
            }),
            profile: Profile::ConsumerStrict,
            label: "observed-data both objects and object_refs",
        },
        CoverageCase {
            code: DiagnosticCode::E0008,
            source: JsonSource::Dynamic(|| {
                wrap_fixture_object("spec/sdo/observed-data-neither-content.json")
            }),
            profile: Profile::ConsumerStrict,
            label: "observed-data missing sco content",
        },
        CoverageCase {
            code: DiagnosticCode::E0009,
            source: bundle_object!(
                r#"{"type":"email-message","spec_version":"2.1","id":"email-message--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061","is_multipart":false,"body":"hello","body_multipart":[{"body":"part"}]}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "email-message body xor multipart",
        },
        CoverageCase {
            code: DiagnosticCode::E0010,
            source: bundle_object!(
                r#"{"type":"indicator","spec_version":"2.1","id":"indicator--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","pattern":"[ipv4-addr:value = 'broken","pattern_type":"stix","valid_from":"2020-01-01T00:00:00.000Z"}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "indicator pattern parse failure",
        },
        CoverageCase {
            code: DiagnosticCode::E0011,
            source: bundle_object!(
                r#"{"type":"indicator","spec_version":"2.1","id":"indicator--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","pattern":"[ipv4-addr:not_a_property = 'x']","pattern_type":"stix","valid_from":"2020-01-01T00:00:00.000Z"}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "indicator pattern type-check failure",
        },
        CoverageCase {
            code: DiagnosticCode::E0012,
            source: bundle_object!(
                r#"{"type":"identity","spec_version":"2.1","id":"identity--11111111-1111-4111-8111-111111111111","created":"2020-01-01T00:00:00Z","modified":"2020-01-01T00:00:00.000Z","name":"x","identity_class":"organization"}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "short timestamp fractional digits",
        },
        CoverageCase {
            code: DiagnosticCode::E0013,
            source: bundle_object!(
                r#"{"type":"opinion","spec_version":"2.1","id":"opinion--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","opinion":"not-a-valid-opinion","object_refs":["indicator--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"]}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "unknown opinion closed vocabulary",
        },
        CoverageCase {
            code: DiagnosticCode::W0010,
            source: JsonSource::Fixture("validation/bundle-bad-encryption.json"),
            profile: Profile::ConsumerStrict,
            label: "closed vocabulary encryption_algorithm",
        },
        CoverageCase {
            code: DiagnosticCode::E0014,
            source: bundle_object!(
                r#"{"type":"identity","spec_version":"2.1","id":"identity--11111111-1111-4111-8111-111111111111","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"x","identity_class":"organization","x_score":9007199254740993}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "unsafe integer magnitude",
        },
        CoverageCase {
            code: DiagnosticCode::E0015,
            source: bundle_object!(
                r#"{"type":"identity","spec_version":"2.1","id":"identity--11111111-1111-4111-8111-111111111111","created":"2020-01-02T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"x","identity_class":"organization"}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "modified before created",
        },
        CoverageCase {
            code: DiagnosticCode::E0020,
            source: bundle_object!(
                r#"{"type":"sighting","spec_version":"2.1","id":"sighting--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","first_seen":"2020-01-01T00:00:00.000Z","last_seen":"2020-01-01T00:00:00.000Z","sighting_of_ref":"domain-name--00000000-0000-0000-0000-000000000001"}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "sighting_of_ref points to sco",
        },
        CoverageCase {
            code: DiagnosticCode::E0021,
            source: JsonSource::Dynamic(|| {
                wrap_fixture_object("spec/sdo/malware-sample-ref-invalid.json")
            }),
            profile: Profile::ConsumerStrict,
            label: "invalid malware sample_ref kind",
        },
        CoverageCase {
            code: DiagnosticCode::E0022,
            source: bundle_object!(
                r#"{"type":"identity","spec_version":"2.1","id":"identity--11111111-1111-4111-8111-111111111111","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"x","identity_class":"organization","object_marking_refs":["identity--22222222-2222-4222-8222-222222222222"]}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "object_marking_refs not marking-definition",
        },
        CoverageCase {
            code: DiagnosticCode::E0023,
            source: bundle_object!(
                r#"{"type":"identity","spec_version":"2.1","id":"identity--11111111-1111-4111-8111-111111111111","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"x","identity_class":"organization","granular_markings":[{"selectors":["name"],"marking_ref":"identity--22222222-2222-4222-8222-222222222222"}]}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "granular marking_ref not marking-definition",
        },
        CoverageCase {
            code: DiagnosticCode::E0024,
            source: JsonSource::Fixture("validation/bundle-granular-selector-invalid.json"),
            profile: Profile::ConsumerStrict,
            label: "invalid granular selector",
        },
        CoverageCase {
            code: DiagnosticCode::E0030,
            source: bundle_object!(
                r#"{"type":"identity","spec_version":"2.1","id":"identity--11111111-1111-4111-8111-111111111111","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"x","identity_class":"organization","extensions":{"extension-definition--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa":{"extension_type":"not-a-real-type"}}}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "unknown extension_type",
        },
        CoverageCase {
            code: DiagnosticCode::E0031,
            source: bundle_object!(
                r#"{"type":"identity","spec_version":"2.1","id":"identity--11111111-1111-4111-8111-111111111111","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"x","identity_class":"organization","extensions":{"extension-definition--60477d8d-78ac-1058-8160-d776f9386f83":{"extension_type":"toplevel-property-extension","x_custom":"nested-only"}}}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "toplevel property extension not hoisted",
        },
        CoverageCase {
            code: DiagnosticCode::E0040,
            source: bundle_object!(
                r#"{"type":"identity","spec_version":"2.1","id":"identity--11111111-1111-4111-8111-111111111111","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"x","identity_class":"organization","granular_markings":[{"selectors":["name"]}]}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "granular marking missing ref and lang",
        },
        CoverageCase {
            code: DiagnosticCode::E0041,
            source: bundle_object!(
                r#"{"type":"identity","spec_version":"2.1","id":"identity--11111111-1111-4111-8111-111111111111","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"x","identity_class":"organization","granular_markings":[{"selectors":["name"],"lang":"en","marking_ref":"marking-definition--94868c89-73b8-4b43-b99e-6a4f9d6ded18"}]}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "granular marking both ref and lang",
        },
        CoverageCase {
            code: DiagnosticCode::E0050,
            source: JsonSource::Dynamic(long_custom_type_bundle),
            profile: Profile::ConsumerStrict,
            label: "custom type name too long",
        },
        CoverageCase {
            code: DiagnosticCode::E0051,
            source: bundle_object!(
                r#"{"type":"x-Bad-Upper","id":"x-Bad-Upper--00000000-0000-0000-0000-000000000001"}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "custom type invalid charset",
        },
        CoverageCase {
            code: DiagnosticCode::E0052,
            source: bundle_object!(
                r#"{"type":"x-my--type","id":"x-my--type--00000000-0000-0000-0000-000000000001"}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "custom type double hyphen",
        },
        CoverageCase {
            code: DiagnosticCode::W0002,
            source: JsonSource::Fixture("validation/bundle-sco-deterministic-id-mismatch.json"),
            profile: Profile::InteropStrict,
            label: "sco deterministic id mismatch",
        },
        CoverageCase {
            code: DiagnosticCode::W0003,
            source: JsonSource::Static(
                r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[{"type":"malware","spec_version":"2.1","id":"malware--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","revoked":true,"name":"revoked","is_family":false},{"type":"malware","spec_version":"2.1","id":"malware--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-02T00:00:00.000Z","name":"later","is_family":false}]}"#,
            ),
            profile: Profile::InteropStrict,
            label: "version after revocation",
        },
        CoverageCase {
            code: DiagnosticCode::W0004,
            source: JsonSource::Fixture("conformance/versioning/third_party_version.json"),
            profile: Profile::InteropStrict,
            label: "third-party version",
        },
        CoverageCase {
            code: DiagnosticCode::W0010,
            source: JsonSource::Fixture("validation/bundle-bad-capec.json"),
            profile: Profile::ConsumerStrict,
            label: "unresolved capec external reference",
        },
        CoverageCase {
            code: DiagnosticCode::W0020,
            source: bundle_object!(
                r#"{"type":"identity","spec_version":"2.1","id":"identity--11111111-1111-4111-8111-111111111111","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"x","identity_class":"organization","extensions":{"extension-definition--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa":{"extension_type":"property-extension","x_custom":"v"}}}"#
            ),
            profile: Profile::InteropStrict,
            label: "unknown extension definition id",
        },
        CoverageCase {
            code: DiagnosticCode::W0030,
            source: bundle_object!(
                r#"{"type":"marking-definition","spec_version":"2.1","id":"marking-definition--94868c89-73b8-4b43-b99e-6a4f9d6ded18","created":"2022-03-11T19:45:00.000Z","definition_type":"tlp","definition":{"tlp":"amber+stict"}}"#
            ),
            profile: Profile::InteropStrict,
            label: "tlp amber+stict typo",
        },
        CoverageCase {
            code: DiagnosticCode::W0031,
            source: JsonSource::Fixture("validation/bundle-tlp1-marking-ref.json"),
            profile: Profile::ConsumerStrict,
            label: "tlp 1.x marking reference",
        },
        CoverageCase {
            code: DiagnosticCode::W0040,
            source: bundle_object!(
                r#"{"type":"domain-name","spec_version":"2.1","id":"domain-name--00000000-0000-0000-0000-000000000001","value":"example.com","created":"2020-01-01T00:00:00.000Z"}"#
            ),
            profile: Profile::InteropStrict,
            label: "sco forbidden common property",
        },
        CoverageCase {
            code: DiagnosticCode::I0001,
            source: JsonSource::Fixture("validation/bundle-location-bad-region.json"),
            profile: Profile::ConsumerStrict,
            label: "open vocabulary region extension",
        },
        CoverageCase {
            code: DiagnosticCode::I0002,
            source: JsonSource::Fixture("validation/bundle-relationship-matrix-invalid.json"),
            profile: Profile::ConsumerStrict,
            label: "relationship endpoint matrix",
        },
        CoverageCase {
            code: DiagnosticCode::I0010,
            source: bundle_object!(
                r#"{"type":"my-custom-type","id":"my-custom-type--00000000-0000-0000-0000-000000000001"}"#
            ),
            profile: Profile::ConsumerStrict,
            label: "custom type without x- prefix",
        },
        CoverageCase {
            code: DiagnosticCode::H0001,
            source: JsonSource::Static("{}"),
            profile: Profile::ConsumerStrict,
            label: "missing root type hint",
        },
    ]
}

#[test]
fn each_diagnostic_code_is_emitted_by_pipeline() {
    let cases = coverage_cases();
    let mut covered = BTreeSet::new();

    for case in &cases {
        let json = load_json(&case.source);
        let report = validator(case.profile).validate_json_str(&json);
        assert!(
            report.with_code(case.code).next().is_some(),
            "expected {} for {} ({})",
            case.code.as_str(),
            case.label,
            match &case.source {
                JsonSource::Fixture(path) => *path,
                JsonSource::Static(_) | JsonSource::Dynamic(_) => case.label,
            }
        );
        covered.insert(case.code.as_str());
    }

    for code in DiagnosticCode::ALL {
        assert!(
            covered.contains(code.as_str()),
            "coverage_cases() missing entry for {}",
            code.as_str()
        );
    }
    assert_eq!(covered.len(), DiagnosticCode::ALL.len());
}
