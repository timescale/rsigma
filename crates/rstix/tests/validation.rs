//! Integration tests for bundle semantic validation (`Bundle::validate`).

#![cfg(feature = "serde")]

#[path = "support/fixtures.rs"]
mod fixtures;

use fixtures::load_fixture;
use rstix::model::sdo::{ObservedData, ObservedDataEmbeddedObject, ObservedDataForm};
use rstix::model::{Bundle, ValidationCode};
use rstix::parse_bundle;

#[test]
fn bad_capec_parses_and_warns_on_validate() {
    let bundle = parse_bundle(&load_fixture("validation/bundle-bad-capec.json")).expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::InvalidCapecExternalReference)
            .next()
            .is_some()
    );
}

#[test]
fn bad_cve_parses_and_warns_on_validate() {
    let bundle = parse_bundle(&load_fixture("validation/bundle-bad-cve.json")).expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::InvalidCveExternalReference)
            .next()
            .is_some()
    );
}

#[test]
fn relationship_matrix_invalid_parses_and_warns() {
    let bundle = parse_bundle(&load_fixture(
        "validation/bundle-relationship-matrix-invalid.json",
    ))
    .expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::RelationshipEndpointMatrixInvalid)
            .next()
            .is_some()
    );
}

#[test]
fn bad_encryption_algorithm_parses_and_warns() {
    let bundle =
        parse_bundle(&load_fixture("validation/bundle-bad-encryption.json")).expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::EncryptionAlgorithmInvalid)
            .next()
            .is_some()
    );
}

#[test]
fn granular_selector_semantic_invalid_warns() {
    let bundle = parse_bundle(&load_fixture(
        "validation/bundle-granular-selector-invalid.json",
    ))
    .expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::GranularSelectorSemanticInvalid)
            .next()
            .is_some()
    );
}

#[test]
fn location_bad_country_warns() {
    let bundle =
        parse_bundle(&load_fixture("validation/bundle-location-bad-country.json")).expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::LocationCountryNotIso3166)
            .next()
            .is_some()
    );
}

#[test]
fn observed_data_deprecated_objects_accepts_embedded_sro() {
    let raw = load_fixture("validation/observed-data-objects-with-sro.json");
    let observed: ObservedData = serde_json::from_str(&raw).expect("deserialize");
    match &observed.form {
        ObservedDataForm::DeprecatedObjects(objects) => {
            assert_eq!(objects.len(), 2);
            assert!(matches!(
                objects.get("0"),
                Some(ObservedDataEmbeddedObject::Sco(_))
            ));
            assert!(matches!(
                objects.get("1"),
                Some(ObservedDataEmbeddedObject::Sro(_))
            ));
        }
        ObservedDataForm::ObjectRefs(_) => panic!("expected deprecated objects form"),
    }
}

#[test]
fn location_bad_region_warns() {
    let bundle =
        parse_bundle(&load_fixture("validation/bundle-location-bad-region.json")).expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::LocationRegionNotInOpenVocab)
            .next()
            .is_some()
    );
}

#[test]
fn language_content_list_length_mismatch_warns() {
    let bundle = parse_bundle(&load_fixture(
        "validation/bundle-language-content-list-length.json",
    ))
    .expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::LanguageContentValueMismatch)
            .next()
            .is_some()
    );
}

#[test]
fn language_content_type_mismatch_warns() {
    let bundle = parse_bundle(&load_fixture(
        "validation/bundle-language-content-type-mismatch.json",
    ))
    .expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::LanguageContentValueMismatch)
            .next()
            .is_some()
    );
}

#[test]
fn validate_is_clean_for_minimal_bundle() {
    let raw = fixtures::load_spec_fixture("bundle/bundle-minimal.json");
    let bundle = Bundle::parse(&raw).expect("parse");
    assert!(bundle.validate().is_clean());
}
