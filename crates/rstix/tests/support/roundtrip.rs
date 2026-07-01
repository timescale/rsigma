//! Deserialize → serialize → deserialize round-trip against a fixture file.

use std::fmt::Debug;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::fixtures_spec::load_spec_fixture;

/// Load `relative_path`, round-trip through JSON with **strict** fixture equality, and
/// return the parsed value.
///
/// Use for complete types that must not drop any fixture field on re-serialize.
pub fn roundtrip_strict<T>(relative_path: &str) -> T
where
    T: DeserializeOwned + Serialize + PartialEq + Debug,
{
    roundtrip_inner(relative_path, true)
}

/// Load `relative_path`, round-trip through JSON with **subset** fixture comparison,
/// and return the parsed value.
///
/// Use when the type deliberately ignores extra fixture keys (for example
/// `SdoSroCommonProps` fixtures that carry SDO-specific fields not modeled yet).
/// Subset comparison does not catch dropped fixture fields on object fixtures; see
/// [`assert_reserialized_matches_fixture_subset`].
pub fn roundtrip<T>(relative_path: &str) -> T
where
    T: DeserializeOwned + Serialize + PartialEq + Debug,
{
    roundtrip_inner(relative_path, false)
}

fn roundtrip_inner<T>(relative_path: &str, strict: bool) -> T
where
    T: DeserializeOwned + Serialize + PartialEq + Debug,
{
    let json = load_spec_fixture(relative_path);
    let original: serde_json::Value = serde_json::from_str(&json).expect("parse fixture");
    let parsed: T = serde_json::from_str(&json).expect("deserialize");
    let reserialized_value = serde_json::to_value(&parsed).expect("serialize to value");
    if strict {
        assert_eq!(
            original, reserialized_value,
            "strict round-trip: re-serialized value must equal fixture ({relative_path})"
        );
    } else {
        assert_reserialized_matches_fixture_subset(&original, &reserialized_value);
    }
    let reparsed: T = serde_json::from_value(reserialized_value).expect("reparse");
    assert_eq!(parsed, reparsed);
    parsed
}

/// Assert that deserializing `relative_path` fails.
pub fn assert_fixture_rejects<T: DeserializeOwned>(relative_path: &str) {
    let json = load_spec_fixture(relative_path);
    assert!(
        serde_json::from_str::<T>(&json).is_err(),
        "expected {relative_path} to fail deserialization"
    );
}

/// Subset compare used by [`roundtrip`]: for object fixtures, every emitted field
/// must match the fixture, but extra fixture keys are allowed; dropped fields are
/// NOT caught by this object-vs-object arm. Only non-object fixtures use full value
/// equality. Prefer [`roundtrip_strict`] for complete types that must not drop any
/// fixture field today.
fn assert_reserialized_matches_fixture_subset(
    original: &serde_json::Value,
    reserialized: &serde_json::Value,
) {
    match (original, reserialized) {
        (serde_json::Value::Object(original), serde_json::Value::Object(reserialized)) => {
            for (key, reserialized_value) in reserialized {
                assert_eq!(
                    original.get(key),
                    Some(reserialized_value),
                    "reserialized field `{key}` does not match fixture"
                );
            }
        }
        _ => assert_eq!(
            original, reserialized,
            "reserialized value does not match fixture"
        ),
    }
}
