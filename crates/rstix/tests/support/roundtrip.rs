//! Deserialize → serialize → deserialize round-trip against a fixture file.

use std::fmt::Debug;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::load_spec_fixture;

/// Load `relative_path` under `tests/fixtures/spec/`, round-trip through JSON, and
/// return the parsed value.
pub fn roundtrip<T>(relative_path: &str) -> T
where
    T: DeserializeOwned + Serialize + PartialEq + Debug,
{
    let json = load_spec_fixture(relative_path);
    let parsed: T = serde_json::from_str(&json).expect("deserialize");
    let reserialized = serde_json::to_string(&parsed).expect("serialize");
    let reparsed: T = serde_json::from_str(&reserialized).expect("reparse");
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
