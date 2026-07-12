//! STIX `type` field validation for typed object deserialization.

use serde::Deserialize;

use crate::model::ModelError;

/// Reject JSON whose `type` field does not match the expected STIX type name.
pub(crate) fn check_stix_type(actual: &str, expected: &'static str) -> Result<(), ModelError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ModelError::UnexpectedObjectType {
            expected,
            actual: actual.to_owned(),
        })
    }
}

/// Deserialize a STIX `type` string and validate it in a single pass (no intermediate
/// [`serde_json::Value`]).
pub(crate) fn deserialize_stix_type_field<'de, D>(
    deserializer: D,
    expected: &'static str,
) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let actual = String::deserialize(deserializer)?;
    check_stix_type(&actual, expected).map_err(ModelError::into_de_custom)?;
    Ok(actual)
}
