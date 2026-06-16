//! Core traits for STIX object querying.

use crate::core::{SpecVersion, StixId, StixTimestamp};

/// Implemented by every STIX object type that can be queried by pattern/runtime logic.
pub trait QueryableStixObject: Send + Sync + 'static {
    /// Object identifier.
    fn id(&self) -> &StixId;
    /// Object type string.
    fn type_name(&self) -> &'static str;
    /// Optional object spec version.
    fn spec_version(&self) -> Option<SpecVersion>;
    /// Created timestamp (SCOs may return `None`).
    fn created(&self) -> Option<&StixTimestamp>;
    /// Modified timestamp (SCOs may return `None`).
    fn modified(&self) -> Option<&StixTimestamp>;
    /// Property path access.
    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>>;
}

/// Borrowed query value abstraction used by pattern/runtime.
#[derive(Debug, PartialEq)]
pub enum QueryValue<'a> {
    /// String value.
    Str(&'a str),
    /// Integer value.
    Int(i64),
    /// Floating point value.
    Float(f64),
    /// Boolean value.
    Bool(bool),
    /// Timestamp value.
    Timestamp(&'a StixTimestamp),
    /// STIX object reference id.
    Id(&'a StixId),
    /// Null value.
    Null,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{SpecVersion, StixId, StixTimestamp};

    struct DummyObject {
        id: StixId,
        created: StixTimestamp,
    }

    impl QueryableStixObject for DummyObject {
        fn id(&self) -> &StixId {
            &self.id
        }

        fn type_name(&self) -> &'static str {
            "indicator"
        }

        fn spec_version(&self) -> Option<SpecVersion> {
            Some(SpecVersion::V2_1)
        }

        fn created(&self) -> Option<&StixTimestamp> {
            Some(&self.created)
        }

        fn modified(&self) -> Option<&StixTimestamp> {
            Some(&self.created)
        }

        fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
            if path == ["name"] {
                Some(QueryValue::Str("dummy"))
            } else {
                None
            }
        }
    }

    #[test]
    fn trait_is_dyn_safe() {
        let id = StixId::parse("indicator--550e8400-e29b-41d4-a716-446655440000").expect("id");
        let created = StixTimestamp::parse("2024-01-01T00:00:00.000Z").expect("ts");
        let obj = DummyObject { id, created };
        let boxed: Box<dyn QueryableStixObject> = Box::new(obj);
        assert_eq!(boxed.type_name(), "indicator");
        assert_eq!(boxed.get_field(&["name"]), Some(QueryValue::Str("dummy")));
    }
}
