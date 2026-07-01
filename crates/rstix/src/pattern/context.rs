//! Evaluation context for STIX patterns (STIX Specification §9).

use crate::core::{StixId, StixTimestamp};
use crate::model::Bundle;
use crate::model::StixObject;
use crate::model::sco::ScoObject;
use crate::model::sdo::{ObservedData, ObservedDataEmbeddedObject, ObservedDataForm};

/// One cyber-observable plus when it was observed.
#[derive(Clone, Debug, PartialEq)]
pub struct TimestampedObservation<'a> {
    /// The cyber-observable object.
    pub sco: &'a ScoObject,
    /// When this SCO was observed (`None` when the source lacks a timestamp).
    pub at: Option<StixTimestamp>,
}

/// Input to [`crate::pattern::Pattern::evaluate`].
#[derive(Clone, Debug, PartialEq)]
pub struct ObservationContext<'a> {
    /// Timestamped SCO instances available for matching.
    pub observations: &'a [TimestampedObservation<'a>],
    /// When set, `_ref` paths resolve against objects in this bundle.
    pub bundle: Option<&'a Bundle>,
}

impl<'a> ObservationContext<'a> {
    /// Build a context from standalone SCO observations (no bundle).
    ///
    /// Use when evaluating patterns that do not dereference `_ref` paths, or supply
    /// [`ObservationContext::bundle`] when ref chains need bundle lookup.
    pub fn from_scos(observations: &'a [TimestampedObservation<'a>]) -> Self {
        Self {
            observations,
            bundle: None,
        }
    }
}

/// Build timestamped observations from an [`ObservedData`] SDO and its bundle.
///
/// Each referenced or embedded SCO is stamped with [`ObservedData::first_observed`]
/// as its observation time. When `object_refs` is used, every referenced SCO shares
/// that timestamp (STIX §4.14 sighting window start). `last_observed` is not used to
/// synthesize per-SCO timestamps in this release.
pub(crate) fn build_observations_from_observed_data<'a>(
    observed_data: &'a ObservedData,
    bundle: &'a Bundle,
) -> Result<Vec<TimestampedObservation<'a>>, ObservedDataContextError> {
    let mut observations = Vec::new();
    let at = observed_data.first_observed.clone();
    match &observed_data.form {
        ObservedDataForm::ObjectRefs(refs) => {
            ensure_observation_capacity(refs.len())?;
            for id in refs {
                let Some(obj) = bundle.get(id) else {
                    return Err(ObservedDataContextError::MissingObject { id: id.clone() });
                };
                let StixObject::Sco(sco) = obj else {
                    return Err(ObservedDataContextError::NotSco {
                        id: id.clone(),
                        type_name: QueryableStixObject::type_name(obj).to_owned(),
                    });
                };
                observations.push(TimestampedObservation {
                    sco,
                    at: Some(at.clone()),
                });
            }
        }
        ObservedDataForm::DeprecatedObjects(objects) => {
            let sco_count = objects
                .values()
                .filter(|embedded| matches!(embedded, ObservedDataEmbeddedObject::Sco(_)))
                .count();
            ensure_observation_capacity(sco_count)?;
            for embedded in objects.values() {
                let sco = match embedded {
                    ObservedDataEmbeddedObject::Sco(sco) => sco,
                    ObservedDataEmbeddedObject::Sro(_) => continue,
                };
                observations.push(TimestampedObservation {
                    sco,
                    at: Some(at.clone()),
                });
            }
        }
    }
    Ok(observations)
}

fn ensure_observation_capacity(count: usize) -> Result<(), ObservedDataContextError> {
    if count > crate::pattern::lexer::MAX_OBSERVATIONS {
        return Err(ObservedDataContextError::TooManyObservations {
            count,
            max: crate::pattern::lexer::MAX_OBSERVATIONS,
        });
    }
    Ok(())
}

use crate::core::QueryableStixObject;

/// Error building an evaluation context from observed-data.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ObservedDataContextError {
    /// A referenced object id was not found in the bundle.
    #[error("observed-data references missing object `{id}`")]
    MissingObject {
        /// Missing STIX id.
        id: StixId,
    },
    /// An `object_refs` entry is not an SCO.
    #[error("observed-data reference `{id}` has type `{type_name}`, expected an SCO")]
    NotSco {
        /// Referenced id.
        id: StixId,
        /// Actual STIX type.
        type_name: String,
    },
    /// Deprecated embedded SRO members are skipped (not included in observations).
    #[error("observed-data embedded SRO objects are not supported for pattern evaluation")]
    EmbeddedSroNotSupported,
    /// Observation count exceeds the evaluation cap.
    #[error("observed-data yields {count} SCO observations; maximum is {max}")]
    TooManyObservations {
        /// Resolved SCO count.
        count: usize,
        /// Configured maximum.
        max: usize,
    },
}

impl From<ObservedDataContextError> for crate::pattern::error::PatternMatchError {
    fn from(err: ObservedDataContextError) -> Self {
        match err {
            ObservedDataContextError::MissingObject { id } => Self::RefResolution {
                path: "observed-data.object_refs".into(),
                msg: format!("missing object `{id}`"),
            },
            ObservedDataContextError::NotSco { id, type_name } => Self::RefResolution {
                path: "observed-data.object_refs".into(),
                msg: format!("object `{id}` has type `{type_name}`, expected an SCO"),
            },
            ObservedDataContextError::EmbeddedSroNotSupported => Self::RefResolution {
                path: "observed-data.objects".into(),
                msg: "embedded SRO objects are not supported".into(),
            },
            ObservedDataContextError::TooManyObservations { count, max } => {
                Self::TooManyObservations { count, max }
            }
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::pattern::error::PatternMatchError;

    #[test]
    fn from_scos_wraps_slice() {
        let json = include_str!("../../tests/fixtures/spec/sco/ipv4-addr-single.json");
        let sco = ScoObject::Ipv4Addr(serde_json::from_str(json).expect("parse"));
        let at = StixTimestamp::parse("2024-01-01T00:00:00.000Z").expect("ts");
        let obs = [TimestampedObservation {
            sco: &sco,
            at: Some(at.clone()),
        }];
        let ctx = ObservationContext::from_scos(&obs);
        assert_eq!(ctx.observations.len(), 1);
        assert!(ctx.bundle.is_none());
    }

    #[test]
    fn observed_data_missing_object_ref() {
        use crate::core::StixId;
        use crate::model::Bundle;
        use crate::model::sdo::ObservedData;

        let observed: ObservedData = serde_json::from_str(include_str!(
            "../../tests/fixtures/spec/sdo/observed-data-object-refs.json"
        ))
        .expect("observed-data");
        let bundle = Bundle::from_objects_for_test(
            StixId::parse("bundle--00000000-0000-0000-0000-000000000001").expect("id"),
            vec![],
        );
        let err = build_observations_from_observed_data(&observed, &bundle).unwrap_err();
        assert!(matches!(
            err,
            ObservedDataContextError::MissingObject { .. }
        ));
        assert_eq!(
            PatternMatchError::from(err),
            PatternMatchError::RefResolution {
                path: "observed-data.object_refs".into(),
                msg: "missing object `ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8`".into(),
            }
        );
    }

    #[test]
    fn observed_data_object_ref_not_sco() {
        use crate::core::StixId;
        use crate::model::Bundle;
        use crate::model::StixObject;
        use crate::model::sdo::ObservedData;
        use crate::model::sro::Relationship;

        let observed_json = r#"{
          "type": "observed-data",
          "spec_version": "2.1",
          "id": "observed-data--00000000-0000-0000-0000-000000000011",
          "created": "2024-01-01T00:00:00.000Z",
          "modified": "2024-01-01T00:00:00.000Z",
          "first_observed": "2024-01-01T00:00:00.000Z",
          "last_observed": "2024-01-01T00:00:00.000Z",
          "number_observed": 1,
          "object_refs": ["relationship--00000000-0000-0000-0000-000000000001"]
        }"#;
        let observed: ObservedData = serde_json::from_str(observed_json).expect("observed-data");
        let relationship: Relationship = serde_json::from_str(
            r#"{
              "type": "relationship",
              "spec_version": "2.1",
              "id": "relationship--00000000-0000-0000-0000-000000000001",
              "created": "2024-01-01T00:00:00.000Z",
              "modified": "2024-01-01T00:00:00.000Z",
              "relationship_type": "related-to",
              "source_ref": "identity--00000000-0000-0000-0000-000000000001",
              "target_ref": "identity--00000000-0000-0000-0000-000000000002"
            }"#,
        )
        .expect("relationship");
        let bundle = Bundle::from_objects_for_test(
            StixId::parse("bundle--00000000-0000-0000-0000-000000000002").expect("id"),
            vec![StixObject::Sro(crate::model::sro::SroObject::Relationship(
                relationship,
            ))],
        );
        let err = build_observations_from_observed_data(&observed, &bundle).unwrap_err();
        assert!(matches!(err, ObservedDataContextError::NotSco { .. }));
        assert_eq!(
            PatternMatchError::from(err),
            PatternMatchError::RefResolution {
                path: "observed-data.object_refs".into(),
                msg: "object `relationship--00000000-0000-0000-0000-000000000001` has type `relationship`, expected an SCO".into(),
            }
        );
    }

    #[test]
    fn observed_data_embedded_sro_error_mapping() {
        let err = ObservedDataContextError::EmbeddedSroNotSupported;
        assert_eq!(
            PatternMatchError::from(err),
            PatternMatchError::RefResolution {
                path: "observed-data.objects".into(),
                msg: "embedded SRO objects are not supported".into(),
            }
        );
    }
}
