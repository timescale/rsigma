//! STIX Domain Objects (SDOs).
//!
//! Batch 1 (§4.1–4.6, §4.17–4.18): attack-pattern, campaign, course-of-action,
//! grouping, identity, incident, threat-actor, tool.
//!
//! All 19 STIX 2.1 SDO types are modeled; [`SdoObject`] provides enum dispatch.

mod ref_types;

mod attack_pattern;
mod campaign;
mod course_of_action;
mod grouping;
mod identity;
mod incident;
mod indicator;
mod infrastructure;
mod intrusion_set;
mod location;
mod malware;
mod malware_analysis;
mod note;
mod observed_data;
mod opinion;
mod report;
mod threat_actor;
mod tool;
mod vulnerability;

pub use attack_pattern::AttackPattern;
pub use campaign::Campaign;
pub use course_of_action::CourseOfAction;
pub use grouping::Grouping;
pub use identity::Identity;
pub use incident::Incident;
pub use indicator::{Indicator, IndicatorPattern};
pub use infrastructure::Infrastructure;
pub use intrusion_set::IntrusionSet;
pub use location::Location;
pub use malware::Malware;
pub use malware_analysis::MalwareAnalysis;
pub use note::Note;
pub use observed_data::{ObservedData, ObservedDataEmbeddedObject, ObservedDataForm};
pub use opinion::Opinion;
pub use ref_types::{MalwareAnalysisSampleRef, MalwareSampleRef};
pub use report::Report;
pub use threat_actor::ThreatActor;
pub use tool::Tool;
pub use vulnerability::Vulnerability;

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};

/// STIX SDO enum (19 variants).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum SdoObject {
    /// STIX `attack-pattern` object.
    AttackPattern(AttackPattern),
    /// STIX `campaign` object.
    Campaign(Campaign),
    /// STIX `course-of-action` object.
    CourseOfAction(CourseOfAction),
    /// STIX `grouping` object.
    Grouping(Grouping),
    /// STIX `identity` object.
    Identity(Identity),
    /// STIX `incident` object.
    Incident(Incident),
    /// STIX `indicator` object.
    Indicator(Indicator),
    /// STIX `infrastructure` object.
    Infrastructure(Infrastructure),
    /// STIX `intrusion-set` object.
    IntrusionSet(IntrusionSet),
    /// STIX `location` object.
    Location(Location),
    /// STIX `malware` object.
    Malware(Malware),
    /// STIX `malware-analysis` object.
    MalwareAnalysis(MalwareAnalysis),
    /// STIX `note` object.
    Note(Note),
    /// STIX `observed-data` object.
    ObservedData(ObservedData),
    /// STIX `opinion` object.
    Opinion(Opinion),
    /// STIX `report` object.
    Report(Report),
    /// STIX `threat-actor` object.
    ThreatActor(ThreatActor),
    /// STIX `tool` object.
    Tool(Tool),
    /// STIX `vulnerability` object.
    Vulnerability(Vulnerability),
}

impl SdoObject {
    /// Borrow shared SDO/SRO common properties.
    pub fn common_props(&self) -> &crate::model::common::SdoSroCommonProps {
        match self {
            Self::AttackPattern(inner) => &inner.common,
            Self::Campaign(inner) => &inner.common,
            Self::CourseOfAction(inner) => &inner.common,
            Self::Grouping(inner) => &inner.common,
            Self::Identity(inner) => &inner.common,
            Self::Incident(inner) => &inner.common,
            Self::Indicator(inner) => &inner.common,
            Self::Infrastructure(inner) => &inner.common,
            Self::IntrusionSet(inner) => &inner.common,
            Self::Location(inner) => &inner.common,
            Self::Malware(inner) => &inner.common,
            Self::MalwareAnalysis(inner) => &inner.common,
            Self::Note(inner) => &inner.common,
            Self::ObservedData(inner) => &inner.common,
            Self::Opinion(inner) => &inner.common,
            Self::Report(inner) => &inner.common,
            Self::ThreatActor(inner) => &inner.common,
            Self::Tool(inner) => &inner.common,
            Self::Vulnerability(inner) => &inner.common,
        }
    }

    pub(crate) fn common_props_mut(&mut self) -> &mut crate::model::common::SdoSroCommonProps {
        match self {
            Self::AttackPattern(inner) => &mut inner.common,
            Self::Campaign(inner) => &mut inner.common,
            Self::CourseOfAction(inner) => &mut inner.common,
            Self::Grouping(inner) => &mut inner.common,
            Self::Identity(inner) => &mut inner.common,
            Self::Incident(inner) => &mut inner.common,
            Self::Indicator(inner) => &mut inner.common,
            Self::Infrastructure(inner) => &mut inner.common,
            Self::IntrusionSet(inner) => &mut inner.common,
            Self::Location(inner) => &mut inner.common,
            Self::Malware(inner) => &mut inner.common,
            Self::MalwareAnalysis(inner) => &mut inner.common,
            Self::Note(inner) => &mut inner.common,
            Self::ObservedData(inner) => &mut inner.common,
            Self::Opinion(inner) => &mut inner.common,
            Self::Report(inner) => &mut inner.common,
            Self::ThreatActor(inner) => &mut inner.common,
            Self::Tool(inner) => &mut inner.common,
            Self::Vulnerability(inner) => &mut inner.common,
        }
    }
}

impl QueryableStixObject for SdoObject {
    fn id(&self) -> &StixId {
        match self {
            Self::AttackPattern(inner) => inner.id(),
            Self::Campaign(inner) => inner.id(),
            Self::CourseOfAction(inner) => inner.id(),
            Self::Grouping(inner) => inner.id(),
            Self::Identity(inner) => inner.id(),
            Self::Incident(inner) => inner.id(),
            Self::Indicator(inner) => inner.id(),
            Self::Infrastructure(inner) => inner.id(),
            Self::IntrusionSet(inner) => inner.id(),
            Self::Location(inner) => inner.id(),
            Self::Malware(inner) => inner.id(),
            Self::MalwareAnalysis(inner) => inner.id(),
            Self::Note(inner) => inner.id(),
            Self::ObservedData(inner) => inner.id(),
            Self::Opinion(inner) => inner.id(),
            Self::Report(inner) => inner.id(),
            Self::ThreatActor(inner) => inner.id(),
            Self::Tool(inner) => inner.id(),
            Self::Vulnerability(inner) => inner.id(),
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            Self::AttackPattern(_) => AttackPattern::TYPE_NAME,
            Self::Campaign(_) => Campaign::TYPE_NAME,
            Self::CourseOfAction(_) => CourseOfAction::TYPE_NAME,
            Self::Grouping(_) => Grouping::TYPE_NAME,
            Self::Identity(_) => Identity::TYPE_NAME,
            Self::Incident(_) => Incident::TYPE_NAME,
            Self::Indicator(_) => Indicator::TYPE_NAME,
            Self::Infrastructure(_) => Infrastructure::TYPE_NAME,
            Self::IntrusionSet(_) => IntrusionSet::TYPE_NAME,
            Self::Location(_) => Location::TYPE_NAME,
            Self::Malware(_) => Malware::TYPE_NAME,
            Self::MalwareAnalysis(_) => MalwareAnalysis::TYPE_NAME,
            Self::Note(_) => Note::TYPE_NAME,
            Self::ObservedData(_) => ObservedData::TYPE_NAME,
            Self::Opinion(_) => Opinion::TYPE_NAME,
            Self::Report(_) => Report::TYPE_NAME,
            Self::ThreatActor(_) => ThreatActor::TYPE_NAME,
            Self::Tool(_) => Tool::TYPE_NAME,
            Self::Vulnerability(_) => Vulnerability::TYPE_NAME,
        }
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        match self {
            Self::AttackPattern(inner) => inner.spec_version(),
            Self::Campaign(inner) => inner.spec_version(),
            Self::CourseOfAction(inner) => inner.spec_version(),
            Self::Grouping(inner) => inner.spec_version(),
            Self::Identity(inner) => inner.spec_version(),
            Self::Incident(inner) => inner.spec_version(),
            Self::Indicator(inner) => inner.spec_version(),
            Self::Infrastructure(inner) => inner.spec_version(),
            Self::IntrusionSet(inner) => inner.spec_version(),
            Self::Location(inner) => inner.spec_version(),
            Self::Malware(inner) => inner.spec_version(),
            Self::MalwareAnalysis(inner) => inner.spec_version(),
            Self::Note(inner) => inner.spec_version(),
            Self::ObservedData(inner) => inner.spec_version(),
            Self::Opinion(inner) => inner.spec_version(),
            Self::Report(inner) => inner.spec_version(),
            Self::ThreatActor(inner) => inner.spec_version(),
            Self::Tool(inner) => inner.spec_version(),
            Self::Vulnerability(inner) => inner.spec_version(),
        }
    }

    fn created(&self) -> Option<&StixTimestamp> {
        match self {
            Self::AttackPattern(inner) => inner.created(),
            Self::Campaign(inner) => inner.created(),
            Self::CourseOfAction(inner) => inner.created(),
            Self::Grouping(inner) => inner.created(),
            Self::Identity(inner) => inner.created(),
            Self::Incident(inner) => inner.created(),
            Self::Indicator(inner) => inner.created(),
            Self::Infrastructure(inner) => inner.created(),
            Self::IntrusionSet(inner) => inner.created(),
            Self::Location(inner) => inner.created(),
            Self::Malware(inner) => inner.created(),
            Self::MalwareAnalysis(inner) => inner.created(),
            Self::Note(inner) => inner.created(),
            Self::ObservedData(inner) => inner.created(),
            Self::Opinion(inner) => inner.created(),
            Self::Report(inner) => inner.created(),
            Self::ThreatActor(inner) => inner.created(),
            Self::Tool(inner) => inner.created(),
            Self::Vulnerability(inner) => inner.created(),
        }
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        match self {
            Self::AttackPattern(inner) => inner.modified(),
            Self::Campaign(inner) => inner.modified(),
            Self::CourseOfAction(inner) => inner.modified(),
            Self::Grouping(inner) => inner.modified(),
            Self::Identity(inner) => inner.modified(),
            Self::Incident(inner) => inner.modified(),
            Self::Indicator(inner) => inner.modified(),
            Self::Infrastructure(inner) => inner.modified(),
            Self::IntrusionSet(inner) => inner.modified(),
            Self::Location(inner) => inner.modified(),
            Self::Malware(inner) => inner.modified(),
            Self::MalwareAnalysis(inner) => inner.modified(),
            Self::Note(inner) => inner.modified(),
            Self::ObservedData(inner) => inner.modified(),
            Self::Opinion(inner) => inner.modified(),
            Self::Report(inner) => inner.modified(),
            Self::ThreatActor(inner) => inner.modified(),
            Self::Tool(inner) => inner.modified(),
            Self::Vulnerability(inner) => inner.modified(),
        }
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match self {
            Self::AttackPattern(inner) => inner.get_field(path),
            Self::Campaign(inner) => inner.get_field(path),
            Self::CourseOfAction(inner) => inner.get_field(path),
            Self::Grouping(inner) => inner.get_field(path),
            Self::Identity(inner) => inner.get_field(path),
            Self::Incident(inner) => inner.get_field(path),
            Self::Indicator(inner) => inner.get_field(path),
            Self::Infrastructure(inner) => inner.get_field(path),
            Self::IntrusionSet(inner) => inner.get_field(path),
            Self::Location(inner) => inner.get_field(path),
            Self::Malware(inner) => inner.get_field(path),
            Self::MalwareAnalysis(inner) => inner.get_field(path),
            Self::Note(inner) => inner.get_field(path),
            Self::ObservedData(inner) => inner.get_field(path),
            Self::Opinion(inner) => inner.get_field(path),
            Self::Report(inner) => inner.get_field(path),
            Self::ThreatActor(inner) => inner.get_field(path),
            Self::Tool(inner) => inner.get_field(path),
            Self::Vulnerability(inner) => inner.get_field(path),
        }
    }
}

use crate::model::ModelError;
use crate::model::common::KillChainPhase;

pub(crate) fn validate_first_last_seen(
    first_seen: &Option<StixTimestamp>,
    last_seen: &Option<StixTimestamp>,
) -> Result<(), ModelError> {
    if let (Some(first), Some(last)) = (first_seen, last_seen)
        && last < first
    {
        return Err(ModelError::SdoLastSeenBeforeFirstSeen);
    }
    Ok(())
}

pub(crate) fn validate_kill_chain_phases(phases: &[KillChainPhase]) -> Result<(), ModelError> {
    for phase in phases {
        phase.validate()?;
    }
    Ok(())
}

pub(crate) fn validate_number_observed(number_observed: i64) -> Result<(), ModelError> {
    if !(1..=999_999_999).contains(&number_observed) {
        return Err(ModelError::ObservedDataNumberObservedOutOfRange);
    }
    Ok(())
}

#[cfg(feature = "serde")]
pub(crate) fn deserialize_sdo_object_from_value(
    value: serde_json::Value,
) -> Result<SdoObject, serde_json::Error> {
    let type_name = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SDO object missing type field",
            ))
        })?;
    match type_name {
        "attack-pattern" => serde_json::from_value(value).map(SdoObject::AttackPattern),
        "campaign" => serde_json::from_value(value).map(SdoObject::Campaign),
        "course-of-action" => serde_json::from_value(value).map(SdoObject::CourseOfAction),
        "grouping" => serde_json::from_value(value).map(SdoObject::Grouping),
        "identity" => serde_json::from_value(value).map(SdoObject::Identity),
        "incident" => serde_json::from_value(value).map(SdoObject::Incident),
        "indicator" => serde_json::from_value(value).map(SdoObject::Indicator),
        "infrastructure" => serde_json::from_value(value).map(SdoObject::Infrastructure),
        "intrusion-set" => serde_json::from_value(value).map(SdoObject::IntrusionSet),
        "location" => serde_json::from_value(value).map(SdoObject::Location),
        "malware" => serde_json::from_value(value).map(SdoObject::Malware),
        "malware-analysis" => serde_json::from_value(value).map(SdoObject::MalwareAnalysis),
        "note" => serde_json::from_value(value).map(SdoObject::Note),
        "observed-data" => serde_json::from_value(value).map(SdoObject::ObservedData),
        "opinion" => serde_json::from_value(value).map(SdoObject::Opinion),
        "report" => serde_json::from_value(value).map(SdoObject::Report),
        "threat-actor" => serde_json::from_value(value).map(SdoObject::ThreatActor),
        "tool" => serde_json::from_value(value).map(SdoObject::Tool),
        "vulnerability" => serde_json::from_value(value).map(SdoObject::Vulnerability),
        _ => Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown SDO type `{type_name}`"),
        ))),
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SdoObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::AttackPattern(inner) => inner.serialize(serializer),
            Self::Campaign(inner) => inner.serialize(serializer),
            Self::CourseOfAction(inner) => inner.serialize(serializer),
            Self::Grouping(inner) => inner.serialize(serializer),
            Self::Identity(inner) => inner.serialize(serializer),
            Self::Incident(inner) => inner.serialize(serializer),
            Self::Indicator(inner) => inner.serialize(serializer),
            Self::Infrastructure(inner) => inner.serialize(serializer),
            Self::IntrusionSet(inner) => inner.serialize(serializer),
            Self::Location(inner) => inner.serialize(serializer),
            Self::Malware(inner) => inner.serialize(serializer),
            Self::MalwareAnalysis(inner) => inner.serialize(serializer),
            Self::Note(inner) => inner.serialize(serializer),
            Self::ObservedData(inner) => inner.serialize(serializer),
            Self::Opinion(inner) => inner.serialize(serializer),
            Self::Report(inner) => inner.serialize(serializer),
            Self::ThreatActor(inner) => inner.serialize(serializer),
            Self::Tool(inner) => inner.serialize(serializer),
            Self::Vulnerability(inner) => inner.serialize(serializer),
        }
    }
}

crate::impl_bundle_object_cast!(Sdo, AttackPattern, AttackPattern);
crate::impl_bundle_object_cast!(Sdo, Campaign, Campaign);
crate::impl_bundle_object_cast!(Sdo, CourseOfAction, CourseOfAction);
crate::impl_bundle_object_cast!(Sdo, Grouping, Grouping);
crate::impl_bundle_object_cast!(Sdo, Identity, Identity);
crate::impl_bundle_object_cast!(Sdo, Incident, Incident);
crate::impl_bundle_object_cast!(Sdo, Indicator, Indicator);
crate::impl_bundle_object_cast!(Sdo, Infrastructure, Infrastructure);
crate::impl_bundle_object_cast!(Sdo, IntrusionSet, IntrusionSet);
crate::impl_bundle_object_cast!(Sdo, Location, Location);
crate::impl_bundle_object_cast!(Sdo, Malware, Malware);
crate::impl_bundle_object_cast!(Sdo, MalwareAnalysis, MalwareAnalysis);
crate::impl_bundle_object_cast!(Sdo, Note, Note);
crate::impl_bundle_object_cast!(Sdo, ObservedData, ObservedData);
crate::impl_bundle_object_cast!(Sdo, Opinion, Opinion);
crate::impl_bundle_object_cast!(Sdo, Report, Report);
crate::impl_bundle_object_cast!(Sdo, ThreatActor, ThreatActor);
crate::impl_bundle_object_cast!(Sdo, Tool, Tool);
crate::impl_bundle_object_cast!(Sdo, Vulnerability, Vulnerability);
