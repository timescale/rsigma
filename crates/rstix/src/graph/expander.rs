//! Relationship-centric graph expansion.

use std::collections::{HashSet, VecDeque};

use crate::core::{IndicatorId, QueryableStixObject, StixId};
use crate::model::sdo::SdoObject;
use crate::model::validate::relationship_types_for_source;

use super::StixGraph;

/// Lightweight identity node summary for expansion results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentitySummary {
    /// STIX id.
    pub id: StixId,
    /// Identity name when present.
    pub name: Option<String>,
}

/// Lightweight infrastructure node summary for expansion results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InfrastructureSummary {
    /// STIX id.
    pub id: StixId,
    /// Infrastructure name when present.
    pub name: Option<String>,
}

/// Lightweight indicator node summary for expansion results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndicatorSummary {
    /// STIX id.
    pub id: StixId,
    /// Indicator name when present.
    pub name: Option<String>,
}

/// Lightweight malware node summary for expansion results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalwareSummary {
    /// STIX id.
    pub id: StixId,
    /// Malware or family name when present.
    pub name: Option<String>,
}

/// Lightweight threat-actor node summary for expansion results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreatActorSummary {
    /// STIX id.
    pub id: StixId,
    /// Threat actor name when present.
    pub name: Option<String>,
}

/// Lightweight campaign node summary for expansion results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignSummary {
    /// STIX id.
    pub id: StixId,
    /// Campaign name when present.
    pub name: Option<String>,
}

/// Lightweight attack-pattern node summary for expansion results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttackPatternSummary {
    /// STIX id.
    pub id: StixId,
    /// Attack pattern name when present.
    pub name: Option<String>,
}

/// Lightweight course-of-action node summary for expansion results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoaSummary {
    /// STIX id.
    pub id: StixId,
    /// Course of action name when present.
    pub name: Option<String>,
}

/// Lightweight vulnerability node summary for expansion results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VulnerabilitySummary {
    /// STIX id.
    pub id: StixId,
    /// Vulnerability name when present.
    pub name: Option<String>,
}

/// Typed objects reachable via relationship edges from a start node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpansionResult {
    /// Related identity objects.
    pub identities: Vec<IdentitySummary>,
    /// Related infrastructure objects.
    pub infrastructures: Vec<InfrastructureSummary>,
    /// Related indicator objects.
    pub indicators: Vec<IndicatorSummary>,
    /// Related malware objects.
    pub malware: Vec<MalwareSummary>,
    /// Related threat-actor objects.
    pub threat_actors: Vec<ThreatActorSummary>,
    /// Related campaign objects.
    pub campaigns: Vec<CampaignSummary>,
    /// Related attack-pattern objects.
    pub attack_patterns: Vec<AttackPatternSummary>,
    /// Related course-of-action objects.
    pub courses_of_action: Vec<CoaSummary>,
    /// Related vulnerability objects.
    pub vulnerabilities: Vec<VulnerabilitySummary>,
}

/// Walks common CTI relationship chains from a start node.
pub struct RelationshipExpander<'g> {
    graph: &'g StixGraph<'g>,
}

impl<'g> RelationshipExpander<'g> {
    /// Create an expander over `graph`.
    pub fn new(graph: &'g StixGraph<'g>) -> Self {
        Self { graph }
    }

    /// Expand from `start_id` following SRO edges up to `max_depth` hops.
    ///
    /// Walks both outgoing and incoming relationship and sighting edges, restricted to
    /// relationship types allowed for each node's SDO type per STIX 2.1 §3.5.
    pub fn expand_from(&self, start_id: &StixId, max_depth: u32) -> ExpansionResult {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::from([(start_id.clone(), 0u32)]);
        let mut result = ExpansionResult::default();

        while let Some((current_id, depth)) = queue.pop_front() {
            if !visited.insert(current_id.as_str().to_owned()) {
                continue;
            }
            if depth > max_depth {
                continue;
            }

            if let Some(object) = self.graph.node(&current_id) {
                accumulate_typed_object(object, &mut result);
            }

            if depth == max_depth {
                continue;
            }

            let source_type = self
                .graph
                .node(&current_id)
                .map(|object| object.type_name())
                .unwrap_or("");
            let mut relationship_types: HashSet<String> =
                relationship_types_for_source(source_type)
                    .into_iter()
                    .map(str::to_owned)
                    .collect();
            for edge in self.graph.outgoing_sro_edges(&current_id) {
                relationship_types.insert(edge.relationship_type.to_owned());
            }
            for edge in self.graph.incoming_sro_edges(&current_id) {
                relationship_types.insert(edge.relationship_type.to_owned());
            }

            for relationship_type in &relationship_types {
                for edge in self.graph.outgoing_sro_edges(&current_id) {
                    if edge.relationship_type == relationship_type.as_str() {
                        queue.push_back((edge.target_id.clone(), depth + 1));
                    }
                }
                for edge in self.graph.incoming_sro_edges(&current_id) {
                    if edge.relationship_type == relationship_type.as_str() {
                        queue.push_back((edge.source_id.clone(), depth + 1));
                    }
                }
            }
        }

        dedupe_summaries(&mut result);
        result
    }

    /// Expand from `indicator` following SRO edges up to `max_depth` hops.
    pub fn expand_from_indicator(
        &self,
        indicator: &IndicatorId,
        max_depth: u32,
    ) -> ExpansionResult {
        self.expand_from(indicator.as_stix_id(), max_depth)
    }
}

fn accumulate_typed_object(object: &crate::model::StixObject, result: &mut ExpansionResult) {
    let Some(sdo) = (match object {
        crate::model::StixObject::Sdo(sdo) => Some(sdo),
        _ => None,
    }) else {
        return;
    };

    match sdo {
        SdoObject::Identity(identity) => result.identities.push(IdentitySummary {
            id: identity.id().clone(),
            name: Some(identity.name.clone()),
        }),
        SdoObject::Infrastructure(infrastructure) => {
            result.infrastructures.push(InfrastructureSummary {
                id: infrastructure.id().clone(),
                name: Some(infrastructure.name.clone()),
            });
        }
        SdoObject::Indicator(indicator) => result.indicators.push(IndicatorSummary {
            id: indicator.id().clone(),
            name: indicator.name.clone(),
        }),
        SdoObject::Malware(malware) => result.malware.push(MalwareSummary {
            id: malware.id().clone(),
            name: malware.name.clone(),
        }),
        SdoObject::ThreatActor(actor) => result.threat_actors.push(ThreatActorSummary {
            id: actor.id().clone(),
            name: Some(actor.name.clone()),
        }),
        SdoObject::Campaign(campaign) => result.campaigns.push(CampaignSummary {
            id: campaign.id().clone(),
            name: Some(campaign.name.clone()),
        }),
        SdoObject::AttackPattern(pattern) => result.attack_patterns.push(AttackPatternSummary {
            id: pattern.id().clone(),
            name: Some(pattern.name.clone()),
        }),
        SdoObject::CourseOfAction(coa) => result.courses_of_action.push(CoaSummary {
            id: coa.id().clone(),
            name: Some(coa.name.clone()),
        }),
        SdoObject::Vulnerability(vuln) => result.vulnerabilities.push(VulnerabilitySummary {
            id: vuln.id().clone(),
            name: Some(vuln.name.clone()),
        }),
        _ => {}
    }
}

fn dedupe_summaries(result: &mut ExpansionResult) {
    dedupe_by_id(&mut result.identities, |item| item.id.as_str());
    dedupe_by_id(&mut result.infrastructures, |item| item.id.as_str());
    dedupe_by_id(&mut result.indicators, |item| item.id.as_str());
    dedupe_by_id(&mut result.malware, |item| item.id.as_str());
    dedupe_by_id(&mut result.threat_actors, |item| item.id.as_str());
    dedupe_by_id(&mut result.campaigns, |item| item.id.as_str());
    dedupe_by_id(&mut result.attack_patterns, |item| item.id.as_str());
    dedupe_by_id(&mut result.courses_of_action, |item| item.id.as_str());
    dedupe_by_id(&mut result.vulnerabilities, |item| item.id.as_str());
}

fn dedupe_by_id<T, F>(items: &mut Vec<T>, id_fn: F)
where
    F: Fn(&T) -> &str,
{
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert(id_fn(item).to_owned()));
}
