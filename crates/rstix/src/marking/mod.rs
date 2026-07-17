//! STIX marking resolution (TLP + granular + statement).

mod granular;
mod resolver;
mod statement;
mod tlp1;
mod tlp2;
mod wire;

pub use granular::{
    selector_applies_to_property, selector_matches_target, selector_resolves_on_object,
};
pub use resolver::{EffectiveMarking, MarkingResolver};
pub use statement::StatementMarking;
#[allow(deprecated)]
pub use tlp1::TlpV1Level;
pub use tlp2::{DisclosureContext, TlpV2Level};
