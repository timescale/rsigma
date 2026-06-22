//! Shared ATT&CK Navigator layer (format 4.5) serde structs.
//!
//! Both `rule coverage` (a detection layer scored by rule count) and
//! `rule visibility` (a visibility layer scored on the DeTT&CT 0-to-4 scale)
//! emit Navigator layers. Centralising the serde structs here keeps the two
//! commands from drifting on the Navigator schema, so a layer from either
//! command loads in the same Navigator instance and the two can be stacked.
//!
//! Output is serialized from typed structs (never hand-built JSON) and is
//! deterministic for golden testing: callers emit techniques in sorted ID
//! order and pin the gradient to a fixed range.

use serde::Serialize;

/// ATT&CK content version stamped into the layer. The field is optional in the
/// spec (Navigator defaults to its current version); a fixed value keeps the
/// golden output deterministic.
pub(crate) const ATTACK_VERSION: &str = "16";
pub(crate) const NAVIGATOR_VERSION: &str = "5.0.0";
pub(crate) const LAYER_VERSION: &str = "4.5";
pub(crate) const DOMAIN: &str = "enterprise-attack";

#[derive(Serialize)]
pub(crate) struct Layer {
    pub(crate) name: String,
    pub(crate) versions: Versions,
    pub(crate) domain: &'static str,
    pub(crate) description: String,
    pub(crate) sorting: u8,
    #[serde(rename = "hideDisabled")]
    pub(crate) hide_disabled: bool,
    pub(crate) gradient: Gradient,
    pub(crate) techniques: Vec<NavTechnique>,
}

#[derive(Serialize)]
pub(crate) struct Versions {
    pub(crate) attack: &'static str,
    pub(crate) navigator: &'static str,
    pub(crate) layer: &'static str,
}

impl Versions {
    /// The pinned `(attack, navigator, layer)` triple every rsigma layer stamps.
    pub(crate) fn current() -> Self {
        Self {
            attack: ATTACK_VERSION,
            navigator: NAVIGATOR_VERSION,
            layer: LAYER_VERSION,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct Gradient {
    pub(crate) colors: Vec<&'static str>,
    #[serde(rename = "minValue")]
    pub(crate) min_value: u64,
    #[serde(rename = "maxValue")]
    pub(crate) max_value: u64,
}

#[derive(Serialize)]
pub(crate) struct NavTechnique {
    #[serde(rename = "techniqueID")]
    pub(crate) technique_id: String,
    pub(crate) score: u64,
    pub(crate) comment: String,
    pub(crate) enabled: bool,
    #[serde(rename = "showSubtechniques", skip_serializing_if = "is_false")]
    pub(crate) show_subtechniques: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Serialize the layer as pretty JSON for writing to a file.
pub(crate) fn to_pretty_json(layer: &Layer) -> String {
    serde_json::to_string_pretty(layer).unwrap_or_else(|_| "{}".to_string())
}
