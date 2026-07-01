//! Observed-data evaluation helpers.

use crate::model::Bundle;
use crate::model::sdo::ObservedData;
use crate::pattern::ast::PatternAst;
use crate::pattern::context::{ObservationContext, build_observations_from_observed_data};
use crate::pattern::error::PatternMatchError;

use super::evaluate;

/// Evaluate a pattern against cyber-observables referenced by an [`ObservedData`] SDO.
///
/// Resolves `object_refs` (or deprecated embedded SCO members) against `bundle`,
/// stamps each SCO with [`ObservedData::first_observed`], then runs full Level 1–3
/// evaluation. Returns [`PatternMatchError::RefResolution`] when a reference is
/// missing or not an SCO.
pub fn evaluate_observed_data(
    ast: &PatternAst,
    observed_data: &ObservedData,
    bundle: &Bundle,
) -> Result<bool, PatternMatchError> {
    let observations = build_observations_from_observed_data(observed_data, bundle)?;
    let ctx = ObservationContext {
        observations: &observations,
        bundle: Some(bundle),
    };
    evaluate(ast, &ctx)
}
