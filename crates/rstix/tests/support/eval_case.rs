//! Table-driven pattern evaluation scenarios.

use rstix::Pattern;
use rstix::core::StixTimestamp;
use rstix::model::Bundle;
use rstix::pattern::{ObservationContext, TimestampedObservation};

use super::sco_json::parse_sco_json;

/// One evaluation scenario: pattern + expected boolean + observations.
#[derive(Clone, Copy)]
pub struct EvalCase {
    /// Stable case id (used in panic messages).
    pub id: &'static str,
    /// STIX pattern source.
    pub pattern: &'static str,
    /// Expected `Pattern::evaluate` / `matches_single*` result.
    pub expect: bool,
    /// SCO JSON fixtures (one per observation when using context mode).
    pub scos: &'static [&'static str],
    /// Parallel observation timestamps (`None` = missing timestamp).
    pub at: &'static [Option<&'static str>],
    /// Optional bundle JSON for `_ref` dereference.
    pub bundle: Option<&'static str>,
}

impl EvalCase {
    /// Run this case; panics with `id` on assertion failure.
    pub fn run(self) {
        let pattern = Pattern::parse(self.pattern)
            .unwrap_or_else(|e| panic!("case `{}`: parse failed: {e:?}", self.id));

        if self.scos.is_empty() {
            panic!("case `{}`: at least one SCO fixture required", self.id);
        }

        let bundle = self.bundle.map(|json| {
            Bundle::parse(json)
                .unwrap_or_else(|e| panic!("case `{}`: bundle parse: {e:?}", self.id))
        });

        if self.at.is_empty() {
            let sco = parse_sco_json(self.scos[0]);
            let got = pattern
                .matches_single_with_bundle(&sco, bundle.as_ref())
                .unwrap_or_else(|e| panic!("case `{}`: eval failed: {e:?}", self.id));
            assert_eq!(got, self.expect, "case `{}`: matches_single*", self.id);
            return;
        }

        assert_eq!(
            self.scos.len(),
            self.at.len(),
            "case `{}`: scos/at length mismatch",
            self.id
        );

        let mut owned = Vec::with_capacity(self.scos.len());
        for json in self.scos {
            owned.push(parse_sco_json(json));
        }

        let mut observations = Vec::with_capacity(owned.len());
        for (sco, at) in owned.iter().zip(self.at.iter()) {
            let timestamp = at.map(|s| {
                StixTimestamp::parse(s)
                    .unwrap_or_else(|e| panic!("case `{}`: bad timestamp `{s}`: {e:?}", self.id))
            });
            observations.push(TimestampedObservation { sco, at: timestamp });
        }

        let ctx = ObservationContext {
            observations: &observations,
            bundle: bundle.as_ref(),
        };
        let got = pattern
            .evaluate(&ctx)
            .unwrap_or_else(|e| panic!("case `{}`: evaluate failed: {e:?}", self.id));
        assert_eq!(got, self.expect, "case `{}`: evaluate", self.id);
    }
}
