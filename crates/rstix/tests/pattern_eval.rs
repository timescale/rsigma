//! Pattern evaluation integration tests (Levels 1–3 + observed-data).

use rstix::Pattern;
use rstix::core::{StixId, StixTimestamp};
use rstix::model::Bundle;
use rstix::model::sco::{DomainName, Ipv4Addr, ScoObject};
use rstix::model::sdo::ObservedData;
use rstix::pattern::{ObservationContext, TimestampedObservation};

#[test]
fn evaluate_observed_data_object_refs() {
    let bundle_json = include_str!("fixtures/pattern/eval/observed-data-bundle.json");
    let bundle: Bundle = Bundle::parse(bundle_json).expect("bundle");
    let id = StixId::parse("observed-data--00000000-0000-0000-0000-000000000001").expect("id");
    let observed: &ObservedData = bundle.get_typed(&id).expect("observed-data");
    let pattern = Pattern::parse("[ipv4-addr:value = '203.0.113.4']").expect("pattern");
    assert!(
        pattern
            .evaluate_observed_data(observed, &bundle)
            .expect("eval")
    );
}

#[test]
fn evaluate_and_with_context() {
    let ipv4 = ScoObject::Ipv4Addr(
        serde_json::from_str::<Ipv4Addr>(include_str!("fixtures/spec/sco/ipv4-addr-single.json"))
            .expect("ipv4"),
    );
    let domain = ScoObject::DomainName(
        serde_json::from_str::<DomainName>(include_str!(
            "fixtures/spec/sco/domain-name-basic.json"
        ))
        .expect("domain"),
    );
    let ts = |s: &str| StixTimestamp::parse(s).expect("ts");
    let observations = [
        TimestampedObservation {
            sco: &ipv4,
            at: Some(ts("2024-01-01T00:00:00.000Z")),
        },
        TimestampedObservation {
            sco: &domain,
            at: Some(ts("2024-01-01T00:00:01.000Z")),
        },
    ];
    let ctx = ObservationContext::from_scos(&observations);
    let pattern = Pattern::parse(
        "[ipv4-addr:value = '198.51.100.3'] AND [domain-name:value = 'example.com']",
    )
    .expect("pattern");
    assert!(pattern.evaluate(&ctx).expect("eval"));
}
