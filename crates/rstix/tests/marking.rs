//! Integration tests for the `marking` feature.

use rstix::core::QueryableStixObject;
use rstix::marking::{MarkingResolver, TlpV2Level};
use rstix::model::{SdoObject, StixObject};
use rstix::parse_bundle;

#[test]
fn marking_resolver_object_and_property() {
    let bundle =
        parse_bundle(include_str!("fixtures/marking/object-red-green.json")).expect("parse");
    let resolver = MarkingResolver::new(&bundle);
    let indicator = bundle
        .objects()
        .iter()
        .find_map(|object| match object {
            StixObject::Sdo(SdoObject::Indicator(ind)) => Some(ind),
            _ => None,
        })
        .expect("indicator");
    let object = StixObject::Sdo(SdoObject::Indicator(indicator.clone()));

    assert_eq!(
        resolver.effective_for_object(&object).tlp_level,
        Some(TlpV2Level::Red)
    );
    assert_eq!(
        resolver.effective_for_property(&object, "name").tlp_level,
        Some(TlpV2Level::Green)
    );
}

#[test]
fn marking_resolver_language_granular() {
    let bundle =
        parse_bundle(include_str!("fixtures/marking/language-granular.json")).expect("parse");
    let resolver = MarkingResolver::new(&bundle);
    let indicator = bundle
        .objects()
        .iter()
        .find_map(|object| match object {
            StixObject::Sdo(SdoObject::Indicator(ind)) => Some(ind),
            _ => None,
        })
        .expect("indicator");
    let object = StixObject::Sdo(SdoObject::Indicator(indicator.clone()));
    let effective = resolver.effective_for_property(&object, "name");
    assert_eq!(effective.language_tags, vec!["de".to_owned()]);
}

#[test]
fn marking_resolver_custom_object_markings() {
    let json = include_str!("fixtures/marking/custom-object-red.json");
    let bundle = rstix::model::Bundle::parse_with_options(
        json,
        &rstix::model::ParseOptions::default().allow_custom(true),
    )
    .expect("parse");
    let resolver = MarkingResolver::new(&bundle);
    let custom = bundle
        .objects()
        .iter()
        .find(|object| object.type_name() == "x-custom-indicator")
        .expect("custom");
    let effective = resolver.effective_for_object(custom);
    assert_eq!(effective.tlp_level, Some(TlpV2Level::Red));
}
