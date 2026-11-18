#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_eval::pipeline::sources::StixOptions;
use rsigma_runtime::sources::stix::build;
use rstix::core::StixTimestamp;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let now = StixTimestamp::parse("2026-06-01T00:00:00.000Z").expect("clock");
    let options = StixOptions::all();
    let Ok(built) = build(raw, &options, &now) else {
        return;
    };
    let Some(object) = built.value.as_object() else {
        panic!("STIX source value is not an object");
    };
    for key in &options.observables {
        match object.get(key).and_then(|value| value.as_array()) {
            Some(_) => {}
            None => panic!("STIX source value is missing array {key}"),
        }
    }
    if object.get("indicators").and_then(|value| value.as_object()).is_none() {
        panic!("STIX source value is missing the indicators object");
    }
});
