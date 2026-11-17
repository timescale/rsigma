#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(pipeline) = rsigma_eval::parse_pipeline(s) {
        let _ = pipeline.is_dynamic();
        let _ = pipeline.dynamic_references();
    }
    // Source declarations live in a sources file. Pipeline parse rejects an
    // inline `sources:` block, so the declaration parser is exercised here.
    if let Ok(value) = yaml_serde::from_str::<yaml_serde::Value>(s)
        && let Some(items) = value
            .as_mapping()
            .and_then(|map| map.get(yaml_serde::Value::String("sources".into())))
    {
        let _ = rsigma_eval::parse_sources(items);
    }
});
