#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_eval::Pipeline;
use rsigma_runtime::TemplateExpander;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    let Some((template, json_str)) = s.split_once('\0') else {
        return;
    };

    let Ok(resolved_data) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return;
    };

    let resolved: HashMap<String, serde_json::Value> = match resolved_data {
        serde_json::Value::Object(map) => map.into_iter().collect(),
        _ => return,
    };

    let mut vars = HashMap::new();
    vars.insert("fuzz_var".to_string(), vec![template.to_string()]);

    let pipeline = Pipeline {
        name: "fuzz".to_string(),
        priority: 0,
        vars,
        transformations: vec![],
        finalizers: vec![],
        sources: vec![],
        source_refs: vec![],
    };

    let _ = TemplateExpander::expand(&pipeline, &resolved);
});
