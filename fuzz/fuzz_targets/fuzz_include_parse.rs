#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    // Path 1: JSON array -> YAML roundtrip -> parse (mirrors include.rs)
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(s) {
        if json.is_array() {
            if let Ok(yaml_str) = serde_json::to_string(&json) {
                if let Ok(yaml_val) = serde_yaml::from_str::<serde_yaml::Value>(&yaml_str) {
                    let _ = rsigma_eval::parse_transformation_items(&yaml_val);
                }
            }
        }
    }

    // Path 2: direct YAML parse -> transformation items
    if let Ok(yaml_val) = serde_yaml::from_str::<serde_yaml::Value>(s) {
        let _ = rsigma_eval::parse_transformation_items(&yaml_val);
    }
});
