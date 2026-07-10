//! Host-neutral WASM instantiation smoke test.
//!
//! This crate is compiled to `wasm32-unknown-unknown` and instantiated by CI in
//! a JavaScript-free runtime (Wasmtime). It exercises the real parse, compile,
//! and evaluate path so a regression that reintroduces a JavaScript import (for
//! example a `wasm-bindgen` dependency pulled in transitively) fails to
//! instantiate, and a semantic regression fails the assertion below.

use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;

const RULE: &str = r#"
title: Whoami
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;

/// Parse, compile, and evaluate a rule against one matching and one
/// non-matching event. Panics (and therefore traps the module) unless exactly
/// one event matches.
#[unsafe(no_mangle)]
pub extern "C" fn run_selftest() {
    let collection = parse_sigma_yaml(RULE).expect("rule parses");
    let mut engine = Engine::new();
    engine.add_collection(&collection).expect("rule compiles");

    let matching = serde_json::json!({ "CommandLine": "cmd /c whoami" });
    let non_matching = serde_json::json!({ "CommandLine": "cmd /c dir" });

    let mut count = 0usize;
    for event in [&matching, &non_matching] {
        count += engine.evaluate(&JsonEvent::borrow(event)).len();
    }

    assert_eq!(count, 1, "expected exactly one match, got {count}");
}
