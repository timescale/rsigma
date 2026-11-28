#![no_main]
//! The `|windash` expansion budget on arbitrary rule YAML.
//!
//! The input is a rule document, optionally followed by a NUL byte and an
//! event value. Invariants: the linter reports `windash_expansion_too_large`
//! whenever the parser rejects a document for the budget, and only for
//! documents the parser rejects (possibly for an earlier problem, such as a
//! missing title); a document the parser accepts never hits the budget again
//! when it compiles; and
//! compiling and evaluating it finishes, however many dash characters its
//! values carry.

use libfuzzer_sys::fuzz_target;
use rsigma_eval::Engine;
use rsigma_eval::event::JsonEvent;
use rsigma_parser::{LintRule, lint_yaml_str, parse_sigma_yaml};
use serde_json::json;

use rsigma_parser::validate::WINDASH_BUDGET_MARKER as BUDGET_ERROR;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (yaml, haystack) = text.split_once('\0').unwrap_or((text, ""));
    let Ok(collection) = parse_sigma_yaml(yaml) else {
        return;
    };

    let parser_rejects = collection
        .errors()
        .any(|error| error.message.contains(BUDGET_ERROR));
    let lint_rejects = lint_yaml_str(yaml)
        .iter()
        .any(|warning| warning.rule == LintRule::WindashExpansionTooLarge);
    assert!(
        !parser_rejects || lint_rejects,
        "lint missed a rule the parser rejects for the windash budget"
    );
    assert!(
        !lint_rejects || collection.has_errors(),
        "lint reports the windash budget for documents the parser accepts"
    );

    let event = json!({ "CommandLine": haystack, "Image": haystack });
    for rule in &collection.rules {
        let mut engine = Engine::new();
        match engine.add_rule(rule) {
            Ok(()) => {
                let _ = engine.evaluate(&JsonEvent::borrow(&event));
            }
            Err(error) => assert!(
                !error.to_string().contains(BUDGET_ERROR),
                "a parsed rule hit the budget when compiling: {error}"
            ),
        }
    }
});
