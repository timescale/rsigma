//! `|windash` in conversion: every backend rejects a rule over the expansion
//! budget with an error naming the rule, and renders a rule inside it.

use rsigma_convert::backends::fibratus::FibratusBackend;
use rsigma_convert::backends::lynxdb::LynxDbBackend;
use rsigma_convert::backends::postgres::PostgresBackend;
use rsigma_convert::backends::test::TextQueryTestBackend;
use rsigma_convert::{Backend, convert_collection};
use rsigma_parser::{Detection, SigmaCollection, SigmaString, SigmaValue, parse_sigma_yaml};

fn dashed(dashes: usize, wildcard: bool) -> String {
    let kinds = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];
    let mut value = String::from("tool");
    for i in 0..dashes {
        value.push(' ');
        value.push(kinds[i % kinds.len()]);
        value.push(char::from(b'a' + (i % 26) as u8));
    }
    if wildcard {
        value.push_str(" *");
    }
    value
}

/// A rule whose only item gets `values`, set on the parsed AST the way a
/// pipeline or a library caller can, past the parser's own check.
fn rule_with(values: Vec<String>) -> SigmaCollection {
    let mut collection = parse_sigma_yaml(
        "title: Windash Convert\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        CommandLine|windash|contains: x\n    condition: selection\n",
    )
    .unwrap();
    let Some(Detection::AllOf(items)) = collection.rules[0].detection.named.get_mut("selection")
    else {
        panic!("expected a mapping selection");
    };
    items[0].values = values
        .iter()
        .map(|v| SigmaValue::String(SigmaString::new(v)))
        .collect();
    collection
}

fn backends() -> Vec<Box<dyn Backend>> {
    vec![
        Box::new(PostgresBackend::new()),
        Box::new(LynxDbBackend::new()),
        Box::new(FibratusBackend::new()),
        Box::new(TextQueryTestBackend::new()),
    ]
}

#[test]
fn every_backend_rejects_a_rule_over_the_budget_naming_it() {
    for wildcard in [false, true] {
        let collection = rule_with((0..3).map(|_| dashed(8, wildcard)).collect());
        for backend in backends() {
            let output = convert_collection(backend.as_ref(), &collection, &[], "default").unwrap();
            assert!(output.queries.is_empty());
            let (title, error) = &output.errors[0];
            assert_eq!(title, "Windash Convert");
            let message = error.to_string();
            assert!(message.contains("rule 'Windash Convert'"), "{message}");
            assert!(message.contains("4096"), "{message}");
        }
    }
}

#[test]
fn rule_inside_the_budget_renders_every_variant() {
    // 5^2 = 25 variants per value.
    let collection = rule_with(vec![dashed(2, false)]);
    for backend in backends() {
        let output = convert_collection(backend.as_ref(), &collection, &[], "default").unwrap();
        assert!(output.errors.is_empty(), "{:?}", output.errors);
        let query = output.queries[0].queries.join("\n");
        for variant in ["\u{2015}a \u{2014}b", "\u{2013}a /b", "/a \u{2015}b"] {
            assert!(query.contains(variant), "{variant} missing from {query}");
        }
    }
}
