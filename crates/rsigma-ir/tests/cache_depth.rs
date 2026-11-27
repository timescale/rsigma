//! The deepest rules the parser accepts round-trip through the HIR cache.

use rsigma_ir::{IrRule, LowerOptions, decode_rules, encode_rules, lower_rule};
use rsigma_parser::{SigmaRule, parse_sigma_yaml};

fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

fn parse_rule(yaml: &str) -> Option<SigmaRule> {
    let mut collection = parse_sigma_yaml(yaml).ok()?;
    if !collection.diagnostics.is_empty() {
        return None;
    }
    collection.rules.pop()
}

fn round_trip(rule: SigmaRule) {
    let ir = lower_rule(&rule, &LowerOptions::default()).unwrap();
    let decoded = on_small_stack(move || {
        let blob = encode_rules(std::slice::from_ref(&ir)).unwrap();
        let decoded: Vec<IrRule> = decode_rules(&blob).unwrap();
        assert_eq!(decoded, [ir]);
        decoded.len()
    });
    assert_eq!(decoded, 1);
}

#[test]
fn deepest_accepted_condition_round_trips() {
    // Each parenthesized level nests an `or` and an `and`, the deepest tree
    // per level of the parser's 64-level limit.
    let condition = format!("{}a{}", "a or b and (".repeat(64), ")".repeat(64));
    let yaml = format!(
        "title: T\nlogsource:\n    category: test\ndetection:\n    a:\n        x: 1\n    b:\n        y: 2\n    condition: {condition}\n"
    );
    round_trip(parse_rule(&yaml).expect("the condition is within the parser's limits"));

    let over = format!("{}a{}", "a or b and (".repeat(65), ")".repeat(65));
    assert!(parse_rule(&yaml.replace(&condition, &over)).is_none());
}

/// A selection of `depth` nested indexed blocks, each holding one item and
/// the next block, so every level adds an `And` to the detection tree.
fn nested_indexed_blocks(depth: usize) -> String {
    let mut body = String::new();
    for level in 0..depth {
        let indent = "    ".repeat(level + 2);
        body.push_str(&format!("{indent}a{level}[0]:\n{indent}    x: 1\n"));
    }
    body.push_str(&format!("{}y: 2\n", "    ".repeat(depth + 2)));
    format!(
        "title: T\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n    selection:\n{body}    condition: selection\n"
    )
}

#[test]
fn deepest_accepted_detection_round_trips() {
    let deepest = (1..)
        .take_while(|&depth| parse_rule(&nested_indexed_blocks(depth)).is_some())
        .last()
        .unwrap();
    // YAML nesting, not the detection parser, sets this bound.
    assert!(deepest > 100, "deepest accepted nesting is {deepest}");
    round_trip(parse_rule(&nested_indexed_blocks(deepest)).unwrap());
}
