//! The `|windash` expansion budget: the parser rejects a rule whose variants
//! exceed it, naming the rule, and the linter predicts exactly that outcome.

use rsigma_parser::validate::{MAX_WINDASH_VARIANTS_PER_ITEM, MAX_WINDASH_VARIANTS_PER_RULE};
use rsigma_parser::{LintRule, lint_yaml_str, parse_sigma_yaml};

/// A value with `dashes` dash characters, every kind of dash represented.
fn dashed(dashes: usize, wildcard: bool) -> String {
    let kinds = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];
    let mut value = String::from("cmd");
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

/// A rule with one `|windash|contains` item per entry of `items`, each with
/// the given (dashes, wildcard) values.
fn rule(title: &str, items: &[Vec<(usize, bool)>]) -> String {
    let mut yaml = format!(
        "title: {title}\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n"
    );
    for (i, values) in items.iter().enumerate() {
        yaml.push_str(&format!("  sel{i}:\n    CommandLine|windash|contains:\n"));
        for (dashes, wildcard) in values {
            yaml.push_str(&format!("      - '{}'\n", dashed(*dashes, *wildcard)));
        }
    }
    yaml.push_str("  condition: all of sel*\n");
    yaml
}

fn parse_error(yaml: &str) -> Option<String> {
    let collection = parse_sigma_yaml(yaml).unwrap();
    collection.errors().next().map(ToString::to_string)
}

fn lint_flags(yaml: &str) -> bool {
    lint_yaml_str(yaml)
        .iter()
        .any(|w| w.rule == LintRule::WindashExpansionTooLarge)
}

#[test]
fn many_maximal_dash_values_in_one_item_are_rejected_naming_the_rule() {
    for wildcard in [false, true] {
        let yaml = rule(
            "Windash Bomb",
            &[vec![(8, wildcard), (8, !wildcard), (8, wildcard)]],
        );
        let error = parse_error(&yaml).expect("the rule is rejected");
        assert!(error.contains("rule 'Windash Bomb'"), "{error}");
        assert!(error.contains("field 'CommandLine'"), "{error}");
        assert!(error.contains("1171875 variants"), "{error}");
        assert!(
            error.contains(&MAX_WINDASH_VARIANTS_PER_ITEM.to_string()),
            "{error}"
        );
        assert!(lint_flags(&yaml), "lint predicts the rejection");
    }
}

#[test]
fn items_that_fit_alone_but_not_together_are_rejected_per_rule() {
    // 5^5 = 3125 variants per item fits the item budget; six items do not fit
    // the rule budget, five do.
    let item = vec![(5, false)];
    let fits = rule("Five Items", &vec![item.clone(); 5]);
    assert_eq!(parse_error(&fits), None);
    assert!(!lint_flags(&fits));

    let over = rule("Six Items", &vec![item; 6]);
    let error = parse_error(&over).expect("the rule is rejected");
    assert!(error.contains("rule 'Six Items'"), "{error}");
    assert!(error.contains("18750 variants"), "{error}");
    assert!(
        error.contains(&MAX_WINDASH_VARIANTS_PER_RULE.to_string()),
        "{error}"
    );
    assert!(lint_flags(&over));
}

#[test]
fn base64offset_counts_three_encodings_per_variant() {
    let yaml = "title: Encoded\nlogsource:\n  product: windows\ndetection:\n  sel:\n    CommandLine|windash|base64offset|contains:\n      - '-a -b -c -d -e'\n      - '-a -b'\n  condition: sel\n";
    // (3125 + 25) * 3 = 9450 > 4096
    let error = parse_error(yaml).expect("the rule is rejected");
    assert!(error.contains("9450 variants"), "{error}");
    assert!(lint_flags(yaml));
}

#[test]
fn filters_share_the_budget() {
    let mut yaml = String::from(
        "title: Noisy Filter\nlogsource:\n  product: windows\nfilter:\n  rules: any\n  selection:\n    CommandLine|windash|contains:\n",
    );
    for _ in 0..2 {
        yaml.push_str(&format!("      - '{}'\n", dashed(6, false)));
    }
    yaml.push_str("  condition: not selection\n");
    let error = parse_error(&yaml).expect("the filter is rejected");
    assert!(error.contains("filter 'Noisy Filter'"), "{error}");
    assert!(lint_flags(&yaml));
}

#[test]
fn lint_and_parser_agree_across_shapes() {
    let mut shapes = Vec::new();
    for items in 1..=6 {
        for dashes in [0usize, 1, 3, 4, 5, 6] {
            for values in [1usize, 2, 4] {
                shapes.push(vec![vec![(dashes, dashes % 2 == 0); values]; items]);
            }
        }
    }
    for (i, shape) in shapes.iter().enumerate() {
        let yaml = rule(&format!("Shape {i}"), shape);
        let rejected = parse_error(&yaml).is_some();
        assert_eq!(rejected, lint_flags(&yaml), "shape {shape:?}");
    }
}

#[test]
fn lint_follows_global_documents_into_the_rules_they_build() {
    // Each document alone is within the budget; the merged rule is not.
    let fragment: String = (0..2)
        .map(|_| format!("        - '{}'\n", dashed(5, false)))
        .collect();
    let yaml = format!(
        "action: global\ndetection:\n    sel:\n        CommandLine|windash|contains:\n{fragment}    condition: sel\n---\ntitle: Merged\nlogsource:\n    product: windows\n"
    );
    let error = parse_error(&yaml).expect("the merged rule is rejected");
    assert!(error.contains("rule 'Merged'"), "{error}");
    assert!(lint_flags(&yaml));
}
