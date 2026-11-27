//! Conversion of a rule that thousands of filters target, on a 2 MiB stack.

use rsigma_convert::backends::postgres::PostgresBackend;
use rsigma_convert::convert_collection;
use rsigma_parser::parse_sigma_yaml;

#[test]
fn thousands_of_filters_on_one_rule_convert_on_small_stack() {
    let count = 10_000;
    let mut yaml = String::from(
        "title: Rule A\nid: rule-a\nlogsource:\n    product: test\ndetection:\n    selection:\n        EventID: 1\n    condition: selection\n",
    );
    for i in 0..count {
        yaml.push_str(&format!(
            "---\ntitle: Filter {i}\nlogsource:\n    product: test\nfilter:\n    rules:\n        - rule-a\n    selection:\n        User: user-{i}\n    condition: not selection\n"
        ));
    }
    let collection = parse_sigma_yaml(&yaml).unwrap();
    let output = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || convert_collection(&PostgresBackend::new(), &collection, &[], "default"))
        .unwrap()
        .join()
        .unwrap()
        .unwrap();
    assert!(output.errors.is_empty(), "{:?}", output.errors);
    let query = &output.queries[0].queries[0];
    assert!(query.contains("user-0") && query.contains(&format!("user-{}", count - 1)));
}
