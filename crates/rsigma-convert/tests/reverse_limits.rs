//! Nesting and size limits of reverse conversion, driven through
//! `reverse_collection` on a 2 MiB stack.

use rsigma_convert::reverse::{MAX_REVERSE_QUERY_DEPTH, MAX_REVERSE_QUERY_LEN};
use rsigma_convert::{ConvertError, LuceneFrontend, ReverseCtx, ReverseOutput, reverse_collection};

fn convert_on_small_stack(query: String) -> ReverseOutput {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let ctx = ReverseCtx {
                title: Some("T".into()),
                product: Some("windows".into()),
                ..Default::default()
            };
            reverse_collection(&LuceneFrontend, &[query], &ctx)
        })
        .unwrap()
        .join()
        .unwrap()
}

fn single_error(output: ReverseOutput) -> ConvertError {
    assert!(output.rules.is_empty(), "expected no rule");
    let mut errors = output.errors;
    assert_eq!(errors.len(), 1);
    errors.pop().unwrap().1
}

fn assert_depth_error(query: String) {
    assert!(query.len() <= MAX_REVERSE_QUERY_LEN);
    let err = single_error(convert_on_small_stack(query));
    assert!(
        matches!(&err, ConvertError::QueryParse(msg) if msg.contains("maximum depth")),
        "{err}"
    );
}

/// `n` opening parentheses, `inner`, and `n` closing ones, filling the query
/// size limit together with `head`.
fn nested_parens(head: &str, inner: &str) -> String {
    let n = (MAX_REVERSE_QUERY_LEN - head.len() - inner.len()) / 2;
    format!("{head}{}{inner}{}", "(".repeat(n), ")".repeat(n))
}

fn fill(unit: &str, tail: &str) -> String {
    let n = (MAX_REVERSE_QUERY_LEN - tail.len()) / unit.len();
    format!("{}{tail}", unit.repeat(n))
}

#[test]
fn max_length_nested_parentheses_fail_without_overflow() {
    assert_depth_error(nested_parens("", "a:1"));
}

#[test]
fn max_length_not_chains_fail_without_overflow() {
    assert_depth_error(fill("NOT ", "a:1"));
    assert_depth_error(fill("! ", "a:1"));
    assert_depth_error(fill("- ", "a:1"));
}

#[test]
fn max_length_nested_value_group_fails_without_overflow() {
    // The group's own parentheses enclose the nested ones.
    let n = (MAX_REVERSE_QUERY_LEN - "a:()".len() - 1) / 2;
    let query = format!("a:({}x{})", "(".repeat(n), ")".repeat(n));
    assert_depth_error(query);
}

#[test]
fn over_length_query_is_rejected_before_tokenizing() {
    // An unterminated quote would be a tokenizer error.
    let query = format!("a:\"{}", "x".repeat(MAX_REVERSE_QUERY_LEN));
    let err = single_error(convert_on_small_stack(query));
    assert!(
        matches!(&err, ConvertError::QueryParse(msg) if msg.contains("maximum is")),
        "{err}"
    );
}

#[test]
fn deepest_accepted_query_converts_on_small_stack() {
    let half = MAX_REVERSE_QUERY_DEPTH / 2;
    let group = format!(
        "{}x{}",
        "(".repeat(MAX_REVERSE_QUERY_DEPTH - 1),
        ")".repeat(MAX_REVERSE_QUERY_DEPTH - 1)
    );
    let query = format!(
        "{}{}a:1 OR b:({group}) AND c:2{}",
        "(NOT ".repeat(half),
        "- ".repeat(MAX_REVERSE_QUERY_DEPTH - 2 * half),
        ")".repeat(half)
    );
    let output = convert_on_small_stack(query);
    assert!(output.errors.is_empty(), "{:?}", output.errors);
    assert_eq!(output.rules.len(), 1);
}
