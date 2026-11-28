//! Reverse conversion only returns a rule whose emitted YAML reads back as
//! the same rule, whatever the query's field names, values, and the caller's
//! title contain.

use rsigma_convert::{LuceneFrontend, ReverseCtx, reverse_collection};

fn ctx(title: &str) -> ReverseCtx {
    ReverseCtx {
        title: Some(title.to_string()),
        product: Some("windows".to_string()),
        ..Default::default()
    }
}

#[test]
fn every_returned_rule_reads_back_the_same() {
    let queries: Vec<String> = [
        r#"Image:"C:\\a: b # c""#,
        r#"CommandLine:"line\nbreak""#,
        r#"User:"it's \"quoted\"""#,
        r"a\:b:x",
        r"a\|b:x",
        r"a\ b:x",
        r"a\#b:x",
        r#"Name:"---""#,
        r#"Name:"...""#,
    ]
    .iter()
    .map(|query| query.to_string())
    .collect();
    for title in ["Plain", "Title\n---\nlevel: low # x", "a\u{2028}b: c"] {
        let output = reverse_collection(&LuceneFrontend, &queries, &ctx(title));
        assert_eq!(
            output.rules.len() + output.errors.len(),
            queries.len(),
            "{title:?}"
        );
        for result in &output.rules {
            let collection = rsigma_parser::parse_sigma_yaml(&result.yaml).unwrap();
            assert!(!collection.has_errors(), "{}", result.yaml);
            assert_eq!(collection.rules.len(), 1, "{}", result.yaml);
            assert_eq!(collection.rules[0].title, title, "{}", result.yaml);
            assert_eq!(
                collection.rules[0].detection.named, result.rule.detection.named,
                "{}",
                result.yaml
            );
        }
    }
}
