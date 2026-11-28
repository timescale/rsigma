#![no_main]
use std::collections::HashMap;
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use rsigma_convert::backend::Backend;
use rsigma_convert::backends::postgres::PostgresBackend;
use rsigma_eval::pipeline::state::PipelineState;
use rsigma_parser::SigmaRule;

// Each input line is one `fields` entry of a PostgreSQL detection rule,
// converted in every output format over flat columns and over a JSONB column.
// Whatever converts must keep rule content inside quoted identifiers and
// string literals: outside them the query has balanced quotes and
// parentheses and no `;`, `--`, or `/*`.

static RULE: LazyLock<SigmaRule> = LazyLock::new(|| {
    rsigma_parser::parse_sigma_yaml(
        "title: T\nid: 00000000-0000-0000-0000-000000000001\nlogsource: {category: test}\n\
         detection:\n  sel: {action: login}\n  condition: sel\n",
    )
    .unwrap()
    .rules
    .remove(0)
});

static BACKENDS: LazyLock<[PostgresBackend; 2]> = LazyLock::new(|| {
    [
        PostgresBackend::new(),
        PostgresBackend::from_options(&HashMap::from([(
            "json_field".to_string(),
            "data".to_string(),
        )])),
    ]
});

const FORMATS: &[&str] = &[
    "default",
    "view",
    "timescaledb",
    "continuous_aggregate",
    "sliding_window",
];

fn check_structure(sql: &str) {
    let mut chars = sql.chars().peekable();
    let mut depth = 0i64;
    while let Some(c) = chars.next() {
        match c {
            '"' | '\'' => loop {
                match chars.next() {
                    Some(q) if q == c => {
                        if chars.peek() == Some(&c) {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    Some(_) => {}
                    None => panic!("unterminated {c} in {sql:?}"),
                }
            },
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                assert!(depth >= 0, "unbalanced ) in {sql:?}");
            }
            ';' => panic!("; outside quotes in {sql:?}"),
            '-' if chars.peek() == Some(&'-') => panic!("-- outside quotes in {sql:?}"),
            '/' if chars.peek() == Some(&'*') => panic!("/* outside quotes in {sql:?}"),
            _ => {}
        }
    }
    assert_eq!(depth, 0, "unbalanced ( in {sql:?}");
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut rule = RULE.clone();
    rule.fields = text.split('\n').map(str::to_string).collect();
    for backend in BACKENDS.iter() {
        for format in FORMATS {
            if let Ok(queries) = backend.convert_rule(&rule, format, &PipelineState::default()) {
                for sql in &queries {
                    check_structure(sql);
                }
            }
        }
    }
});
