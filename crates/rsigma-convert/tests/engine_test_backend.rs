//! Compares the `test` backend with its reference, pySigma's
//! `TextQueryTestBackend`, run from a pinned pySigma release in Docker.
//!
//! The `test` backend has no engine to run queries in, so its contract is
//! textual: for every case both backends must produce the same queries, or
//! both must reject the rule. Run with
//! `cargo test -p rsigma-convert --test engine_test_backend -- --ignored`.

mod engines;

use std::io::Write;
use std::process::{Command, Stdio};

use engines::Problem;
use rsigma_convert::backends::test::TextQueryTestBackend;
use serde_json::{Value, json};

const IMAGE: &str = "rsigma-engine-pysigma:2.0.1";

#[test]
#[ignore = "engine test: needs Docker; run by the test backend engine workflow"]
fn test_backend_matches_pysigma() {
    engines::require_docker();
    let image = engines::docker_build("pysigma", IMAGE);
    let cases = engines::load_cases();

    let request: Vec<Value> = cases
        .iter()
        .map(|c| json!({"name": c.name, "rule": c.rule_yaml, "pipeline": c.pipeline_yaml}))
        .collect();
    let mut child = Command::new("docker")
        .args(["run", "--rm", "-i", &image])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run docker");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(Value::from(request).to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "pySigma converter failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reference: Value = serde_json::from_slice(&out.stdout).unwrap();

    let backend = TextQueryTestBackend::new();
    let mut problems = Vec::new();
    for case in &cases {
        let ours = engines::convert(&backend, case, &[], "default");
        let theirs = &reference[case.name.as_str()];
        let problem = match (ours, theirs.get("queries")) {
            (Ok(q), Some(p)) => {
                let p: Vec<String> = serde_json::from_value(p.clone()).unwrap();
                (q != p).then_some(Problem::OutputDifference {
                    actual: q,
                    reference: p,
                })
            }
            (Err(_), None) => None,
            (Ok(q), None) => Some(Problem::ReferenceRejected {
                actual: q,
                error: theirs["error"].to_string(),
            }),
            (Err(e), Some(p)) => Some(Problem::ReferenceAccepted {
                error: e,
                reference: serde_json::from_value(p.clone()).unwrap(),
            }),
        };
        problems.push((case, problem));
    }
    let failures = engines::check_problems("test-pysigma", &problems);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
