//! Evaluates the Fibratus backend's filters with Fibratus's own filter parser
//! and evaluator.
//!
//! Fibratus is Windows-only, and so are its filter packages, so this test runs
//! on a Windows host with Go installed. The Go program in
//! `tests/engines/fibratus/` builds against a pinned Fibratus commit, loads
//! Fibratus's macro library, and evaluates each generated filter against the
//! case events. Rules are converted with the built-in `fibratus_windows`
//! pipeline, both with the default macro output and with `use_macros=false`,
//! and the case events are renamed and completed the way that pipeline maps
//! Sigma fields. Run with
//! `cargo test -p rsigma-convert --test engine_fibratus -- --ignored`.

mod engines;

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::process::{Command, Stdio};

use engines::{Case, Outcome};
use rsigma_convert::backends::fibratus::FibratusBackend;
use rsigma_eval::pipeline::builtin::resolve_builtin;
use serde_json::{Value, json};

fn pipeline_doc() -> yaml_serde::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rsigma-eval/pipelines/fibratus_windows.yml");
    yaml_serde::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn transformations(doc: &yaml_serde::Value) -> &Vec<yaml_serde::Value> {
    doc["transformations"].as_sequence().unwrap()
}

fn applies_to(t: &yaml_serde::Value, category: &str) -> bool {
    t.get("rule_conditions")
        .and_then(|c| c.as_sequence())
        .is_some_and(|conds| {
            conds.iter().any(|c| {
                c["type"].as_str() == Some("logsource") && c["category"].as_str() == Some(category)
            })
        })
}

/// Every Fibratus field the pipeline maps to or conditions on.
fn pipeline_fields(doc: &yaml_serde::Value) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    for t in transformations(doc) {
        for key in ["mapping", "conditions"] {
            if let Some(m) = t.get(key).and_then(|m| m.as_mapping()) {
                for (k, v) in m {
                    if key == "mapping" {
                        match v {
                            yaml_serde::Value::Sequence(vs) => fields
                                .extend(vs.iter().filter_map(|v| v.as_str()).map(String::from)),
                            v => fields.extend(v.as_str().map(String::from)),
                        }
                    } else {
                        fields.extend(k.as_str().map(String::from));
                    }
                }
            }
        }
    }
    fields
}

/// Rename event fields through the pipeline's mapping for the case category
/// and add the fields its `add_condition` steps require (`evt.name`, ...).
/// A field without a mapping is an error for the case, which it can record as
/// a known failure.
fn fibratus_events(doc: &yaml_serde::Value, case: &Case) -> Result<Vec<Value>, String> {
    let category = case
        .logsource_category
        .as_deref()
        .unwrap_or_else(|| panic!("{}: Fibratus cases need a logsource category", case.name));
    let mut mapping: HashMap<String, String> = HashMap::new();
    let mut added: Vec<(String, Value)> = Vec::new();
    for t in transformations(doc)
        .iter()
        .filter(|t| applies_to(t, category))
    {
        match t["type"].as_str() {
            Some("field_name_mapping") => {
                for (k, v) in t["mapping"].as_mapping().unwrap() {
                    let target = v.as_str().unwrap_or_else(|| {
                        panic!("one-to-many mapping for {k:?} is not supported here")
                    });
                    mapping.insert(k.as_str().unwrap().to_string(), target.to_string());
                }
            }
            Some("add_condition") => {
                for (k, v) in t["conditions"].as_mapping().unwrap() {
                    let value = v
                        .as_str()
                        .unwrap_or_else(|| panic!("non-scalar add_condition value for {k:?}"));
                    added.push((k.as_str().unwrap().to_string(), Value::from(value)));
                }
            }
            other => panic!("unhandled transformation type {other:?} for category {category}"),
        }
    }
    case.events
        .iter()
        .map(|e| {
            let mut out = serde_json::Map::new();
            for (k, v) in e.as_object().unwrap() {
                let name = mapping
                    .get(k)
                    .ok_or_else(|| format!("field {k} has no Fibratus mapping"))?;
                out.insert(name.clone(), v.clone());
            }
            for (k, v) in &added {
                out.insert(k.clone(), v.clone());
            }
            Ok(Value::Object(out))
        })
        .collect()
}

fn build_harness(name: &str) -> (std::path::PathBuf, String) {
    if !cfg!(windows) {
        panic!("Fibratus filter packages only build for Windows; run this test on a Windows host");
    }
    let dir = engines::engines_dir().join("fibratus");
    let exe = std::env::temp_dir().join(format!(
        "rsigma-engine-fibratus-{}-{name}.exe",
        std::process::id()
    ));
    engines::run_ok(
        Command::new("go")
            .args(["build", "-o"])
            .arg(&exe)
            .arg(".")
            .current_dir(&dir)
            .env("CGO_ENABLED", "0"),
    );
    let module_dir = engines::run_ok(
        Command::new("go")
            .args([
                "list",
                "-m",
                "-f",
                "{{.Dir}}",
                "github.com/rabbitstack/fibratus",
            ])
            .current_dir(&dir),
    );
    let macros = std::path::Path::new(module_dir.trim()).join("rules/macros/macros.yml");
    assert!(
        macros.is_file(),
        "missing Fibratus macro library at {}",
        macros.display()
    );
    (exe, macros.display().to_string())
}

fn run_harness(exe: &std::path::Path, request: &Value) -> Value {
    let mut child = Command::new(exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start the Fibratus harness");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "Fibratus harness failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("unparseable harness response")
}

#[test]
#[ignore = "engine test: needs Windows and Go; run by the Fibratus engine workflow"]
fn fibratus_evaluates_cases() {
    let (exe, macros) = build_harness("cases");
    let doc = pipeline_doc();
    let pipeline = resolve_builtin("fibratus_windows").unwrap().unwrap();
    let cases = engines::load_cases();
    let events: Vec<Result<Vec<Value>, String>> =
        cases.iter().map(|c| fibratus_events(&doc, c)).collect();

    let mut failures = Vec::new();
    for (label, use_macros) in [("fibratus", "true"), ("fibratus-nomacros", "false")] {
        let backend = FibratusBackend::from_options(&HashMap::from([(
            "use_macros".to_string(),
            use_macros.to_string(),
        )]));
        let converted: Vec<Result<Vec<String>, String>> = cases
            .iter()
            .map(|c| engines::convert(&backend, c, std::slice::from_ref(&pipeline), "expr"))
            .collect();
        let request_cases: Vec<Value> = cases
            .iter()
            .zip(converted.iter().zip(&events))
            .filter_map(|(c, (conv, events))| {
                let queries = conv.as_ref().ok()?;
                assert_eq!(queries.len(), 1, "{}: expected one filter", c.name);
                Some(json!({
                    "name": c.name,
                    "expr": queries[0],
                    "events": events.as_ref().ok()?,
                }))
            })
            .collect();
        let response = run_harness(
            &exe,
            &json!({"cases": request_cases, "fields": [], "macros": macros}),
        );
        let by_name: HashMap<&str, &Value> = response["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r["name"].as_str().unwrap(), r))
            .collect();
        let results: Vec<(Case, Result<Outcome, String>)> = cases
            .iter()
            .zip(converted.into_iter().zip(&events))
            .map(|(c, (conv, events))| {
                let outcome = match (conv, events) {
                    (Err(e), _) => Ok(Outcome::ConversionRejected(e)),
                    (Ok(_), Err(e)) => Err(e.clone()),
                    (Ok(q), Ok(_)) => {
                        let r = by_name[c.name.as_str()];
                        match r.get("error").and_then(|e| e.as_str()) {
                            Some(e) => Err(format!("{e}\n    filter: {}", q[0])),
                            None => Ok(Outcome::Matched(
                                serde_json::from_value(r["matched"].clone()).unwrap(),
                            )),
                        }
                    }
                };
                (c.clone(), outcome)
            })
            .collect();
        failures.extend(engines::check_outcomes(label, &results));
    }
    let _ = std::fs::remove_file(&exe);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore = "engine test: needs Windows and Go; run by the Fibratus engine workflow"]
fn fibratus_pipeline_fields_exist() {
    let (exe, macros) = build_harness("fields");
    let fields: Vec<String> = pipeline_fields(&pipeline_doc()).into_iter().collect();
    let response = run_harness(
        &exe,
        &json!({"cases": [], "fields": fields, "macros": macros}),
    );
    let _ = std::fs::remove_file(&exe);
    let invalid = response["invalid_fields"].as_array().unwrap();
    assert!(
        invalid.is_empty(),
        "fibratus_windows maps to fields Fibratus does not define:\n  {}",
        invalid
            .iter()
            .map(|f| format!("{}: {}", f["field"], f["error"]))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}
