//! Shared helpers for the engine-backed backend tests.
//!
//! Each case in `tests/engines/cases/` is a Sigma rule, a list of events, and
//! the indices of the events the rule must match according to the Sigma
//! specification. Engine tests convert the rule with a backend, run the
//! generated query in the real engine (or in the engine's own parser and
//! evaluator), and compare the matched indices with `matches`.
//!
//! A case may list `known_failures`: engine labels mapped to a description of
//! a confirmed defect. Those engines must still fail the case; once a fix
//! makes it pass, the test fails until the entry is removed.
//!
//! Engine tests are `#[ignore]`d so the workspace test run never needs Docker
//! or Go; the per-engine CI workflows run them with `--ignored`. When they do
//! run, a missing engine prerequisite is a hard failure, never a skip.

#![allow(dead_code)]

pub mod corpus;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rsigma_convert::backend::Backend;
use rsigma_convert::convert_collection;
use rsigma_eval::pipeline::{Pipeline, parse_pipeline};
use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;
use serde_json::Value;

/// Event field holding the event's position in the case, so engines can
/// report which events matched.
pub const IDX_FIELD: &str = "rsigma_idx";

/// Labels usable in `known_failures`.
pub const ENGINE_LABELS: &[&str] = &[
    "eval",
    "postgres-jsonb",
    "postgres-columns",
    "lynxdb",
    "fibratus",
    "fibratus-nomacros",
    "test-pysigma",
];

#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub description: String,
    pub rule_yaml: String,
    /// Processing pipeline applied before any engine pipeline, and in eval.
    pub pipeline_yaml: Option<String>,
    /// The pipeline as pySigma receives it. pySigma always applies modifiers
    /// before its transformations and rejects the `apply_modifiers` key.
    pub reference_pipeline_yaml: Option<String>,
    pub logsource_category: Option<String>,
    pub events: Vec<Value>,
    pub matches: Vec<usize>,
    /// Engines that must reject the rule at conversion time.
    pub unsupported: Vec<String>,
    /// Engine label to the exact outcome of a confirmed defect.
    pub known_failures: BTreeMap<String, KnownFailure>,
}

impl Case {
    pub fn is_unsupported(&self, engine: &str) -> bool {
        self.unsupported.iter().any(|e| e == engine)
    }

    pub fn known_failure(&self, engine: &str) -> Option<&KnownFailure> {
        self.known_failures.get(engine)
    }

    pub fn pipeline(&self) -> Option<Pipeline> {
        self.pipeline_yaml.as_ref().map(|p| {
            parse_pipeline(p).unwrap_or_else(|e| panic!("{}: invalid pipeline: {e}", self.name))
        })
    }

    /// Events with [`IDX_FIELD`] added.
    pub fn indexed_events(&self) -> Vec<Value> {
        self.events
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let mut e = e.clone();
                e.as_object_mut()
                    .expect("case events must be maps")
                    .insert(IDX_FIELD.to_string(), Value::from(i));
                e
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub enum KnownFailure {
    MatchMismatch {
        reason: String,
        actual: Vec<usize>,
    },
    EngineError {
        reason: String,
        contains: String,
    },
    OutputDifference {
        reason: String,
        actual: Vec<String>,
        reference: Vec<String>,
    },
    ReferenceError {
        reason: String,
        actual: Vec<String>,
        contains: String,
    },
}

impl KnownFailure {
    fn reason(&self) -> &str {
        match self {
            Self::MatchMismatch { reason, .. }
            | Self::EngineError { reason, .. }
            | Self::OutputDifference { reason, .. }
            | Self::ReferenceError { reason, .. } => reason,
        }
    }

    fn matches(&self, problem: &Problem) -> bool {
        match (self, problem) {
            (
                Self::MatchMismatch { actual, .. },
                Problem::MatchMismatch {
                    actual: got,
                    expected: _,
                },
            ) => actual == got,
            (Self::EngineError { contains, .. }, Problem::EngineError(error)) => {
                error.contains(contains)
            }
            (
                Self::OutputDifference {
                    actual, reference, ..
                },
                Problem::OutputDifference {
                    actual: got,
                    reference: got_reference,
                },
            ) => actual == got && reference == got_reference,
            (
                Self::ReferenceError {
                    actual, contains, ..
                },
                Problem::ReferenceRejected { actual: got, error },
            ) => actual == got && error.contains(contains),
            _ => false,
        }
    }
}

pub fn engines_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/engines")
}

pub fn load_cases() -> Vec<Case> {
    let dir = engines_dir().join("cases");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no cases in {}", dir.display());
    paths.iter().map(|p| load_case(p)).collect()
}

fn load_case(path: &Path) -> Case {
    let name = path.file_stem().unwrap().to_string_lossy().into_owned();
    let text = std::fs::read_to_string(path).unwrap();
    let doc: yaml_serde::Value =
        yaml_serde::from_str(&text).unwrap_or_else(|e| panic!("{name}: invalid YAML: {e}"));
    let get = |key: &str| {
        doc.get(key)
            .unwrap_or_else(|| panic!("{name}: missing `{key}`"))
    };
    let rule = get("rule");
    let logsource_category = rule
        .get("logsource")
        .and_then(|l| l.get("category"))
        .and_then(|c| c.as_str())
        .map(str::to_string);
    let events: Vec<Value> = match serde_json::to_value(get("events")).unwrap() {
        Value::Array(a) => a,
        _ => panic!("{name}: `events` must be a list"),
    };
    for (i, e) in events.iter().enumerate() {
        assert!(e.is_object(), "{name}: event {i} must be a map");
    }
    let matches: Vec<usize> = serde_json::from_value(serde_json::to_value(get("matches")).unwrap())
        .unwrap_or_else(|e| panic!("{name}: `matches` must be a list of indices: {e}"));
    for m in &matches {
        assert!(*m < events.len(), "{name}: match index {m} out of range");
    }
    let unsupported = doc
        .get("unsupported")
        .map(|u| serde_json::from_value(serde_json::to_value(u).unwrap()).unwrap())
        .unwrap_or_default();
    let mut known_failures = BTreeMap::new();
    if let Some(entries) = doc.get("known_failures") {
        for (label, value) in entries
            .as_mapping()
            .unwrap_or_else(|| panic!("{name}: `known_failures` must be a map"))
        {
            let label = label
                .as_str()
                .unwrap_or_else(|| panic!("{name}: known-failure labels must be strings"));
            known_failures.insert(label.to_string(), parse_known_failure(&name, label, value));
        }
    }
    for label in known_failures.keys() {
        assert!(
            ENGINE_LABELS.contains(&label.as_str()),
            "{name}: unknown engine label `{label}` in known_failures"
        );
    }
    Case {
        description: get("description").as_str().unwrap_or_default().to_string(),
        rule_yaml: yaml_serde::to_string(rule).unwrap(),
        pipeline_yaml: doc
            .get("pipeline")
            .map(|p| yaml_serde::to_string(p).unwrap()),
        reference_pipeline_yaml: doc.get("pipeline").map(|p| {
            let mut p = p.clone();
            if let Some(mapping) = p.as_mapping_mut() {
                mapping.remove("apply_modifiers");
            }
            yaml_serde::to_string(&p).unwrap()
        }),
        logsource_category,
        events,
        matches,
        unsupported,
        known_failures,
        name,
    }
}

fn parse_known_failure(name: &str, label: &str, value: &yaml_serde::Value) -> KnownFailure {
    let required_str = |key: &str| {
        value
            .get(key)
            .and_then(yaml_serde::Value::as_str)
            .unwrap_or_else(|| panic!("{name}: `{label}` known failure needs string `{key}`"))
            .to_string()
    };
    let reason = required_str("reason");
    match required_str("type").as_str() {
        "match-mismatch" => {
            KnownFailure::MatchMismatch {
                reason,
                actual: serde_json::from_value(
                    serde_json::to_value(value.get("actual").unwrap_or_else(|| {
                        panic!("{name}: `{label}` match mismatch needs `actual`")
                    }))
                    .unwrap(),
                )
                .unwrap_or_else(|e| {
                    panic!("{name}: `{label}` match mismatch has invalid `actual`: {e}")
                }),
            }
        }
        "engine-error" => KnownFailure::EngineError {
            reason,
            contains: required_str("contains"),
        },
        kind @ ("output-difference" | "reference-error") => {
            let queries = |key: &str| {
                serde_json::from_value(
                    serde_json::to_value(
                        value
                            .get(key)
                            .unwrap_or_else(|| panic!("{name}: `{label}` {kind} needs `{key}`")),
                    )
                    .unwrap(),
                )
                .unwrap_or_else(|e| panic!("{name}: `{label}` {kind} has invalid `{key}`: {e}"))
            };
            if kind == "reference-error" {
                KnownFailure::ReferenceError {
                    reason,
                    actual: queries("actual"),
                    contains: required_str("contains"),
                }
            } else {
                KnownFailure::OutputDifference {
                    reason,
                    actual: queries("actual"),
                    reference: queries("reference"),
                }
            }
        }
        kind => panic!("{name}: `{label}` has unknown known-failure type `{kind}`"),
    }
}

/// Convert a case's rule. `Err` carries the conversion error text.
pub fn convert(
    backend: &dyn Backend,
    case: &Case,
    pipelines: &[Pipeline],
    format: &str,
) -> Result<Vec<String>, String> {
    let collection = parse_sigma_yaml(&case.rule_yaml)
        .unwrap_or_else(|e| panic!("{}: rule does not parse: {e}", case.name));
    let mut all_pipelines: Vec<Pipeline> = case.pipeline().into_iter().collect();
    all_pipelines.extend_from_slice(pipelines);
    let output = convert_collection(backend, &collection, &all_pipelines, format)
        .map_err(|e| e.to_string())?;
    if !output.errors.is_empty() {
        return Err(format!("{:?}", output.errors));
    }
    let queries: Vec<String> = output.queries.into_iter().flat_map(|r| r.queries).collect();
    if queries.is_empty() {
        return Err("conversion produced no query".to_string());
    }
    Ok(queries)
}

/// Indices of the case events rsigma's own evaluator matches.
pub fn eval_matches(case: &Case) -> Vec<usize> {
    let collection = parse_sigma_yaml(&case.rule_yaml).unwrap();
    let mut engine = match case.pipeline() {
        Some(pipeline) => Engine::new_with_pipeline(pipeline),
        None => Engine::new(),
    };
    engine
        .add_collection(&collection)
        .unwrap_or_else(|e| panic!("{}: rule does not compile: {e}", case.name));
    case.events
        .iter()
        .enumerate()
        .filter(|(_, e)| !engine.evaluate(&JsonEvent::borrow(e)).is_empty())
        .map(|(i, _)| i)
        .collect()
}

/// Outcome of one case on one engine.
pub enum Outcome {
    Matched(Vec<usize>),
    ConversionRejected(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    MatchMismatch {
        actual: Vec<usize>,
        expected: Vec<usize>,
    },
    EngineError(String),
    ConversionRejected(String),
    UnexpectedAcceptance(String),
    OutputDifference {
        actual: Vec<String>,
        reference: Vec<String>,
    },
    ReferenceRejected {
        actual: Vec<String>,
        error: String,
    },
    ReferenceAccepted {
        error: String,
        reference: Vec<String>,
    },
}

impl Problem {
    fn describe(&self) -> String {
        match self {
            Self::MatchMismatch { actual, expected } => {
                format!("matched {actual:?}, expected {expected:?}")
            }
            Self::EngineError(error) => format!("engine error: {error}"),
            Self::ConversionRejected(error) => format!("conversion failed: {error}"),
            Self::UnexpectedAcceptance(message) => message.clone(),
            Self::OutputDifference { actual, reference } => {
                format!("rsigma {actual:?}, reference {reference:?}")
            }
            Self::ReferenceRejected { actual, error } => {
                format!("rsigma {actual:?}, reference rejected it: {error}")
            }
            Self::ReferenceAccepted { error, reference } => {
                format!("rsigma rejected it ({error}), reference {reference:?}")
            }
        }
    }
}

/// Compare outcomes against the case expectations and panic with every
/// mismatch at once.
pub fn assert_outcomes(engine: &str, results: &[(Case, Result<Outcome, String>)]) {
    let failures = check_outcomes(engine, results);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Compare outcomes against the case expectations. Returns one summary line
/// followed by one line per failing case, or nothing when every case passed.
pub fn check_outcomes(engine: &str, results: &[(Case, Result<Outcome, String>)]) -> Vec<String> {
    let problems: Vec<(&Case, Option<Problem>)> = results
        .iter()
        .map(|(case, result)| (case, outcome_problem(engine, case, result)))
        .collect();
    check_problems(engine, &problems)
}

fn outcome_problem(engine: &str, case: &Case, result: &Result<Outcome, String>) -> Option<Problem> {
    match (result, case.is_unsupported(engine)) {
        (Err(e), _) => Some(Problem::EngineError(e.clone())),
        (Ok(Outcome::ConversionRejected(_)), true) => None,
        (Ok(Outcome::ConversionRejected(e)), false) => Some(Problem::ConversionRejected(e.clone())),
        (Ok(Outcome::Matched(got)), true) => Some(Problem::UnexpectedAcceptance(format!(
            "expected a conversion error, but the query ran and matched {got:?}"
        ))),
        (Ok(Outcome::Matched(got)), false) => {
            let mut got = got.clone();
            got.sort_unstable();
            (got != case.matches).then(|| Problem::MatchMismatch {
                actual: got,
                expected: case.matches.clone(),
            })
        }
    }
}

/// Reconcile per-case problems with the recorded known failures. A known
/// failure that no longer reproduces is itself a failure, so the fix that
/// resolves it must also remove the entry.
pub fn check_problems(engine: &str, problems: &[(&Case, Option<Problem>)]) -> Vec<String> {
    let mut failures = Vec::new();
    for (case, problem) in problems {
        match (problem, case.known_failure(engine)) {
            (Some(problem), None) => {
                failures.push(format!("  {}: {}", case.name, problem.describe()));
            }
            (None, Some(known)) => failures.push(format!(
                "  {}: now passes; remove the known failure \"{}\"",
                case.name,
                known.reason()
            )),
            (Some(problem), Some(known)) if known.matches(problem) => {}
            (Some(problem), Some(known)) => failures.push(format!(
                "  {}: known failure changed ({}); got {}",
                case.name,
                known.reason(),
                problem.describe()
            )),
            (None, None) => {}
        }
    }
    if !failures.is_empty() {
        failures.insert(
            0,
            format!(
                "{engine}: {} of {} cases failed:",
                failures.len(),
                problems.len()
            ),
        );
    }
    failures
}

/// Fail unless a Docker daemon with Linux container support is reachable.
pub fn require_docker() {
    let out = Command::new("docker")
        .args(["info", "--format", "{{.OSType}}"])
        .output();
    match out {
        Ok(o) if o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "linux" => {}
        _ => panic!("engine tests need Docker with Linux container support"),
    }
}

/// Build the Docker image in `tests/engines/<dir>` and return its tag.
pub fn docker_build(dir: &str, tag: &str) -> String {
    let context = engines_dir().join(dir);
    let status = Command::new("docker")
        .args(["build", "--quiet", "-t", tag])
        .arg(&context)
        .stdout(Stdio::null())
        .status()
        .expect("failed to run docker build");
    assert!(
        status.success(),
        "docker build failed for {}",
        context.display()
    );
    tag.to_string()
}

/// Run a command and return stdout, panicking with stderr on failure.
pub fn run_ok(cmd: &mut Command) -> String {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("failed to run {cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?} failed ({}):\n{}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
