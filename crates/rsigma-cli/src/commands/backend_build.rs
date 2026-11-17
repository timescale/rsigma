//! `rsigma backend build`: convert named rulesets into query files and
//! manifests.
//!
//! Each conversion group names a ruleset and a target. A group writes its
//! converted queries to `output` and a manifest to `<output>.manifest.json`.
//! A group that fails does not stop the others; the command exits 2 when any
//! conversion failed, 3 for configuration errors, and 1 for drift under
//! `--check`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::process;

use clap::Args;
use serde::Serialize;
use serde_json::{Value, json};

use crate::config::{ConvertGroupPartial, manifest_path};
use crate::exit_code::{CONFIG_ERROR, FINDINGS, RULE_ERROR};
use crate::fsutil::atomic_write;
use crate::output::{OutputCtx, Tabular, render_report};
use crate::ruleset::build::{ManifestDocument, manifest_documents};

use super::convert::{
    ConvertFailure, ConvertRequest, RuleStatus, convert_delegated, convert_native,
    try_native_backend,
};

/// Arguments for `rsigma backend build`.
#[derive(Args, Debug)]
pub(crate) struct BackendBuildArgs {
    /// Path to an rsigma config file. Overrides config-file discovery.
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Convert only these groups (repeatable). Defaults to every group.
    #[arg(long = "group", value_name = "NAME")]
    pub groups: Vec<String>,

    /// Report drift without writing anything. Exits 1 when either file
    /// differs from what a build would write.
    #[arg(long)]
    pub check: bool,
}

/// Manifest written next to each group's query output.
#[derive(Debug, Serialize)]
struct Manifest {
    manifest_version: u32,
    group: String,
    ruleset: String,
    target: String,
    format: String,
    pipelines: Vec<String>,
    output: String,
    generator: String,
    queries: usize,
    rules: Vec<ManifestRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<BTreeMap<String, Value>>,
}

/// One rule listed in a manifest.
#[derive(Debug, Clone, Serialize)]
struct ManifestRule {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    title: String,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
}

/// One group's result, rendered as a report row.
#[derive(Debug, Serialize)]
struct BuildRow {
    group: String,
    ruleset: String,
    target: String,
    rules: usize,
    queries: usize,
    status: String,
    output: String,
}

impl Tabular for BuildRow {
    fn headers() -> &'static [&'static str] {
        &[
            "GROUP", "RULESET", "TARGET", "RULES", "QUERIES", "STATUS", "OUTPUT",
        ]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.group.clone(),
            self.ruleset.clone(),
            self.target.clone(),
            self.rules.to_string(),
            self.queries.to_string(),
            self.status.clone(),
            self.output.clone(),
        ]
    }
}

/// A file whose contents differ from what a build would write.
#[derive(Debug, Serialize)]
struct DriftRow {
    group: String,
    path: String,
}

impl Tabular for DriftRow {
    fn headers() -> &'static [&'static str] {
        &["GROUP", "PATH"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.group.clone(), self.path.clone()]
    }
}

/// The contents a successful build would write for one group.
struct GroupOutput {
    ruleset: String,
    target: String,
    rules: Vec<ManifestRule>,
    queries: usize,
    manifest: Manifest,
    output: PathBuf,
    query_text: String,
}

enum GroupResult {
    Converted(GroupOutput),
    RuleFailed(GroupOutput, String),
    ConversionFailed(String),
    ConfigFailed(String),
}

pub(crate) fn cmd_build(args: BackendBuildArgs, ctx: OutputCtx) {
    let config = crate::config::load_and_merge(args.config.as_deref());
    let Some(convert) = config.convert.as_ref() else {
        eprintln!("error: no convert groups are configured; add a `convert:` section");
        process::exit(CONFIG_ERROR);
    };
    let Some(groups) = convert.groups.as_ref().filter(|groups| !groups.is_empty()) else {
        eprintln!("error: no convert groups are configured; add `convert.groups` entries");
        process::exit(CONFIG_ERROR);
    };
    let collisions = convert.output_collisions();
    if !collisions.is_empty() {
        for (_, message) in &collisions {
            eprintln!("error: {message}");
        }
        process::exit(CONFIG_ERROR);
    }
    let specs = config.rulesets.clone().unwrap_or_default();

    let selected: BTreeSet<String> = if args.groups.is_empty() {
        groups.keys().cloned().collect()
    } else {
        let mut selected = BTreeSet::new();
        for name in &args.groups {
            if !groups.contains_key(name) {
                eprintln!(
                    "error: unknown convert group '{name}'; configured groups: {}",
                    groups.keys().cloned().collect::<Vec<_>>().join(", ")
                );
                process::exit(CONFIG_ERROR);
            }
            selected.insert(name.clone());
        }
        selected
    };

    let mut rows = Vec::new();
    let mut drift = Vec::new();
    let mut config_failed = false;
    let mut rule_failed = false;

    for name in selected {
        let group = &groups[&name];
        let effective = convert.effective(group);
        match build_group(&name, &effective, &specs, &ctx) {
            GroupResult::Converted(output) => {
                let status = if args.check {
                    let drifted = check_group(&output);
                    if drifted.is_empty() {
                        "clean".to_string()
                    } else {
                        for path in drifted {
                            drift.push(DriftRow {
                                group: name.clone(),
                                path,
                            });
                        }
                        "drifted".to_string()
                    }
                } else {
                    match write_group(&output) {
                        Ok(written) => {
                            if written {
                                "written".to_string()
                            } else {
                                "unchanged".to_string()
                            }
                        }
                        Err(error) => {
                            eprintln!("error: group '{name}': {error}");
                            config_failed = true;
                            "failed".to_string()
                        }
                    }
                };
                rows.push(BuildRow {
                    group: name,
                    ruleset: output.ruleset,
                    target: output.target,
                    rules: output.rules.len(),
                    queries: output.queries,
                    status,
                    output: output.manifest.output,
                });
            }
            GroupResult::RuleFailed(output, message) => {
                eprintln!("error: group '{name}': {message}");
                rule_failed = true;
                if args.check {
                    for path in check_group(&output) {
                        drift.push(DriftRow {
                            group: name.clone(),
                            path,
                        });
                    }
                } else if let Err(error) = write_group(&output) {
                    eprintln!("error: group '{name}': {error}");
                    config_failed = true;
                }
                rows.push(BuildRow {
                    group: name,
                    ruleset: output.ruleset,
                    target: output.target,
                    rules: output.rules.len(),
                    queries: output.queries,
                    status: "failed".to_string(),
                    output: output.manifest.output,
                });
            }
            GroupResult::ConversionFailed(message) => {
                eprintln!("error: group '{name}': {message}");
                rule_failed = true;
                rows.push(BuildRow {
                    group: name.clone(),
                    ruleset: effective.ruleset.clone().unwrap_or_default(),
                    target: effective.target.clone().unwrap_or_default(),
                    rules: 0,
                    queries: 0,
                    status: "failed".to_string(),
                    output: effective
                        .output
                        .as_ref()
                        .map(|path| path.to_string_lossy().to_string())
                        .unwrap_or_default(),
                });
            }
            GroupResult::ConfigFailed(message) => {
                eprintln!("error: group '{name}': {message}");
                config_failed = true;
                rows.push(BuildRow {
                    group: name.clone(),
                    ruleset: effective.ruleset.clone().unwrap_or_default(),
                    target: effective.target.clone().unwrap_or_default(),
                    rules: 0,
                    queries: 0,
                    status: "failed".to_string(),
                    output: effective
                        .output
                        .as_ref()
                        .map(|path| path.to_string_lossy().to_string())
                        .unwrap_or_default(),
                });
            }
        }
    }

    if args.check {
        if drift.is_empty() {
            eprintln!("No drift in the configured conversion groups");
        } else {
            let envelope = json!({ "drifted": &drift });
            render_report(&ctx, &envelope, &drift);
        }
    } else {
        let envelope = json!({ "groups": &rows });
        render_report(&ctx, &envelope, &rows);
    }

    if config_failed {
        process::exit(CONFIG_ERROR);
    }
    if rule_failed {
        process::exit(RULE_ERROR);
    }
    if args.check && !drift.is_empty() {
        process::exit(FINDINGS);
    }
}

/// Resolve a group's ruleset and convert it.
fn build_group(
    name: &str,
    group: &ConvertGroupPartial,
    specs: &BTreeMap<String, rsigma_parser::ruleset::RulesetSpec>,
    ctx: &OutputCtx,
) -> GroupResult {
    let Some(ruleset_name) = group.ruleset.as_deref() else {
        return GroupResult::ConfigFailed("no ruleset is set".to_string());
    };
    let Some(spec) = specs.get(ruleset_name) else {
        let defined: Vec<&str> = specs.keys().map(String::as_str).collect();
        let message = if defined.is_empty() {
            format!("unknown ruleset '{ruleset_name}': no rulesets are defined")
        } else {
            format!(
                "unknown ruleset '{ruleset_name}'; defined rulesets: {}",
                defined.join(", ")
            )
        };
        return GroupResult::ConfigFailed(message);
    };
    let Some(target) = group.target.as_deref() else {
        return GroupResult::ConfigFailed("no target is set".to_string());
    };
    let Some(output) = group.output.as_ref() else {
        return GroupResult::ConfigFailed("no output is set".to_string());
    };
    let format = group.format.as_deref().unwrap_or("default");
    let skip_unsupported = group.skip_unsupported.unwrap_or(false);
    let without_pipeline = group.without_pipeline.unwrap_or(false);
    let pipeline_paths = group.pipelines.clone().unwrap_or_default();
    let options: BTreeMap<String, String> = group.options.clone().unwrap_or_default();

    let resolved = match rsigma_parser::ruleset::resolve_ruleset(
        ruleset_name,
        spec,
        &rsigma_parser::ruleset::ResolveOptions::default(),
    ) {
        Ok(resolved) => {
            crate::report_load_diagnostics(&resolved.collection);
            if !ctx.quiet {
                for warning in &resolved.warnings {
                    eprintln!("warning: {warning}");
                }
            }
            resolved
        }
        Err(error) => {
            let message = error.to_string();
            return GroupResult::ConfigFailed(
                if message.starts_with(&format!("ruleset '{ruleset_name}'")) {
                    message
                } else {
                    format!("ruleset '{ruleset_name}': {message}")
                },
            );
        }
    };
    let manifest_rules = manifest_documents(&resolved);

    let manifest_path = manifest_path(output);
    let output_text = output.to_string_lossy().to_string();

    let native_options: HashMap<String, String> = options
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if try_native_backend(target, &native_options).is_some() {
        let pipelines = match crate::try_load_pipelines(&pipeline_paths) {
            Ok(pipelines) => pipelines,
            Err(message) => return GroupResult::ConfigFailed(message),
        };
        let request = ConvertRequest {
            collection: &resolved.collection,
            target,
            format,
            pipelines,
            options: native_options,
            skip_unsupported,
            without_pipeline,
        };
        let converted = match convert_native(&request) {
            Ok(converted) => converted,
            Err(ConvertFailure::Config(message)) => return GroupResult::ConfigFailed(message),
            Err(ConvertFailure::Rule(message)) => return GroupResult::ConversionFailed(message),
        };

        let statuses = ConversionStatuses::new(&converted.rules);
        let rules = manifest_rules
            .into_iter()
            .map(|document| {
                let status = statuses.of(&document);
                manifest_rule(document, Some(status))
            })
            .collect::<Vec<_>>();
        let failed_rules = rules
            .iter()
            .filter(|rule| rule.status == Some("failed"))
            .count();
        for (title, message) in &converted.warnings {
            eprintln!("  warning: group '{name}', rule '{title}': {message}");
        }

        let manifest = Manifest {
            manifest_version: 1,
            group: name.to_string(),
            ruleset: ruleset_name.to_string(),
            target: target.to_string(),
            format: format.to_string(),
            pipelines: pipeline_strings(&pipeline_paths),
            output: output_text.clone(),
            generator: generator(),
            queries: converted.queries,
            rules,
            metadata: group.metadata.clone(),
        };
        let group_output = GroupOutput {
            ruleset: ruleset_name.to_string(),
            target: target.to_string(),
            rules: manifest.rules.clone(),
            queries: converted.queries,
            manifest,
            output: output.clone(),
            query_text: converted.text,
        };
        return if failed_rules > 0 {
            GroupResult::RuleFailed(
                group_output,
                format!(
                    "{failed_rules} rule(s) failed to convert; see {}",
                    manifest_path.display()
                ),
            )
        } else {
            GroupResult::Converted(group_output)
        };
    }

    // Delegated targets are materialized so sigma-cli reads a stable tree.
    let materialized = match crate::ruleset::build::materialize_temp(&resolved, spec) {
        Ok(dir) => dir,
        Err(error) => return GroupResult::ConfigFailed(error),
    };
    let option_list = options
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    let delegated = convert_delegated(
        &[materialized.path().to_path_buf()],
        target,
        format,
        &pipeline_paths,
        &option_list,
        skip_unsupported,
        without_pipeline,
    );
    drop(materialized);

    let delegated = match delegated {
        Ok(delegated) => delegated,
        Err(ConvertFailure::Config(message)) => return GroupResult::ConfigFailed(message),
        Err(ConvertFailure::Rule(message)) => {
            return GroupResult::ConversionFailed(if message.is_empty() {
                "sigma-cli reported a conversion failure".to_string()
            } else {
                message
            });
        }
    };
    if !delegated.stderr.is_empty() {
        eprint!("{}", delegated.stderr);
    }

    let rules = manifest_rules
        .into_iter()
        .map(|document| manifest_rule(document, None))
        .collect::<Vec<_>>();
    let queries = delegated.queries.len();
    let manifest = Manifest {
        manifest_version: 1,
        group: name.to_string(),
        ruleset: ruleset_name.to_string(),
        target: target.to_string(),
        format: format.to_string(),
        pipelines: pipeline_strings(&pipeline_paths),
        output: output_text,
        generator: generator(),
        queries,
        rules,
        metadata: group.metadata.clone(),
    };
    GroupResult::Converted(GroupOutput {
        ruleset: ruleset_name.to_string(),
        target: target.to_string(),
        rules: manifest.rules.clone(),
        queries,
        manifest,
        output: output.clone(),
        query_text: delegated.raw,
    })
}

/// Conversion outcomes indexed for matching back to ruleset documents.
struct ConversionStatuses<'a> {
    converted_ids: HashSet<&'a str>,
    converted_without_id: HashSet<&'a str>,
    errors: HashMap<&'a str, RuleStatus>,
}

impl<'a> ConversionStatuses<'a> {
    fn new(outcomes: &'a [super::convert::RuleOutcome]) -> Self {
        let mut statuses = Self {
            converted_ids: HashSet::new(),
            converted_without_id: HashSet::new(),
            errors: HashMap::new(),
        };
        for outcome in outcomes {
            match (outcome.status, &outcome.id) {
                (RuleStatus::Converted, Some(id)) => {
                    statuses.converted_ids.insert(id);
                }
                (RuleStatus::Converted, None) => {
                    statuses.converted_without_id.insert(&outcome.title);
                }
                (status, _) => {
                    statuses.errors.insert(&outcome.title, status);
                }
            }
        }
        statuses
    }

    /// A document is converted when the backend returned a result for its id
    /// (or, without an id, its title). Failed and skipped rules carry only a
    /// title. Anything else produced no query of its own.
    fn of(&self, document: &ManifestDocument) -> &'static str {
        let converted = match &document.id {
            Some(id) => self.converted_ids.contains(id.as_str()),
            None => self.converted_without_id.contains(document.title.as_str()),
        };
        if converted {
            return "converted";
        }
        match self.errors.get(document.title.as_str()) {
            Some(RuleStatus::Failed) => "failed",
            Some(_) => "skipped",
            None => "no_query",
        }
    }
}

fn manifest_rule(document: ManifestDocument, status: Option<&'static str>) -> ManifestRule {
    ManifestRule {
        kind: document.kind.to_string(),
        id: document.id,
        title: document.title,
        sha256: document.sha256,
        status,
    }
}

fn generator() -> String {
    format!("rsigma {}", env!("CARGO_PKG_VERSION"))
}

fn pipeline_strings(pipelines: &[PathBuf]) -> Vec<String> {
    pipelines
        .iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect()
}

fn manifest_contents(manifest: &Manifest) -> String {
    let mut text = serde_json::to_string_pretty(manifest).unwrap_or_default();
    text.push('\n');
    text
}

fn check_group(output: &GroupOutput) -> Vec<String> {
    let mut drifted = Vec::new();
    if !fs::read(&output.output).is_ok_and(|existing| existing == output.query_text.as_bytes()) {
        drifted.push(output.output.to_string_lossy().to_string());
    }
    let manifest = manifest_path(&output.output);
    let contents = manifest_contents(&output.manifest);
    if !fs::read(&manifest).is_ok_and(|existing| existing == contents.as_bytes()) {
        drifted.push(manifest.to_string_lossy().to_string());
    }
    drifted
}

/// Write the query output and manifest. Returns whether anything changed.
fn write_group(output: &GroupOutput) -> Result<bool, String> {
    let manifest = manifest_path(&output.output);
    let contents = manifest_contents(&output.manifest);
    let mut changed = false;
    for (path, text) in [
        (&output.output, output.query_text.as_str()),
        (&manifest, contents.as_str()),
    ] {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        if fs::read(path).is_ok_and(|existing| existing == text.as_bytes()) {
            continue;
        }
        atomic_write(path, text)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        changed = true;
    }
    Ok(changed)
}
