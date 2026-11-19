//! The `rsigma config` command group: scaffold, validate, introspect, and
//! locate configuration files.
//!
//! Output contract (agent-friendly): machine-readable answers go to stdout,
//! diagnostics and human messages go to stderr. `validate` supports
//! `--format json` so agents can branch on a structured envelope. The global
//! `--output-format` is honored when the local `--format` is unset.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};

use crate::exit_code;
use crate::output::{
    OutputCtx, OutputFormat, Tabular, render_json, render_json_only, render_report,
};

use super::defaults::defaults_partial;
use super::resolve::{Source, env_partial, resolve_layers, to_value, value_at};
use super::{discover, ignored_key_warning, inactive_sections, load_layered};
use rsigma_parser::ruleset::validate_spec;

/// Validate the `daemon.rulesets` selection.
fn daemon_ruleset_errors(config: &super::RsigmaConfigPartial) -> Vec<SemanticError> {
    let mut errors = Vec::new();
    let defined: HashSet<&str> = config
        .rulesets
        .as_ref()
        .map(|rulesets| rulesets.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let Some(daemon) = &config.daemon else {
        return errors;
    };
    let list = daemon
        .rulesets
        .as_ref()
        .filter(|entries| !entries.is_empty());
    if daemon.rules.is_some() && list.is_some() {
        errors.push(SemanticError::new(
            "daemon",
            "set either daemon.rules or daemon.rulesets, not both",
        ));
    }
    if let Some(entries) = list {
        ruleset_list_errors("daemon", entries, &defined, &mut errors);
    }
    errors
}

/// One semantic problem found while validating a config section, keyed by
/// the dotted config path it concerns.
#[derive(Debug, Clone)]
struct SemanticError {
    path: String,
    message: String,
}

impl SemanticError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Validate the `convert` section: group names, ruleset references, and the
/// fields a group needs after the defaults are folded in.
fn convert_errors(config: &super::RsigmaConfigPartial) -> Vec<SemanticError> {
    use rsigma_parser::ruleset::validate_ruleset_name;

    let mut errors = Vec::new();
    let Some(convert) = &config.convert else {
        return errors;
    };
    let Some(groups) = &convert.groups else {
        return errors;
    };
    let defined: HashSet<&str> = config
        .rulesets
        .as_ref()
        .map(|rulesets| rulesets.keys().map(String::as_str).collect())
        .unwrap_or_default();

    for (name, group) in groups {
        let path = format!("convert.groups.{name}");
        if let Err(message) = validate_ruleset_name(name) {
            errors.push(SemanticError {
                path: path.clone(),
                message: message.replace("ruleset name", "group name"),
            });
        }
        let effective = convert.effective(group);
        let Some(ruleset) = effective.ruleset.as_deref() else {
            errors.push(SemanticError {
                path: path.clone(),
                message: format!("convert group '{name}' has no ruleset"),
            });
            continue;
        };
        if !defined.contains(ruleset) {
            errors.push(SemanticError {
                path: path.clone(),
                message: format!("convert group '{name}' names unknown ruleset '{ruleset}'"),
            });
        }
        if effective.target.is_none() {
            errors.push(SemanticError {
                path: path.clone(),
                message: format!("convert group '{name}' has no target"),
            });
        }
        if effective.output.is_none() {
            errors.push(SemanticError {
                path: path.clone(),
                message: format!("convert group '{name}' has no output"),
            });
        }
    }
    for (name, message) in convert.output_collisions() {
        errors.push(SemanticError::new(
            format!("convert.groups.{name}"),
            message,
        ));
    }
    errors
}

/// Validate the `eval.ruleset`/`eval.rulesets` selection.
fn eval_ruleset_errors(config: &super::RsigmaConfigPartial) -> Vec<SemanticError> {
    let mut errors = Vec::new();
    let defined: HashSet<&str> = config
        .rulesets
        .as_ref()
        .map(|rulesets| rulesets.keys().map(String::as_str).collect())
        .unwrap_or_default();

    let Some(eval) = &config.eval else {
        return errors;
    };
    let list = eval.rulesets.as_ref().filter(|entries| !entries.is_empty());
    if eval.rules.is_some() && (eval.ruleset.is_some() || list.is_some()) {
        errors.push(SemanticError::new(
            "eval",
            "set either eval.rules or eval.ruleset/eval.rulesets, not both",
        ));
    }
    if eval.ruleset.is_some() && list.is_some() {
        errors.push(SemanticError::new(
            "eval",
            "set either eval.ruleset or eval.rulesets, not both",
        ));
    }
    if let Some(name) = &eval.ruleset
        && !defined.contains(name.as_str())
    {
        errors.push(SemanticError::new(
            "eval.ruleset",
            format!("eval.ruleset names unknown ruleset '{name}'"),
        ));
    }
    if let Some(entries) = list {
        ruleset_list_errors("eval", entries, &defined, &mut errors);
    }
    errors
}

/// Check a `<section>.rulesets` list for duplicate or undefined names and
/// unknown entry or `when` keys. Schema names are checked when the classifier
/// loads, since `--schema-config` can add schemas.
fn ruleset_list_errors(
    section: &str,
    entries: &[super::RulesetEntryPartial],
    defined: &HashSet<&str>,
    errors: &mut Vec<SemanticError>,
) {
    let path = format!("{section}.rulesets");
    let mut seen = HashSet::new();
    for entry in entries {
        let (name, when, tenants, unknown) = match entry {
            super::RulesetEntryPartial::Name(name) => (name, None, None, None),
            super::RulesetEntryPartial::Bound {
                name,
                when,
                tenants,
                unknown,
            } => (name, when.as_ref(), tenants.as_ref(), Some(unknown)),
        };
        if section != "daemon" && tenants.is_some_and(|t| !t.is_empty()) {
            errors.push(SemanticError::new(
                &path,
                format!(
                    "ruleset '{name}' sets `tenants`, which is only valid under daemon.rulesets"
                ),
            ));
        }
        if !seen.insert(name.as_str()) {
            errors.push(SemanticError::new(
                &path,
                format!("duplicate ruleset name '{name}'"),
            ));
        }
        if !defined.contains(name.as_str()) {
            errors.push(SemanticError::new(
                &path,
                format!("{section}.rulesets names unknown ruleset '{name}'"),
            ));
        }
        if let Some(unknown) = unknown
            && !unknown.is_empty()
        {
            errors.push(SemanticError::new(
                &path,
                format!(
                    "unknown key(s) in ruleset entry '{name}': {}",
                    unknown.keys().cloned().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
        if let Some(when) = when
            && !when.unknown.is_empty()
        {
            errors.push(SemanticError::new(
                &path,
                format!(
                    "unknown key(s) in `when` of ruleset entry '{name}': {}",
                    when.unknown.keys().cloned().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
}

/// Render protected keys dropped from project files as `[{file, key}]`.
fn ignored_keys_json(ignored: &[(PathBuf, &'static str)]) -> Value {
    ignored
        .iter()
        .map(|(path, key)| json!({ "file": path, "key": key }))
        .collect()
}

/// The committed, commented template emitted by `rsigma config init`.
const TEMPLATE: &str = include_str!("template.yaml");

#[derive(Subcommand, Debug)]
pub(crate) enum ConfigCommands {
    /// Write a commented config template
    Init(InitArgs),

    /// Load config files and report unknown keys, inactive sections, and errors
    Validate(ValidateArgs),

    /// Print the effective config with the source of each value
    Show(ShowArgs),

    /// Print the JSON Schema for the config file
    Schema,

    /// Print the config file path(s) that would be loaded
    Path(PathArgs),

    /// Ask a running daemon to hot-reload (POST /api/v1/reload)
    Reload(ReloadArgs),
}

#[derive(Args, Debug)]
pub(crate) struct InitArgs {
    /// Where to write the template (default: ./rsigma.yaml)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Overwrite an existing file
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub(crate) struct ValidateArgs {
    /// Explicit config file (otherwise the discovery chain is used)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Output format: text (default) or json. When unset, the global
    /// `--output-format` is used.
    #[arg(long, value_parser = ["text", "json"])]
    pub format: Option<String>,

    /// Treat unknown keys as errors (non-zero exit)
    #[arg(long)]
    pub strict: bool,
}

#[derive(Args, Debug)]
pub(crate) struct ShowArgs {
    /// Explicit config file (otherwise the discovery chain is used)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Restrict output to one section
    #[arg(long = "for", value_parser = ["global", "daemon", "eval", "rulesets", "convert"])]
    pub section: Option<String>,

    /// Output format: text (default), json, or yaml. When unset, the global
    /// `--output-format` is used.
    #[arg(long, value_parser = ["text", "json", "yaml"])]
    pub format: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct PathArgs {
    /// Explicit config file (otherwise the discovery chain is used)
    #[arg(short, long)]
    pub config: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct ReloadArgs {
    /// Daemon API address as `host:port` or a full URL.
    /// Defaults to `daemon.api.addr` from the resolved config.
    #[arg(long)]
    pub addr: Option<String>,

    /// Explicit config file used to resolve the daemon address
    #[arg(short, long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct PathRow {
    source: String,
    path: String,
}

impl Tabular for PathRow {
    fn headers() -> &'static [&'static str] {
        &["SOURCE", "PATH"]
    }
    fn row(&self) -> Vec<String> {
        vec![self.source.clone(), self.path.clone()]
    }
}

#[derive(Debug, Serialize)]
struct ValidateIssueRow {
    kind: String,
    file: String,
    detail: String,
}

impl Tabular for ValidateIssueRow {
    fn headers() -> &'static [&'static str] {
        &["KIND", "FILE", "DETAIL"]
    }
    fn row(&self) -> Vec<String> {
        vec![self.kind.clone(), self.file.clone(), self.detail.clone()]
    }
}

#[derive(Debug, Serialize)]
struct ShowRow {
    path: String,
    value: String,
    source: String,
}

impl Tabular for ShowRow {
    fn headers() -> &'static [&'static str] {
        &["PATH", "VALUE", "SOURCE"]
    }
    fn row(&self) -> Vec<String> {
        vec![self.path.clone(), self.value.clone(), self.source.clone()]
    }
}

/// Dispatch a `rsigma config` subcommand.
pub(crate) fn dispatch(cmd: ConfigCommands, ctx: OutputCtx) {
    match cmd {
        ConfigCommands::Init(args) => cmd_init(args, ctx),
        ConfigCommands::Validate(args) => cmd_validate(args, ctx),
        ConfigCommands::Show(args) => cmd_show(args, ctx),
        ConfigCommands::Schema => cmd_schema(ctx),
        ConfigCommands::Path(args) => cmd_path(args, ctx),
        ConfigCommands::Reload(args) => cmd_reload(args, ctx),
    }
}

fn cmd_init(args: InitArgs, ctx: OutputCtx) {
    if ctx.explicit_format {
        ctx.warn_unsupported("config init", "file write (no stdout data)");
    }
    let output = args.output.unwrap_or_else(|| PathBuf::from("rsigma.yaml"));
    if output.exists() && !args.force {
        eprintln!(
            "refusing to overwrite existing {} (pass --force to replace it)",
            output.display()
        );
        process::exit(exit_code::CONFIG_ERROR);
    }
    if let Err(e) = std::fs::write(&output, TEMPLATE) {
        eprintln!("could not write {}: {e}", output.display());
        process::exit(exit_code::CONFIG_ERROR);
    }
    eprintln!("Wrote config template to {}", output.display());
}

fn cmd_validate(args: ValidateArgs, ctx: OutputCtx) {
    let mode = resolve_local_or_global(
        "config validate",
        args.format.as_deref(),
        &ctx,
        "text",
        &["text", "json"],
    );

    match load_layered(args.config.as_deref()) {
        Ok(loaded) => {
            let inactive = inactive_sections(&loaded.config);
            let unknown_count = loaded.unknown_keys.len();
            let mut semantic_errors: Vec<SemanticError> = loaded
                .config
                .rulesets
                .as_ref()
                .map(|rulesets| {
                    let mut errors = Vec::new();
                    for (name, spec) in rulesets {
                        for message in validate_spec(name, spec) {
                            errors.push(SemanticError::new(format!("rulesets.{name}"), message));
                        }
                    }
                    errors
                })
                .unwrap_or_default();
            semantic_errors.extend(eval_ruleset_errors(&loaded.config));
            semantic_errors.extend(daemon_ruleset_errors(&loaded.config));
            semantic_errors.extend(convert_errors(&loaded.config));
            let failed = (args.strict && unknown_count > 0) || !semantic_errors.is_empty();

            let envelope = serde_json::json!({
                "ok": !failed,
                "sources": loaded.sources,
                "unknown_keys": loaded
                    .unknown_keys
                    .iter()
                    .map(|(path, key)| serde_json::json!({
                        "file": path,
                        "key": key,
                    }))
                    .collect::<Vec<_>>(),
                "ignored_keys": ignored_keys_json(&loaded.ignored_keys),
                "inactive_sections": inactive,
                "semantic_errors": semantic_errors
                    .iter()
                    .map(|error| serde_json::json!({
                        "path": error.path,
                        "message": error.message,
                    }))
                    .collect::<Vec<_>>(),
            });

            let mut rows = Vec::new();
            for (path, key) in &loaded.unknown_keys {
                rows.push(ValidateIssueRow {
                    kind: "unknown_key".into(),
                    file: path.display().to_string(),
                    detail: key.clone(),
                });
            }
            for (path, key) in &loaded.ignored_keys {
                rows.push(ValidateIssueRow {
                    kind: "ignored_key".into(),
                    file: path.display().to_string(),
                    detail: key.to_string(),
                });
            }
            for section in &inactive {
                rows.push(ValidateIssueRow {
                    kind: "inactive_section".into(),
                    file: String::new(),
                    detail: section.to_string(),
                });
            }
            for error in &semantic_errors {
                rows.push(ValidateIssueRow {
                    kind: "semantic_error".into(),
                    file: error.path.clone(),
                    detail: error.message.clone(),
                });
            }
            if rows.is_empty() {
                rows.push(ValidateIssueRow {
                    kind: if failed { "error" } else { "ok" }.into(),
                    file: String::new(),
                    detail: if failed {
                        format!("{unknown_count} unknown key(s)")
                    } else {
                        "valid".into()
                    },
                });
            }

            match mode.as_str() {
                "json" => render_json(&envelope, true),
                "ndjson" | "table" | "csv" | "tsv" => {
                    // Build a temporary ctx with the resolved format so
                    // render_report branches correctly.
                    let mut report_ctx = ctx;
                    report_ctx.format = OutputFormat::parse(&mode).unwrap_or(ctx.format);
                    report_ctx.explicit_format = true;
                    render_report(&report_ctx, &envelope, &rows);
                }
                _ => {
                    if loaded.sources.is_empty() {
                        eprintln!("No config files found; compiled defaults apply.");
                    } else {
                        eprintln!("Loaded (low to high precedence):");
                        for source in &loaded.sources {
                            eprintln!("  - {}", source.display());
                        }
                    }
                    for (path, key) in &loaded.unknown_keys {
                        eprintln!("warning: unknown key '{key}' in {}", path.display());
                    }
                    for (path, key) in &loaded.ignored_keys {
                        eprintln!("{}", ignored_key_warning(path, key));
                    }
                    for section in &inactive {
                        eprintln!(
                            "warning: section '{section}' is set but inert in this build (feature disabled)"
                        );
                    }
                    for error in &semantic_errors {
                        eprintln!("error: {}", error.message);
                    }
                    if failed {
                        if unknown_count > 0 {
                            eprintln!("{unknown_count} unknown key(s) found (--strict)");
                        }
                        if !semantic_errors.is_empty() {
                            eprintln!("{} configuration error(s) found", semantic_errors.len());
                        }
                    } else {
                        eprintln!("Config is valid.");
                    }
                }
            }

            if failed {
                process::exit(exit_code::CONFIG_ERROR);
            }
        }
        Err(e) => {
            match mode.as_str() {
                "json" | "ndjson" => {
                    let envelope = serde_json::json!({
                        "ok": false,
                        "error": e.to_string(),
                    });
                    if mode == "ndjson" {
                        render_json(&envelope, false);
                    } else {
                        render_json(&envelope, true);
                    }
                }
                "table" | "csv" | "tsv" => {
                    let rows = [ValidateIssueRow {
                        kind: "error".into(),
                        file: String::new(),
                        detail: e.to_string(),
                    }];
                    let envelope = serde_json::json!({ "ok": false, "error": e.to_string() });
                    let mut report_ctx = ctx;
                    report_ctx.format = OutputFormat::parse(&mode).unwrap_or(ctx.format);
                    report_ctx.explicit_format = true;
                    render_report(&report_ctx, &envelope, &rows);
                }
                _ => eprintln!("error: {e}"),
            }
            process::exit(exit_code::CONFIG_ERROR);
        }
    }
}

fn cmd_show(args: ShowArgs, ctx: OutputCtx) {
    let mode = resolve_local_or_global(
        "config show",
        args.format.as_deref(),
        &ctx,
        "text",
        &["text", "json", "yaml"],
    );

    let loaded = match load_layered(args.config.as_deref()) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    let default_v = to_value(&defaults_partial());
    let file_v = to_value(&loaded.config);
    let env_v = to_value(&env_partial());
    // No flag layer for `config show`; that only applies to a live command.
    let resolved = resolve_layers(default_v, file_v, env_v, Value::Null);

    let filter = args.section.as_deref();
    let merged = filter_section(&resolved.merged, filter);

    let rows: Vec<ShowRow> = resolved
        .sources
        .iter()
        .filter(|(path, _)| section_matches(path, filter))
        .map(|(path, source)| ShowRow {
            path: path.clone(),
            value: value_at(&resolved.merged, path)
                .map(render_scalar)
                .unwrap_or_default(),
            source: source.to_string(),
        })
        .collect();

    if mode != "json" {
        for (path, key) in &loaded.ignored_keys {
            eprintln!("{}", ignored_key_warning(path, key));
        }
    }

    match mode.as_str() {
        "json" => {
            let sources: BTreeMap<&String, Source> = resolved
                .sources
                .iter()
                .filter(|(path, _)| section_matches(path, filter))
                .map(|(path, source)| (path, *source))
                .collect();
            let envelope = json!({
                "config": merged,
                "sources": sources,
                "ignored_keys": ignored_keys_json(&loaded.ignored_keys),
            });
            render_json(&envelope, true);
        }
        "yaml" => {
            println!("{}", yaml_serde::to_string(&merged).unwrap_or_default());
        }
        "ndjson" | "table" | "csv" | "tsv" => {
            let envelope = json!({ "config": merged, "rows": rows });
            let mut report_ctx = ctx;
            report_ctx.format = OutputFormat::parse(&mode).unwrap_or(ctx.format);
            report_ctx.explicit_format = true;
            render_report(&report_ctx, &envelope, &rows);
        }
        _ => {
            for row in &rows {
                println!("{} = {}  ({})", row.path, row.value, row.source);
            }
        }
    }
}

/// Keep only the requested top-level section, or everything when `None`.
fn filter_section(merged: &Value, section: Option<&str>) -> Value {
    match (section, merged) {
        (Some(name), Value::Object(map)) => {
            let mut out = serde_json::Map::new();
            if let Some(v) = map.get(name) {
                out.insert(name.to_string(), v.clone());
            }
            Value::Object(out)
        }
        _ => merged.clone(),
    }
}

/// Whether a dotted leaf path belongs to the requested section.
fn section_matches(path: &str, section: Option<&str>) -> bool {
    match section {
        None => true,
        Some(name) => path == name || path.starts_with(&format!("{name}.")),
    }
}

/// Render a JSON value for the text view (bare strings, JSON for the rest).
fn render_scalar(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn cmd_schema(ctx: OutputCtx) {
    let schema = schemars::schema_for!(super::RsigmaConfigPartial);
    render_json_only("config schema", &ctx, &schema);
}

fn cmd_path(args: PathArgs, ctx: OutputCtx) {
    let paths = discover(args.config.as_deref());
    if !ctx.explicit_format {
        if paths.is_empty() {
            println!("none");
        } else {
            for path in paths {
                println!("{}", path.display());
            }
        }
        return;
    }

    let rows: Vec<PathRow> = if paths.is_empty() {
        vec![PathRow {
            source: "none".into(),
            path: String::new(),
        }]
    } else {
        paths
            .iter()
            .enumerate()
            .map(|(i, path)| PathRow {
                source: format!("{}", i + 1),
                path: path.display().to_string(),
            })
            .collect()
    };
    let envelope = json!({ "paths": rows });
    render_report(&ctx, &envelope, &rows);
}

fn cmd_reload(args: ReloadArgs, ctx: OutputCtx) {
    if ctx.explicit_format {
        ctx.warn_unsupported("config reload", "status on stderr (no stdout data)");
    }
    let addr = super::resolve_daemon_addr(args.addr, args.config.as_deref());
    let url = super::api_url(&addr, "/api/v1/reload");

    match ureq::post(&url).send_empty() {
        Ok(resp) if resp.status().is_success() => {
            eprintln!("reload requested: {url}");
        }
        Ok(resp) => {
            eprintln!("reload failed: {url} returned HTTP {}", resp.status());
            process::exit(exit_code::CONFIG_ERROR);
        }
        Err(e) => {
            eprintln!("reload failed: could not reach {url}: {e}");
            eprintln!("(is the daemon running? on unix you can also `kill -HUP <pid>`)");
            process::exit(exit_code::CONFIG_ERROR);
        }
    }
}

/// Resolve the effective format string for a config subcommand.
///
/// Local `--format` wins when set. When both local and global selectors are
/// explicit, warn and keep the local value. When only the global selector is
/// set, map it into a mode string (`json`/`ndjson`/`table`/`csv`/`tsv`, or
/// `text` for unsupported local-only defaults).
fn resolve_local_or_global(
    command: &str,
    local: Option<&str>,
    ctx: &OutputCtx,
    default: &str,
    local_allowed: &[&str],
) -> String {
    if let Some(local) = local {
        if ctx.explicit_format {
            ctx.warn_ignored(command, "local --format takes precedence");
        }
        return local.to_string();
    }
    if ctx.explicit_format {
        let global = ctx.format.as_str();
        // Global formats always work through render_report / render_json.
        // Local-only values like `yaml`/`text` are not produced by the global
        // selector.
        if local_allowed.contains(&global) || matches!(global, "ndjson" | "table" | "csv" | "tsv") {
            return global.to_string();
        }
        ctx.warn_unsupported(command, default);
        return default.to_string();
    }
    default.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partial(yaml: &str) -> super::super::RsigmaConfigPartial {
        yaml_serde::from_str(yaml).expect("valid partial")
    }

    #[test]
    fn convert_errors_accept_a_complete_group() {
        let config = partial(
            "rulesets:\n  linux_edge:\n    sources: [rules]\nconvert:\n  defaults:\n    target: postgres\n  groups:\n    linux_edge_pg:\n      ruleset: linux_edge\n      output: build/linux_edge.sql\n",
        );
        assert!(convert_errors(&config).is_empty());
    }

    #[test]
    fn convert_errors_report_a_missing_target_and_output() {
        let config = partial(
            "rulesets:\n  linux_edge:\n    sources: [rules]\nconvert:\n  groups:\n    linux_edge_pg:\n      ruleset: linux_edge\n",
        );
        let messages: Vec<String> = convert_errors(&config)
            .into_iter()
            .map(|error| error.message)
            .collect();
        assert!(
            messages
                .iter()
                .any(|message| message == "convert group 'linux_edge_pg' has no target")
        );
        assert!(
            messages
                .iter()
                .any(|message| message == "convert group 'linux_edge_pg' has no output")
        );
    }

    #[test]
    fn convert_errors_report_an_unknown_ruleset() {
        let config = partial(
            "convert:\n  groups:\n    g:\n      ruleset: nope\n      target: postgres\n      output: build/g.sql\n",
        );
        let errors = convert_errors(&config);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "convert.groups.g");
        assert_eq!(
            errors[0].message,
            "convert group 'g' names unknown ruleset 'nope'"
        );
    }

    #[test]
    fn convert_errors_report_an_invalid_group_name() {
        let config = partial(
            "rulesets:\n  linux_edge:\n    sources: [rules]\nconvert:\n  groups:\n    Linux:\n      ruleset: linux_edge\n      target: postgres\n      output: build/g.sql\n",
        );
        let errors = convert_errors(&config);
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].message,
            "invalid group name 'Linux': must start with a-z"
        );
    }

    #[test]
    fn convert_errors_require_a_ruleset() {
        let config = partial(
            "convert:\n  groups:\n    g:\n      target: postgres\n      output: build/g.sql\n",
        );
        let errors = convert_errors(&config);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "convert group 'g' has no ruleset");
    }
}
