//! Shared loading and resolution of named rulesets for `rsigma ruleset`.

pub(crate) mod build;
pub(crate) mod lock;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process;

use rsigma_parser::SigmaCollection;
use rsigma_parser::ruleset::{ResolveOptions, ResolvedRuleset, RulesetSpec, resolve_ruleset};

use crate::config;
use crate::exit_code;
use crate::output::OutputCtx;

/// Read the merged `rulesets` section from the configuration layers.
pub(crate) fn load_specs(config: Option<&Path>) -> BTreeMap<String, RulesetSpec> {
    config::load_and_merge(config).rulesets.unwrap_or_default()
}

/// Look up one named ruleset, exiting with a configuration error when the
/// name is unknown.
pub(crate) fn load_named(name: &str, config: Option<&Path>) -> (String, RulesetSpec) {
    let specs = load_specs(config);
    let Some(spec) = specs.get(name) else {
        let defined: Vec<&str> = specs.keys().map(String::as_str).collect();
        if defined.is_empty() {
            let files = config::discover(config);
            if files.is_empty() {
                eprintln!(
                    "error: unknown ruleset '{name}': no rulesets are defined and no config files were found"
                );
            } else {
                eprintln!(
                    "error: unknown ruleset '{name}': no rulesets are defined; config files read: {}",
                    files
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        } else {
            eprintln!(
                "error: unknown ruleset '{name}'; defined rulesets: {}",
                defined.join(", ")
            );
        }
        process::exit(exit_code::CONFIG_ERROR);
    };
    (name.to_string(), spec.clone())
}

/// Resolve one named ruleset, exiting with a configuration error when the
/// name is unknown or resolution fails.
pub(crate) fn resolve_named(name: &str, config: Option<&Path>, ctx: &OutputCtx) -> ResolvedRuleset {
    let (name, spec) = load_named(name, config);
    resolve_or_exit(&name, &spec, ctx)
}

/// Resolve a spec and exit 3 on failure, printing diagnostics and warnings.
pub(crate) fn resolve_or_exit(name: &str, spec: &RulesetSpec, ctx: &OutputCtx) -> ResolvedRuleset {
    match resolve_ruleset(name, spec, &ResolveOptions::default()) {
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
            if message.starts_with(&format!("ruleset '{name}'")) {
                eprintln!("error: {message}");
            } else {
                eprintln!("error: ruleset '{name}': {message}");
            }
            process::exit(exit_code::CONFIG_ERROR);
        }
    }
}

/// The pipeline paths a ruleset declares, in declaration order.
pub(crate) fn ruleset_pipelines(spec: &RulesetSpec) -> Vec<PathBuf> {
    spec.pipelines.iter().map(PathBuf::from).collect()
}

/// How a command selects the rules it operates on: explicit paths, or one
/// named ruleset from the configuration.
pub(crate) struct RuleInput<'a> {
    pub rules: &'a [PathBuf],
    pub ruleset: Option<&'a str>,
    pub config: Option<&'a Path>,
}

impl RuleInput<'_> {
    /// Load the selected rules. A ruleset resolves through the configuration
    /// and exits 3 on unknown names or resolution errors.
    pub(crate) fn collection(&self, ctx: &OutputCtx) -> SigmaCollection {
        match self.resolved(ctx) {
            Some(resolved) => resolved.collection,
            None => crate::load_collection_multi(self.rules),
        }
    }

    /// Like [`collection`](Self::collection), but a single explicit path loads
    /// through [`crate::load_collection`], which accepts a path holding no
    /// detection rules. For the commands whose `--rules` takes one path.
    pub(crate) fn single_path_collection(&self, ctx: &OutputCtx) -> SigmaCollection {
        match (self.resolved(ctx), self.rules) {
            (Some(resolved), _) => resolved.collection,
            (None, [path]) => crate::load_collection(path),
            (None, paths) => crate::load_collection_multi(paths),
        }
    }

    /// Resolve the selected ruleset, when one is selected.
    pub(crate) fn resolved(&self, ctx: &OutputCtx) -> Option<ResolvedRuleset> {
        self.ruleset
            .map(|name| resolve_named(name, self.config, ctx))
    }

    /// Apply the pipeline precedence for commands with `-p`: explicit flags
    /// win, then a selected ruleset's pipelines. Commands with a config
    /// pipeline key apply the config fallback themselves.
    pub(crate) fn pipelines(&self, explicit: &[PathBuf]) -> Vec<PathBuf> {
        if !explicit.is_empty() {
            return explicit.to_vec();
        }
        let Some(name) = self.ruleset else {
            return Vec::new();
        };
        let (_, spec) = load_named(name, self.config);
        ruleset_pipelines(&spec)
    }

    /// A human label for reports: the ruleset name, or the joined paths.
    pub(crate) fn label(&self) -> String {
        match self.ruleset {
            Some(name) => format!("ruleset {name}"),
            None => self
                .rules
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        }
    }
}
