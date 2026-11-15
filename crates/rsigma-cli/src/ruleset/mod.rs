//! Shared loading and resolution of named rulesets for `rsigma ruleset`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process;

use rsigma_parser::ruleset::{ResolveOptions, ResolvedRuleset, RulesetSpec, resolve_ruleset};

use crate::config;
use crate::exit_code;
use crate::output::OutputCtx;

/// Read the merged `rulesets` section from the configuration layers.
pub(crate) fn load_specs(config: Option<&Path>) -> BTreeMap<String, RulesetSpec> {
    config::load_and_merge(config).rulesets.unwrap_or_default()
}

/// Resolve one named ruleset, exiting with a configuration error when the
/// name is unknown or resolution fails.
pub(crate) fn resolve_named(name: &str, config: Option<&Path>, ctx: &OutputCtx) -> ResolvedRuleset {
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
    resolve_or_exit(name, spec, ctx)
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
