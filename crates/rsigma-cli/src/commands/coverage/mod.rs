//! `rsigma rule coverage`: map a rule set onto MITRE ATT&CK.
//!
//! The command extracts ATT&CK technique/tactic tags from a rule set, exports
//! an ATT&CK Navigator layer (format 4.5, scored by rule count), and reports
//! coverage gaps against three optional cross-references: the Atomic Red Team
//! index, the SigmaHQ baseline heatmap, and a user-supplied target technique
//! list. `--fail-on-gaps` turns any uncovered cross-reference into a non-zero
//! exit for CI.
//!
//! It works entirely from technique IDs already present on the rules; it does
//! not need the full ATT&CK matrix (the Navigator renders that, and each
//! cross-reference supplies its own technique set).

mod navigator;
mod report;
mod sources;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process;

use clap::parser::ValueSource;
use clap::{ArgMatches, Args};
use rsigma_parser::SigmaCollection;

use crate::commands::reports::CoverageReport;
use crate::config;
use crate::exit_code;
use crate::output::OutputCtx;
// The ATT&CK tag extraction lives in the shared `crate::rule_meta` helper so
// `rule coverage` and `rule hygiene` cannot drift on what "untagged" means.
// Re-exported here so this module's submodules keep referring to them as
// `super::normalize_technique` / `super::parent_technique`.
pub(crate) use crate::rule_meta::{normalize_technique, parent_technique};
use crate::rule_meta::classify_tags;
use sources::{DEFAULT_ATOMICS_URL, DEFAULT_BASELINE_URL};

/// Arguments for `rsigma rule coverage`.
#[derive(Args, Debug)]
pub(crate) struct CoverageArgs {
    /// Path to a YAML config file. Overrides config-file discovery.
    /// CLI flags still take precedence over config-file values.
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Print the effective config (defaults < file < env) and exit.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Path to a Sigma rule file or directory of rules (repeatable).
    #[arg(short = 'r', long = "rules", value_name = "PATH")]
    pub rules: Vec<PathBuf>,

    /// Write an ATT&CK Navigator layer (format 4.5) JSON to this file.
    #[arg(long = "navigator", value_name = "FILE")]
    pub navigator: Option<PathBuf>,

    /// Cross-reference against the Atomic Red Team index. Accepts a local path
    /// (index.yaml or an atomic-red-team `atomics/` directory) or a URL; bare
    /// `--atomics` uses the upstream `atomics/Indexes/index.yaml`.
    #[arg(
        long = "atomics",
        value_name = "PATH_OR_URL",
        num_args = 0..=1,
        default_missing_value = DEFAULT_ATOMICS_URL,
    )]
    pub atomics: Option<String>,

    /// Cross-reference against a baseline ATT&CK Navigator layer. Accepts a
    /// local path or URL; bare `--baseline` uses the SigmaHQ coverage heatmap.
    #[arg(
        long = "baseline",
        value_name = "PATH_OR_URL",
        num_args = 0..=1,
        default_missing_value = DEFAULT_BASELINE_URL,
    )]
    pub baseline: Option<String>,

    /// Cross-reference against a target technique list (one technique ID per
    /// line; `#` comments allowed).
    #[arg(long = "targets", value_name = "FILE")]
    pub targets: Option<PathBuf>,

    /// Exit with code 1 when any requested cross-reference reports uncovered
    /// techniques (for CI gating).
    #[arg(long = "fail-on-gaps")]
    pub fail_on_gaps: bool,
}

/// Overlay the `coverage` config section (defaults < file < env) onto `args`
/// for any flag the operator did not set explicitly, then handle `--dry-run`.
pub(crate) fn apply_coverage_config(args: &mut CoverageArgs, matches: &ArgMatches) {
    let base = config::load_and_merge(args.config.as_deref());
    if args.dry_run {
        config::print_dry_run("coverage", &base);
        process::exit(exit_code::SUCCESS);
    }
    overlay_coverage_config(args, matches, base);
}

/// Pure overlay of the resolved `coverage` section onto `args` (no disk
/// access), split out so it can be unit-tested.
fn overlay_coverage_config(
    args: &mut CoverageArgs,
    matches: &ArgMatches,
    base: config::RsigmaConfigPartial,
) {
    let explicit = |id: &str| {
        matches!(
            matches.value_source(id),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        )
    };

    if let Some(cov) = base.coverage {
        // `--rules` is repeatable with no clap default, so an empty vec means
        // the operator left it off; let the config layer fill it.
        if !explicit("rules")
            && args.rules.is_empty()
            && let Some(v) = cov.rules
        {
            args.rules = v;
        }
        // `--atomics`/`--baseline` have no clap default, so `is_none` means the
        // operator left them off; let the config layer fill them.
        if args.atomics.is_none()
            && let Some(v) = cov.atomics
        {
            args.atomics = Some(v);
        }
        if args.baseline.is_none()
            && let Some(v) = cov.baseline
        {
            args.baseline = Some(v);
        }
        if args.targets.is_none()
            && let Some(v) = cov.targets
        {
            args.targets = Some(v);
        }
        if !explicit("fail_on_gaps")
            && let Some(v) = cov.fail_on_gaps
        {
            args.fail_on_gaps = v;
        }
    }
}

/// Run `rule coverage`. Returns the process exit code (0 success, 1 gaps under
/// `--fail-on-gaps`, 2 rule error, 3 config error). Rule errors exit directly
/// via [`crate::load_collection_multi`].
pub(crate) fn cmd_coverage(args: CoverageArgs, ctx: OutputCtx) -> i32 {
    if args.rules.is_empty() {
        eprintln!("error: no rules path; pass --rules <PATH> (repeatable)");
        return exit_code::CONFIG_ERROR;
    }

    let collection = crate::load_collection_multi(&args.rules);
    let coverage = Coverage::from_collection(&collection);

    let atomics = match &args.atomics {
        Some(spec) => match sources::load_atomics(spec) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("error: {e}");
                return exit_code::CONFIG_ERROR;
            }
        },
        None => None,
    };
    let baseline = match &args.baseline {
        Some(spec) => match sources::load_baseline(spec) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("error: {e}");
                return exit_code::CONFIG_ERROR;
            }
        },
        None => None,
    };
    let targets = match &args.targets {
        Some(path) => match sources::load_targets(path) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("error: {e}");
                return exit_code::CONFIG_ERROR;
            }
        },
        None => None,
    };

    if let Some(path) = &args.navigator {
        let layer = navigator::build_layer(&coverage, "rsigma coverage");
        let json = navigator::to_pretty_json(&layer);
        if let Err(e) = std::fs::write(path, format!("{json}\n")) {
            eprintln!(
                "error: could not write Navigator layer to {}: {e}",
                path.display()
            );
            return exit_code::CONFIG_ERROR;
        }
        if ctx.show_progress() {
            eprintln!("Wrote ATT&CK Navigator layer to {}", path.display());
        }
    }

    let report = CoverageReport::build(&coverage, atomics, baseline, targets);
    report.render(&ctx);
    report.exit_code(args.fail_on_gaps)
}

// ---------------------------------------------------------------------------
// Coverage extraction
// ---------------------------------------------------------------------------

/// Per-technique aggregate: which rules reference it and which tactics those
/// rules tagged.
#[derive(Debug, Default)]
pub(crate) struct TechniqueAgg {
    /// Distinct rules referencing this technique, keyed by rule identity (the
    /// rule `id` when present, else its title) so two rules that happen to
    /// share a title are still counted separately. Maps identity -> display
    /// title.
    rules: BTreeMap<String, String>,
    pub(crate) tactics: BTreeSet<String>,
}

impl TechniqueAgg {
    /// Number of distinct rules referencing this technique.
    pub(crate) fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Sorted, de-duplicated display titles of the referencing rules.
    pub(crate) fn titles(&self) -> Vec<String> {
        let mut titles: Vec<String> = self.rules.values().cloned().collect();
        titles.sort();
        titles.dedup();
        titles
    }
}

/// The ATT&CK coverage computed from a rule set.
#[derive(Debug, Default)]
pub(crate) struct Coverage {
    pub(crate) techniques: BTreeMap<String, TechniqueAgg>,
    pub(crate) tactics: BTreeSet<String>,
    pub(crate) untagged_rules: Vec<String>,
    pub(crate) rules_total: usize,
    pub(crate) rules_tagged: usize,
}

/// Result of testing whether a target technique is covered by the rule set.
pub(crate) struct Covers {
    pub(crate) covered: bool,
    pub(crate) via_subtechnique: bool,
}

impl Coverage {
    /// Build coverage from a parsed collection. Detection and correlation rules
    /// contribute their `attack.*` tags; filter rules are excluded (they
    /// suppress rather than detect).
    pub(crate) fn from_collection(collection: &SigmaCollection) -> Self {
        let mut cov = Coverage::default();
        for rule in &collection.rules {
            cov.ingest(rule.id.as_deref(), &rule.title, &rule.tags);
        }
        for corr in &collection.correlations {
            cov.ingest(corr.id.as_deref(), &corr.title, &corr.tags);
        }
        cov.untagged_rules.sort();
        cov.untagged_rules.dedup();
        cov
    }

    fn ingest(&mut self, id: Option<&str>, title: &str, tags: &[String]) {
        self.rules_total += 1;
        let (techniques, tactics, has_attack) = classify_tags(tags);
        if has_attack {
            self.rules_tagged += 1;
        } else {
            self.untagged_rules.push(title.to_string());
        }
        // Identify a rule by its id when present, else its title, so two
        // distinct rules that share a title are still counted separately.
        let identity = id.unwrap_or(title).to_string();
        for slug in &tactics {
            self.tactics.insert(slug.clone());
        }
        for tech in &techniques {
            let agg = self.techniques.entry(tech.clone()).or_default();
            agg.rules.insert(identity.clone(), title.to_string());
            for slug in &tactics {
                agg.tactics.insert(slug.clone());
            }
        }
    }

    /// Test whether `target` is covered. A base technique is covered directly,
    /// or via any sub-technique rule (`via_subtechnique`). A sub-technique is
    /// covered only by a rule on that exact sub-technique (a coarser parent
    /// rule does not vouch for it).
    pub(crate) fn covers(&self, target: &str) -> Covers {
        let direct = self.techniques.contains_key(target);
        if target.contains('.') {
            return Covers {
                covered: direct,
                via_subtechnique: false,
            };
        }
        let via = !direct
            && self
                .techniques
                .keys()
                .any(|k| parent_technique(k) == Some(target));
        Covers {
            covered: direct || via,
            via_subtechnique: via,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Command, FromArgMatches};

    fn coverage_from(yaml: &str) -> Coverage {
        Coverage::from_collection(&rsigma_parser::parse_sigma_yaml(yaml).expect("parse"))
    }

    #[test]
    fn coverage_dedupes_rule_titles_and_tactics() {
        let cov = coverage_from(
            r#"
title: A
id: 00000000-0000-0000-0000-0000000000a1
logsource: {category: test, product: test}
detection: {sel: {Image: a}, condition: sel}
tags: [attack.execution, attack.t1059]
---
title: B
id: 00000000-0000-0000-0000-0000000000a2
logsource: {category: test, product: test}
detection: {sel: {Image: b}, condition: sel}
tags: [attack.execution, attack.t1059]
"#,
        );
        let agg = cov.techniques.get("T1059").unwrap();
        assert_eq!(agg.rule_count(), 2);
        assert_eq!(
            agg.tactics.iter().cloned().collect::<Vec<_>>(),
            vec!["execution".to_string()]
        );
        assert_eq!(cov.tactics.len(), 1);
    }

    #[test]
    fn distinct_rules_sharing_a_title_count_separately() {
        // Two rules with the same title but different ids both tag T1059.
        // They are distinct rules and must be counted as 2, not collapsed.
        let cov = coverage_from(
            r#"
title: Same Title
id: 00000000-0000-0000-0000-0000000000d1
logsource: {category: test, product: test}
detection: {sel: {Image: a}, condition: sel}
tags: [attack.t1059]
---
title: Same Title
id: 00000000-0000-0000-0000-0000000000d2
logsource: {category: test, product: test}
detection: {sel: {Image: b}, condition: sel}
tags: [attack.t1059]
"#,
        );
        let agg = cov.techniques.get("T1059").unwrap();
        assert_eq!(agg.rule_count(), 2);
        // Display de-duplicates identical titles.
        assert_eq!(agg.titles(), vec!["Same Title".to_string()]);
    }

    #[test]
    fn covers_parent_via_subtechnique_but_not_reverse() {
        let cov = coverage_from(
            r#"
title: Sub
id: 00000000-0000-0000-0000-0000000000a1
logsource: {category: test, product: test}
detection: {sel: {Image: a}, condition: sel}
tags: [attack.t1059.001]
"#,
        );
        // Parent target covered via the sub-technique rule.
        let parent = cov.covers("T1059");
        assert!(parent.covered && parent.via_subtechnique);
        // The exact sub is covered directly.
        assert!(cov.covers("T1059.001").covered);
        // A different sub is not covered by the T1059.001 rule.
        assert!(!cov.covers("T1059.002").covered);
    }

    fn parse(argv: &[&str]) -> (CoverageArgs, ArgMatches) {
        let cmd = CoverageArgs::augment_args(Command::new("coverage"));
        let matches = cmd.get_matches_from(argv);
        let args = CoverageArgs::from_arg_matches(&matches).expect("valid args");
        (args, matches)
    }

    fn partial(yaml: &str) -> config::RsigmaConfigPartial {
        yaml_serde::from_str(yaml).expect("valid partial")
    }

    #[test]
    fn bare_atomics_flag_uses_default_url() {
        let (args, _) = parse(&["coverage", "-r", "/r", "--atomics"]);
        assert_eq!(args.atomics.as_deref(), Some(DEFAULT_ATOMICS_URL));
    }

    #[test]
    fn atomics_flag_with_value_overrides_default() {
        let (args, _) = parse(&["coverage", "-r", "/r", "--atomics=/local/index.yaml"]);
        assert_eq!(args.atomics.as_deref(), Some("/local/index.yaml"));
    }

    #[test]
    fn config_fills_unset_atomics_and_fail_on_gaps() {
        let (mut args, matches) = parse(&["coverage", "-r", "/r"]);
        let base = partial("coverage:\n  atomics: /file/index.yaml\n  fail_on_gaps: true\n");
        overlay_coverage_config(&mut args, &matches, base);
        assert_eq!(args.atomics.as_deref(), Some("/file/index.yaml"));
        assert!(args.fail_on_gaps);
    }

    #[test]
    fn config_fills_unset_rules() {
        // No -r on the command line; the rules come from the config file.
        let (mut args, matches) = parse(&["coverage"]);
        let base = partial("coverage:\n  rules:\n    - /file/rules\n");
        overlay_coverage_config(&mut args, &matches, base);
        assert_eq!(args.rules, vec![PathBuf::from("/file/rules")]);
    }

    #[test]
    fn cli_rules_beat_config() {
        let (mut args, matches) = parse(&["coverage", "-r", "/cli/rules"]);
        let base = partial("coverage:\n  rules:\n    - /file/rules\n");
        overlay_coverage_config(&mut args, &matches, base);
        assert_eq!(args.rules, vec![PathBuf::from("/cli/rules")]);
    }

    #[test]
    fn cli_atomics_beats_config() {
        let (mut args, matches) = parse(&["coverage", "-r", "/r", "--atomics=/cli/index.yaml"]);
        let base = partial("coverage:\n  atomics: /file/index.yaml\n");
        overlay_coverage_config(&mut args, &matches, base);
        assert_eq!(args.atomics.as_deref(), Some("/cli/index.yaml"));
    }
}
