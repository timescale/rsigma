use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::process;
use std::time::SystemTime;

use rsigma_parser::lint::{self, FileLintResult, LintConfig};
use serde::Deserialize;

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_lint(
    path: PathBuf,
    schema: Option<String>,
    verbose: bool,
    color: &str,
    disable: Vec<String>,
    lint_config_path: Option<PathBuf>,
    exclude: Vec<String>,
    apply_fix: bool,
) {
    let p = Painter::new(color);

    // 0. Build lint config from file + CLI flags
    let config = build_lint_config(&path, disable, lint_config_path, exclude);

    // 1. Run built-in lint checks (with suppression)
    let results: Vec<FileLintResult> = if path.is_dir() {
        match lint::lint_yaml_directory_with_config(&path, &config) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        }
    } else {
        match lint::lint_yaml_file_with_config(&path, &config) {
            Ok(r) => vec![r],
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        }
    };

    // 2. Optionally run JSON schema validation
    let schema_results = schema.map(|schema_arg| run_schema_validation(&path, &schema_arg));

    // 3. Merge schema warnings into results
    let mut all_results = results;
    if let Some(sr) = schema_results {
        merge_schema_results(&mut all_results, sr);
    }

    // 4. Render results
    let mut total_files = 0usize;
    let mut failed_files = 0usize;
    let mut total_errors = 0usize;
    let mut total_warnings = 0usize;
    let mut total_infos = 0usize;

    for result in &all_results {
        total_files += 1;
        let errors = result.error_count();
        let warnings = result.warning_count();
        let infos = result.info_count();
        total_errors += errors;
        total_warnings += warnings;
        total_infos += infos;

        let has_failures = result
            .warnings
            .iter()
            .any(|w| matches!(w.severity, lint::Severity::Error | lint::Severity::Warning));

        if result.warnings.is_empty() {
            if verbose {
                println!(
                    "{} {}",
                    p.bold(&result.path.display().to_string()),
                    p.green("OK"),
                );
            }
        } else if has_failures {
            failed_files += 1;
            // File header
            println!("{}", p.bold(&result.path.display().to_string()));
            for w in &result.warnings {
                render_lint_warning(w, &p);
            }
            println!(); // blank line between file blocks
        } else {
            // Only info/hint — show if verbose
            if verbose {
                println!("{}", p.bold(&result.path.display().to_string()));
                for w in &result.warnings {
                    render_lint_warning(w, &p);
                }
                println!();
            }
        }
    }

    // 5. Summary
    let passed = total_files - failed_files;
    let separator = "─".repeat(60);
    println!("{}", p.dim(&separator));

    let passed_str = format!("{passed} passed");
    let failed_str = format!("{failed_files} failed");
    let errors_str = format!("{total_errors} error(s)");
    let warnings_str = format!("{total_warnings} warning(s)");
    let infos_str = format!("{total_infos} info(s)");

    let passed_colored = if passed > 0 {
        p.green_bold(&passed_str)
    } else {
        p.dim(&passed_str)
    };
    let failed_colored = if failed_files > 0 {
        p.red_bold(&failed_str)
    } else {
        p.dim(&failed_str)
    };
    let errors_colored = if total_errors > 0 {
        p.red(&errors_str)
    } else {
        p.dim(&errors_str)
    };
    let warnings_colored = if total_warnings > 0 {
        p.yellow(&warnings_str)
    } else {
        p.dim(&warnings_str)
    };
    let infos_colored = if total_infos > 0 {
        p.blue(&infos_str)
    } else {
        p.dim(&infos_str)
    };

    println!(
        "Checked {} file(s): {}, {} ({}, {}, {})",
        total_files,
        passed_colored,
        failed_colored,
        errors_colored,
        warnings_colored,
        infos_colored,
    );

    // 6. Apply fixes if requested
    if apply_fix {
        let fixable: usize = all_results
            .iter()
            .flat_map(|r| &r.warnings)
            .filter(|w| {
                w.fix
                    .as_ref()
                    .is_some_and(|f| f.disposition == lint::FixDisposition::Safe)
            })
            .count();

        if fixable == 0 {
            println!("{}", p.dim("No auto-fixable issues found."));
        } else {
            let result = crate::fix::apply_fixes(&all_results);
            println!(
                "\n{}",
                p.green_bold(&format!(
                    "Applied {} fix(es) across {} file(s).",
                    result.applied, result.files_modified,
                ))
            );
            if result.failed > 0 {
                println!(
                    "{}",
                    p.yellow(&format!(
                        "{} fix(es) could not be applied (conflicts).",
                        result.failed,
                    ))
                );
            }
        }
    }

    if total_errors > 0 {
        process::exit(1);
    }
}

fn render_lint_warning(w: &lint::LintWarning, p: &Painter) {
    let (severity_label, rule_bracket) = match w.severity {
        lint::Severity::Error => (p.red_bold("error"), p.red(&format!("[{}]", w.rule))),
        lint::Severity::Warning => (p.yellow_bold("warning"), p.yellow(&format!("[{}]", w.rule))),
        lint::Severity::Info => (p.blue("info"), p.blue(&format!("[{}]", w.rule))),
        lint::Severity::Hint => (p.dim("hint"), p.dim(&format!("[{}]", w.rule))),
    };
    println!("  {}{}: {}", severity_label, rule_bracket, w.message);
    let location = if let Some(span) = &w.span {
        format!("{} (line {})", w.path, span.start_line + 1)
    } else {
        w.path.clone()
    };
    println!("    {} {}", p.cyan("-->"), p.cyan(&location));
}

// ---------------------------------------------------------------------------
// JSON Schema validation
// ---------------------------------------------------------------------------

/// Official Sigma detection rule schema URL.
const SCHEMA_URL: &str = "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/json-schema/sigma-detection-rule-schema.json";

/// Cache freshness duration: 7 days in seconds.
const CACHE_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Resolve the schema JSON string from the `--schema` argument.
///
/// - `"default"`: download from GitHub and cache in XDG cache dir.
/// - anything else: treat as a local file path.
fn resolve_schema(schema_arg: &str) -> String {
    if schema_arg == "default" {
        resolve_default_schema()
    } else {
        match std::fs::read_to_string(schema_arg) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error reading schema file '{schema_arg}': {e}");
                process::exit(1);
            }
        }
    }
}

fn resolve_default_schema() -> String {
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("rsigma");
    let cache_path = cache_dir.join("sigma-schema.json");

    // Check if cached copy is fresh
    if let Ok(meta) = std::fs::metadata(&cache_path)
        && let Ok(modified) = meta.modified()
    {
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        if age.as_secs() < CACHE_MAX_AGE_SECS
            && let Ok(content) = std::fs::read_to_string(&cache_path)
        {
            eprintln!("Using cached schema: {}", cache_path.display());
            return content;
        }
    }

    // Download
    eprintln!("Downloading schema from {SCHEMA_URL}...");
    match ureq::get(SCHEMA_URL).call() {
        Ok(response) => {
            let body = response.into_body().read_to_string().unwrap_or_else(|e| {
                eprintln!("Error reading schema response: {e}");
                process::exit(1);
            });

            // Cache it
            if let Err(e) = std::fs::create_dir_all(&cache_dir) {
                eprintln!("Warning: could not create cache dir: {e}");
            } else if let Err(e) = std::fs::write(&cache_path, &body) {
                eprintln!("Warning: could not cache schema: {e}");
            } else {
                eprintln!("Cached schema at {}", cache_path.display());
            }

            body
        }
        Err(e) => {
            // Offline fallback: use stale cache if available
            if let Ok(content) = std::fs::read_to_string(&cache_path) {
                eprintln!("Warning: schema download failed ({e}), using stale cache");
                content
            } else {
                eprintln!("Error downloading schema: {e}");
                process::exit(1);
            }
        }
    }
}

/// Run JSON schema validation on all YAML files at `path`.
fn run_schema_validation(path: &std::path::Path, schema_arg: &str) -> Vec<FileLintResult> {
    let schema_json_str = resolve_schema(schema_arg);
    let schema_value: serde_json::Value = match serde_json::from_str(&schema_json_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing schema JSON: {e}");
            process::exit(1);
        }
    };

    let validator = jsonschema::validator_for(&schema_value).unwrap_or_else(|e| {
        eprintln!("Error compiling JSON schema: {e}");
        process::exit(1);
    });

    let mut results = Vec::new();

    if path.is_dir() {
        fn walk_schema(
            dir: &std::path::Path,
            validator: &jsonschema::Validator,
            results: &mut Vec<FileLintResult>,
        ) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk_schema(&p, validator, results);
                } else if matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")) {
                    results.push(validate_file_against_schema(&p, validator));
                }
            }
        }
        walk_schema(path, &validator, &mut results);
    } else {
        results.push(validate_file_against_schema(path, &validator));
    }

    results
}

fn validate_file_against_schema(
    path: &std::path::Path,
    validator: &jsonschema::Validator,
) -> FileLintResult {
    let mut warnings = Vec::new();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            warnings.push(lint::LintWarning {
                rule: lint::LintRule::FileReadError,
                severity: lint::Severity::Error,
                message: format!("error reading file: {e}"),
                path: "/".to_string(),
                span: None,
                fix: None,
            });
            return FileLintResult {
                path: path.to_path_buf(),
                warnings,
            };
        }
    };

    for doc in serde_yaml::Deserializer::from_str(&content) {
        let yaml_value: serde_yaml::Value = match serde_yaml::Value::deserialize(doc) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Skip action fragments
        if let Some(m) = yaml_value.as_mapping()
            && let Some(action) = m
                .get(serde_yaml::Value::String("action".into()))
                .and_then(|v| v.as_str())
            && matches!(action, "global" | "reset" | "repeat")
        {
            continue;
        }

        // Convert YAML to JSON for schema validation
        let json_str = match serde_json::to_string(&yaml_value) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let json_value: serde_json::Value = match serde_json::from_str(&json_str) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Validate
        for error in validator.iter_errors(&json_value) {
            warnings.push(lint::LintWarning {
                rule: lint::LintRule::SchemaViolation,
                severity: lint::Severity::Error,
                message: format!("schema: {error}"),
                path: error.instance_path().to_string(),
                span: None,
                fix: None,
            });
        }
    }

    FileLintResult {
        path: path.to_path_buf(),
        warnings,
    }
}

/// Merge schema validation results into the main lint results.
///
/// For files already in `main_results`, append schema warnings.
/// For files only in `schema_results`, add them as new entries.
fn merge_schema_results(
    main_results: &mut Vec<FileLintResult>,
    schema_results: Vec<FileLintResult>,
) {
    use std::collections::HashMap;

    let mut index: HashMap<PathBuf, usize> = main_results
        .iter()
        .enumerate()
        .map(|(i, r)| (r.path.clone(), i))
        .collect();

    for sr in schema_results {
        if let Some(&idx) = index.get(&sr.path) {
            main_results[idx].warnings.extend(sr.warnings);
        } else {
            let idx = main_results.len();
            index.insert(sr.path.clone(), idx);
            main_results.push(sr);
        }
    }
}

// ---------------------------------------------------------------------------
// Lint config
// ---------------------------------------------------------------------------

/// Build a `LintConfig` from a config file (auto-discovered or explicit) + CLI `--disable` flags.
fn build_lint_config(
    path: &std::path::Path,
    disable: Vec<String>,
    lint_config_path: Option<PathBuf>,
    exclude: Vec<String>,
) -> LintConfig {
    // Load config file
    let mut config = if let Some(explicit) = lint_config_path {
        match LintConfig::load(&explicit) {
            Ok(c) => {
                eprintln!("Loaded lint config: {}", explicit.display());
                c
            }
            Err(e) => {
                eprintln!("Error loading lint config '{}': {e}", explicit.display());
                process::exit(1);
            }
        }
    } else if let Some(found) = LintConfig::find_in_ancestors(path) {
        match LintConfig::load(&found) {
            Ok(c) => {
                eprintln!("Loaded lint config: {}", found.display());
                c
            }
            Err(e) => {
                eprintln!(
                    "Warning: found .rsigma-lint.yml at {} but failed to load: {e}",
                    found.display()
                );
                LintConfig::default()
            }
        }
    } else {
        LintConfig::default()
    };

    // Merge --disable and --exclude CLI flags
    if !disable.is_empty() || !exclude.is_empty() {
        let cli_config = LintConfig {
            disabled_rules: disable.into_iter().collect(),
            exclude_patterns: exclude,
            ..Default::default()
        };
        config.merge(&cli_config);
    }

    config
}

// ---------------------------------------------------------------------------
// Terminal color support
// ---------------------------------------------------------------------------

/// ANSI color painter that respects `--color`, `NO_COLOR`, and tty detection.
struct Painter {
    enabled: bool,
}

impl Painter {
    fn new(color_arg: &str) -> Self {
        let enabled = match color_arg {
            "always" => true,
            "never" => false,
            _ => io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        };
        Painter { enabled }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }

    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }

    fn red(&self, s: &str) -> String {
        self.paint("31", s)
    }

    fn red_bold(&self, s: &str) -> String {
        self.paint("1;31", s)
    }

    fn green(&self, s: &str) -> String {
        self.paint("32", s)
    }

    fn green_bold(&self, s: &str) -> String {
        self.paint("1;32", s)
    }

    fn yellow(&self, s: &str) -> String {
        self.paint("33", s)
    }

    fn yellow_bold(&self, s: &str) -> String {
        self.paint("1;33", s)
    }

    fn blue(&self, s: &str) -> String {
        self.paint("34", s)
    }

    fn cyan(&self, s: &str) -> String {
        self.paint("36", s)
    }
}
