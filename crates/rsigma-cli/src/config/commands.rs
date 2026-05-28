//! The `rsigma config` command group: scaffold, validate, introspect, and
//! locate configuration files.
//!
//! Output contract (agent-friendly): machine-readable answers go to stdout,
//! diagnostics and human messages go to stderr. `validate` supports
//! `--format json` so agents can branch on a structured envelope.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::exit_code;

use super::defaults::{self, defaults_partial};
use super::resolve::{Source, env_partial, resolve_layers, to_value, value_at};
use super::{discover, inactive_sections, load_and_merge, load_layered};

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

    /// Output format: text (default) or json
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

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
    #[arg(long = "for", value_parser = ["global", "daemon", "eval"])]
    pub section: Option<String>,

    /// Output format: text (default), json, or yaml
    #[arg(long, default_value = "text", value_parser = ["text", "json", "yaml"])]
    pub format: String,
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

/// Dispatch a `rsigma config` subcommand.
pub(crate) fn dispatch(cmd: ConfigCommands) {
    match cmd {
        ConfigCommands::Init(args) => cmd_init(args),
        ConfigCommands::Validate(args) => cmd_validate(args),
        ConfigCommands::Show(args) => cmd_show(args),
        ConfigCommands::Schema => cmd_schema(),
        ConfigCommands::Path(args) => cmd_path(args),
        ConfigCommands::Reload(args) => cmd_reload(args),
    }
}

fn cmd_init(args: InitArgs) {
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

fn cmd_validate(args: ValidateArgs) {
    let json = args.format == "json";
    match load_layered(args.config.as_deref()) {
        Ok(loaded) => {
            let inactive = inactive_sections(&loaded.config);
            let unknown_count = loaded.unknown_keys.len();
            let failed = args.strict && unknown_count > 0;

            if json {
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
                    "inactive_sections": inactive,
                });
                println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
            } else {
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
                for section in &inactive {
                    eprintln!(
                        "warning: section '{section}' is set but inert in this build (feature disabled)"
                    );
                }
                if failed {
                    eprintln!("{unknown_count} unknown key(s) found (--strict)");
                } else {
                    eprintln!("Config is valid.");
                }
            }

            if failed {
                process::exit(exit_code::CONFIG_ERROR);
            }
        }
        Err(e) => {
            if json {
                let envelope = serde_json::json!({
                    "ok": false,
                    "error": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
            } else {
                eprintln!("error: {e}");
            }
            process::exit(exit_code::CONFIG_ERROR);
        }
    }
}

fn cmd_show(args: ShowArgs) {
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

    match args.format.as_str() {
        "json" => {
            let sources: BTreeMap<&String, Source> = resolved
                .sources
                .iter()
                .filter(|(path, _)| section_matches(path, filter))
                .map(|(path, source)| (path, *source))
                .collect();
            let envelope = json!({ "config": merged, "sources": sources });
            println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
        }
        "yaml" => {
            println!("{}", yaml_serde::to_string(&merged).unwrap_or_default());
        }
        _ => {
            for (path, source) in &resolved.sources {
                if !section_matches(path, filter) {
                    continue;
                }
                let value = value_at(&resolved.merged, path)
                    .map(render_scalar)
                    .unwrap_or_default();
                println!("{path} = {value}  ({source})");
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

fn cmd_schema() {
    let schema = schemars::schema_for!(super::RsigmaConfigPartial);
    match serde_json::to_string_pretty(&schema) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("could not serialize schema: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    }
}

fn cmd_path(args: PathArgs) {
    let paths = discover(args.config.as_deref());
    if paths.is_empty() {
        println!("none");
    } else {
        for path in paths {
            println!("{}", path.display());
        }
    }
}

fn cmd_reload(args: ReloadArgs) {
    let addr = args.addr.unwrap_or_else(|| {
        let base = load_and_merge(args.config.as_deref());
        base.daemon
            .and_then(|d| d.api)
            .and_then(|a| a.addr)
            .unwrap_or_else(|| defaults::API_ADDR.to_string())
    });
    let url = reload_url(&addr);

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

/// Build the reload endpoint URL from a `host:port` or full URL. Wildcard bind
/// addresses are mapped to loopback so the client can actually connect.
fn reload_url(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        format!("{}/api/v1/reload", addr.trim_end_matches('/'))
    } else {
        let host_port = addr
            .replace("0.0.0.0", "127.0.0.1")
            .replace("[::]", "[::1]");
        format!("http://{host_port}/api/v1/reload")
    }
}

#[cfg(test)]
mod tests {
    use super::reload_url;

    #[test]
    fn reload_url_maps_wildcard_to_loopback() {
        assert_eq!(
            reload_url("0.0.0.0:9090"),
            "http://127.0.0.1:9090/api/v1/reload"
        );
        assert_eq!(
            reload_url("10.0.0.1:9090"),
            "http://10.0.0.1:9090/api/v1/reload"
        );
    }

    #[test]
    fn reload_url_accepts_full_url() {
        assert_eq!(
            reload_url("https://daemon.internal:9443/"),
            "https://daemon.internal:9443/api/v1/reload"
        );
    }
}
