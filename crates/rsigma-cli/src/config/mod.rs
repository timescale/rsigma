//! Layered YAML configuration for rsigma.
//!
//! Configuration is resolved with the precedence (low to high):
//! compiled defaults < `/etc/rsigma` < `~/.config/rsigma` < nearest
//! `.rsigmarc` (walked up from CWD) < `./rsigma.yaml` < environment variables
//! < CLI flags. An explicit `--config <path>` replaces the file-discovery set
//! entirely (only that file is loaded), mirroring `rsigma rule lint --config`.
//!
//! This module owns the file layer: discovery, layered loading, and
//! unknown-key / inactive-section diagnostics. The env and flag layers, plus
//! the mapping from config keys to concrete command settings, live in
//! `resolve` (added alongside the per-command wiring).

pub(crate) mod commands;
pub(crate) mod defaults;
mod resolve;
mod schema;

use std::fmt;
use std::path::{Path, PathBuf};

pub(crate) use schema::{Merge, RsigmaConfigPartial};

/// Load the config files and fold them with the compiled defaults and the
/// `RSIGMA_*` environment layer into one typed partial (precedence:
/// default < file < env). Unknown keys are warned about on stderr. Exits with
/// `CONFIG_ERROR` if a discovered file cannot be read or parsed.
///
/// The CLI-flag layer is applied separately by each command, since only the
/// command knows which of its flags were set explicitly.
pub(crate) fn load_and_merge(explicit: Option<&Path>) -> RsigmaConfigPartial {
    match load_layered(explicit) {
        Ok(loaded) => {
            for (path, key) in &loaded.unknown_keys {
                eprintln!("warning: unknown config key '{key}' in {}", path.display());
            }
            for section in inactive_sections(&loaded.config) {
                eprintln!(
                    "warning: config section '{section}' is set but inert in this build (feature disabled)"
                );
            }
            defaults::defaults_partial()
                .merge(loaded.config)
                .merge(resolve::env_partial())
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }
}

/// Best-effort lookup of `global.log_format` from the config files (honoring an
/// explicit `--config` path when present) and the `RSIGMA_*` env (no compiled
/// default, so this is `None` unless an operator set it). Used by `main` to
/// pick the CLI log format before any command runs. Quiet: unlike
/// `load_and_merge`, it never warns or exits.
pub(crate) fn discovered_log_format(explicit: Option<&Path>) -> Option<String> {
    let loaded = load_layered(explicit).ok()?;
    let merged = loaded.config.merge(resolve::env_partial());
    merged.global.and_then(|g| g.log_format)
}

/// Print the effective `section` config (defaults < file < env) as YAML to
/// stdout, used by `--dry-run`. CLI flags override these at runtime; that note
/// goes to stderr so the YAML on stdout stays clean.
pub(crate) fn print_dry_run(section: &str, base: &RsigmaConfigPartial) {
    let value = resolve::to_value(base);
    let filtered = value
        .get(section)
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    eprintln!(
        "# effective {section} config (defaults < file < env); CLI flags override these at runtime"
    );
    println!("{}", yaml_serde::to_string(&filtered).unwrap_or_default());
}

/// Errors surfaced while loading a config file.
#[derive(Debug)]
pub(crate) enum ConfigError {
    /// The file could not be read from disk.
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The file did not parse as a valid rsigma config document.
    Parse { path: PathBuf, message: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read { path, source } => {
                write!(f, "could not read config {}: {source}", path.display())
            }
            ConfigError::Parse { path, message } => {
                write!(f, "could not parse config {}: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// The result of loading and merging every config layer that was found.
#[derive(Debug, Default)]
pub(crate) struct LoadedConfig {
    /// The merged configuration across all loaded files.
    pub config: RsigmaConfigPartial,
    /// The files that were loaded, in increasing precedence order.
    pub sources: Vec<PathBuf>,
    /// Unknown keys encountered while parsing, paired with their file.
    pub unknown_keys: Vec<(PathBuf, String)>,
}

/// Return the user config directory (`$XDG_CONFIG_HOME/rsigma` or
/// `~/.config/rsigma`), following the XDG spec explicitly rather than
/// `dirs::config_dir()` (which is `~/Library/Application Support` on macOS).
fn user_config_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(xdg);
        if !p.as_os_str().is_empty() {
            return Some(p.join("rsigma"));
        }
    }
    dirs::home_dir().map(|h| h.join(".config").join("rsigma"))
}

/// Find the first existing `<stem>.yaml` / `<stem>.yml` in `dir`.
fn first_existing(dir: &Path, stem: &str) -> Option<PathBuf> {
    for ext in ["yaml", "yml"] {
        let candidate = dir.join(format!("{stem}.{ext}"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Walk up from the current directory looking for a project `.rsigmarc`.
fn find_rsigmarc() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        let candidate = current.join(".rsigmarc");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Resolve the ordered list of config files to load, lowest precedence first.
///
/// When `explicit` is set, only that path is returned (it is loaded
/// unconditionally so a bad `--config` surfaces a clear error).
pub(crate) fn discover(explicit: Option<&Path>) -> Vec<PathBuf> {
    if let Some(path) = explicit {
        return vec![path.to_path_buf()];
    }

    let mut paths = Vec::new();
    if let Some(p) = first_existing(Path::new("/etc/rsigma"), "config") {
        paths.push(p);
    }
    if let Some(dir) = user_config_dir()
        && let Some(p) = first_existing(&dir, "config")
    {
        paths.push(p);
    }
    if let Some(p) = find_rsigmarc() {
        paths.push(p);
    }
    if let Some(p) = first_existing(Path::new("."), "rsigma") {
        paths.push(p);
    }
    paths
}

/// Parse a single config file into a partial plus the unknown keys it carried.
fn load_file(path: &Path) -> Result<(RsigmaConfigPartial, Vec<String>), ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    let mut unknown = Vec::new();
    let mut docs = yaml_serde::Deserializer::from_str(&content);
    let Some(doc) = docs.next() else {
        // Empty file (or comments only): nothing to merge.
        return Ok((RsigmaConfigPartial::default(), unknown));
    };

    let partial: RsigmaConfigPartial =
        serde_ignored::deserialize(doc, |path| unknown.push(path.to_string())).map_err(|e| {
            let raw = e.to_string();
            // A top-level scalar/sequence/null produces serde's terse
            // "invalid type: …, expected struct RsigmaConfigPartial". Rewrite it
            // into something an operator can act on.
            let message = if raw.contains("expected struct RsigmaConfigPartial") {
                format!(
                    "top-level config must be a YAML mapping of sections \
                 (global, daemon, eval); got {raw}"
                )
            } else {
                raw
            };
            ConfigError::Parse {
                path: path.to_path_buf(),
                message,
            }
        })?;

    Ok((partial, unknown))
}

/// Discover and merge every config layer (or the single `--config` file).
pub(crate) fn load_layered(explicit: Option<&Path>) -> Result<LoadedConfig, ConfigError> {
    let mut loaded = LoadedConfig::default();
    for path in discover(explicit) {
        let (partial, unknown) = load_file(&path)?;
        for key in unknown {
            loaded.unknown_keys.push((path.clone(), key));
        }
        loaded.config = std::mem::take(&mut loaded.config).merge(partial);
        loaded.sources.push(path);
    }
    Ok(loaded)
}

/// Return config sections that are present but inert in this build because the
/// gating Cargo feature is disabled. Used by `config validate` to warn rather
/// than silently ignore.
#[allow(unused_mut, unused_variables)]
pub(crate) fn inactive_sections(config: &RsigmaConfigPartial) -> Vec<&'static str> {
    let mut inactive: Vec<&'static str> = Vec::new();

    #[cfg(not(feature = "daemon"))]
    if config.daemon.is_some() {
        inactive.push("daemon");
    }

    #[cfg(not(feature = "daemon-nats"))]
    if config
        .daemon
        .as_ref()
        .and_then(|d| d.nats.as_ref())
        .is_some()
    {
        inactive.push("daemon.nats");
    }

    #[cfg(not(feature = "daemon-tls"))]
    if config
        .daemon
        .as_ref()
        .and_then(|d| d.api.as_ref())
        .and_then(|a| a.tls.as_ref())
        .is_some()
    {
        inactive.push("daemon.api.tls");
    }

    inactive
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn explicit_path_replaces_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.yaml");
        std::fs::write(&path, "version: 1\n").unwrap();
        let discovered = discover(Some(&path));
        assert_eq!(discovered, vec![path]);
    }

    #[test]
    fn load_collects_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rsigma.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "version: 1\nbogus_key: true\ndaemon:\n  rules: /x\n  nope: 1"
        )
        .unwrap();

        let (partial, unknown) = load_file(&path).unwrap();
        assert_eq!(partial.version, Some(1));
        assert!(unknown.iter().any(|k| k == "bogus_key"));
        assert!(unknown.iter().any(|k| k.contains("nope")));
    }

    #[test]
    fn empty_file_yields_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rsigma.yaml");
        std::fs::write(&path, "").unwrap();
        let (partial, unknown) = load_file(&path).unwrap();
        assert!(partial.version.is_none());
        assert!(unknown.is_empty());
    }
}
