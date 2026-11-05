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
            for (path, key) in &loaded.ignored_keys {
                eprintln!("{}", ignored_key_warning(path, key));
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

/// Resolve the daemon admin address for client commands (`config reload`,
/// `engine status`, ...). Precedence: an explicit `--addr` wins, otherwise
/// `daemon.api.addr` from the layered config, otherwise the compiled default.
pub(crate) fn resolve_daemon_addr(addr: Option<String>, explicit: Option<&Path>) -> String {
    addr.unwrap_or_else(|| {
        load_and_merge(explicit)
            .daemon
            .and_then(|d| d.api)
            .and_then(|a| a.addr)
            .unwrap_or_else(|| defaults::API_ADDR.to_string())
    })
}

/// Build an admin endpoint URL from a `host:port` or full URL, appending
/// `path` (which must start with `/`). Wildcard bind addresses are mapped to
/// loopback so the client can connect to a daemon that advertised `0.0.0.0`
/// or `[::]`.
pub(crate) fn api_url(addr: &str, path: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        format!("{}{path}", addr.trim_end_matches('/'))
    } else {
        let host_port = addr
            .replace("0.0.0.0", "127.0.0.1")
            .replace("[::]", "[::1]");
        format!("http://{host_port}{path}")
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

/// Best-effort lookup of `global.output_format` and `global.color` from the
/// config file and `RSIGMA_*` environment layers. Returns each layer
/// separately so invalid environment values can be rejected before precedence
/// resolution without discarding a valid file value. Quiet: like
/// [`discovered_log_format`], it never warns or exits.
pub(crate) fn discovered_global_output(
    explicit: Option<&Path>,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let Some(loaded) = load_layered(explicit).ok() else {
        return (None, None, None, None);
    };
    let file_global = loaded.config.global.unwrap_or_default();
    let env_global = resolve::env_partial().global.unwrap_or_default();
    (
        file_global.output_format,
        file_global.color,
        env_global.output_format,
        env_global.color,
    )
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
    /// [`PROTECTED_KEYS`] a project file set, paired with that file. They are
    /// not part of [`Self::config`].
    pub ignored_keys: Vec<(PathBuf, &'static str)>,
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

/// The discovery layer a config file was loaded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    /// `/etc/rsigma/config.yaml`.
    System,
    /// `~/.config/rsigma/config.yaml` (or under `$XDG_CONFIG_HOME`).
    User,
    /// The nearest `.rsigmarc`, walked up from the current directory.
    ProjectRc,
    /// `./rsigma.yaml` in the current directory.
    ProjectYaml,
    /// The file named by `--config`, which replaces discovery.
    Explicit,
}

impl Layer {
    /// Whether the file came from the working tree rather than from the
    /// operator. Project files ship with whatever repository is checked out,
    /// so they may not set [`PROTECTED_KEYS`].
    fn is_project(self) -> bool {
        matches!(self, Layer::ProjectRc | Layer::ProjectYaml)
    }
}

/// Resolve the ordered list of config files to load, lowest precedence first.
///
/// When `explicit` is set, only that path is returned (it is loaded
/// unconditionally so a bad `--config` surfaces a clear error).
pub(crate) fn discover(explicit: Option<&Path>) -> Vec<PathBuf> {
    discover_layers(explicit)
        .into_iter()
        .map(|(path, _)| path)
        .collect()
}

/// Like [`discover`], but pairs each path with the layer it came from.
fn discover_layers(explicit: Option<&Path>) -> Vec<(PathBuf, Layer)> {
    if let Some(path) = explicit {
        return vec![(path.to_path_buf(), Layer::Explicit)];
    }

    let mut paths = Vec::new();
    if let Some(p) = first_existing(Path::new("/etc/rsigma"), "config") {
        paths.push((p, Layer::System));
    }
    if let Some(dir) = user_config_dir()
        && let Some(p) = first_existing(&dir, "config")
    {
        paths.push((p, Layer::User));
    }
    if let Some(p) = find_rsigmarc() {
        paths.push((p, Layer::ProjectRc));
    }
    if let Some(p) = first_existing(Path::new("."), "rsigma") {
        paths.push((p, Layer::ProjectYaml));
    }
    paths
}

/// A security-sensitive config key that project files (`.rsigmarc`,
/// `./rsigma.yaml`) may not set.
///
/// Each of these opens a gate (a listener, a write path, a subprocess, a
/// network client) or weakens a guard that a repository could otherwise
/// change just by being the current directory. They are honored from
/// `--config`, the user and system config files, `RSIGMA_*` environment
/// variables, and flags.
pub(crate) struct ProtectedKey {
    /// Dotted config path, as printed in warnings and docs.
    pub key: &'static str,
    /// Clear the key from a project file's partial. `project_dir` is the
    /// directory holding that file. Returns whether a value was removed.
    strip: fn(&mut RsigmaConfigPartial, project_dir: &Path) -> bool,
}

fn mcp(config: &mut RsigmaConfigPartial) -> Option<&mut schema::McpPartial> {
    config.mcp.as_mut()
}

fn daemon(config: &mut RsigmaConfigPartial) -> Option<&mut schema::DaemonPartial> {
    config.daemon.as_mut()
}

fn api(config: &mut RsigmaConfigPartial) -> Option<&mut schema::ApiPartial> {
    daemon(config)?.api.as_mut()
}

fn output(config: &mut RsigmaConfigPartial) -> Option<&mut schema::OutputPartial> {
    daemon(config)?.output.as_mut()
}

fn engine(config: &mut RsigmaConfigPartial) -> Option<&mut schema::EnginePartial> {
    daemon(config)?.engine.as_mut()
}

/// Clear `slot` and return whether it held a value.
fn take<T>(slot: Option<&mut Option<T>>) -> bool {
    slot.is_some_and(|value| value.take().is_some())
}

/// Clear an opt-in flag only when it is `true`: a project file may still
/// turn the gate off.
fn take_true(slot: Option<&mut Option<bool>>) -> bool {
    slot.is_some_and(|value| value.take_if(|on| *on).is_some())
}

/// Every key project files may not set. `scripts/docs-audit/check_sources.py`
/// checks that the configuration and security references list each one.
pub(crate) const PROTECTED_KEYS: &[ProtectedKey] = &[
    ProtectedKey {
        key: "mcp.http_addr",
        strip: |c, _| take(mcp(c).map(|m| &mut m.http_addr)),
    },
    ProtectedKey {
        key: "mcp.allow_unconfined_paths",
        strip: |c, _| take_true(mcp(c).map(|m| &mut m.allow_unconfined_paths)),
    },
    ProtectedKey {
        key: "mcp.allow_sigma_cli",
        strip: |c, _| take_true(mcp(c).map(|m| &mut m.allow_sigma_cli)),
    },
    ProtectedKey {
        key: "mcp.daemon_url",
        strip: |c, _| take(mcp(c).map(|m| &mut m.daemon_url)),
    },
    ProtectedKey {
        key: "mcp.daemon_ca",
        strip: |c, _| take(mcp(c).map(|m| &mut m.daemon_ca)),
    },
    ProtectedKey {
        key: "mcp.allow_operate_writes",
        strip: |c, _| take_true(mcp(c).map(|m| &mut m.allow_operate_writes)),
    },
    // A project may point these at its own tree, but not at paths outside
    // the project.
    ProtectedKey {
        key: "mcp.rules_dir",
        strip: |c, project_dir| mcp(c).is_some_and(|m| take_outside(&mut m.rules_dir, project_dir)),
    },
    ProtectedKey {
        key: "mcp.lint_config",
        strip: |c, project_dir| {
            mcp(c).is_some_and(|m| take_outside(&mut m.lint_config, project_dir))
        },
    },
    // Files that can declare `command` and HTTP sources or enrichers.
    ProtectedKey {
        key: "daemon.sources",
        strip: |c, _| take(daemon(c).map(|d| &mut d.sources)),
    },
    ProtectedKey {
        key: "daemon.enrichers",
        strip: |c, _| take(daemon(c).map(|d| &mut d.enrichers)),
    },
    ProtectedKey {
        key: "daemon.dispositions.source",
        strip: |c, _| {
            take(
                daemon(c)
                    .and_then(|d| d.dispositions.as_mut())
                    .map(|d| &mut d.source),
            )
        },
    },
    // Destinations that receive detections, failed events, or audit lines.
    ProtectedKey {
        key: "daemon.output.sinks",
        strip: |c, _| take(output(c).map(|o| &mut o.sinks)),
    },
    ProtectedKey {
        key: "daemon.output.dlq",
        strip: |c, _| take(output(c).map(|o| &mut o.dlq)),
    },
    ProtectedKey {
        key: "daemon.output.webhooks",
        strip: |c, _| take(output(c).map(|o| &mut o.webhooks)),
    },
    // A NATS input connects with the operator's NATS credentials, and
    // binding a unix:// path replaces whatever stale socket sits there.
    ProtectedKey {
        key: "daemon.input.source",
        strip: |c, project_dir| {
            daemon(c)
                .and_then(|d| d.input.as_mut())
                .is_some_and(|input| {
                    if input.source.as_deref().is_some_and(|s| {
                        s.starts_with("nats://") || unix_path_outside(s, project_dir)
                    }) {
                        input.source = None;
                        true
                    } else {
                        false
                    }
                })
        },
    },
    // A durable consumer name could join another deployment's consumer and
    // pull its messages.
    ProtectedKey {
        key: "daemon.nats.consumer_group",
        strip: |c, _| {
            take(
                daemon(c)
                    .and_then(|d| d.nats.as_mut())
                    .map(|n| &mut n.consumer_group),
            )
        },
    },
    // Client commands send the API token to this address, and the server
    // binds it.
    ProtectedKey {
        key: "daemon.api.addr",
        strip: |c, project_dir| {
            api(c).is_some_and(|a| {
                if a.addr
                    .as_deref()
                    .is_some_and(|addr| !is_local_api_addr(addr, project_dir))
                {
                    a.addr = None;
                    true
                } else {
                    false
                }
            })
        },
    },
    // API listener guards.
    ProtectedKey {
        key: "daemon.api.auth",
        strip: |c, _| take(api(c).map(|a| &mut a.auth)),
    },
    ProtectedKey {
        key: "daemon.api.allow_unauthenticated",
        strip: |c, _| take_true(api(c).map(|a| &mut a.allow_unauthenticated)),
    },
    ProtectedKey {
        key: "daemon.api.tls.allow_plaintext",
        strip: |c, _| {
            take_true(
                api(c)
                    .and_then(|a| a.tls.as_mut())
                    .map(|t| &mut t.allow_plaintext),
            )
        },
    },
    ProtectedKey {
        key: "daemon.api.tls.client_ca",
        strip: |c, _| {
            take(
                api(c)
                    .and_then(|a| a.tls.as_mut())
                    .map(|t| &mut t.client_ca),
            )
        },
    },
    ProtectedKey {
        key: "daemon.api.audit",
        strip: |c, _| take(api(c).map(|a| &mut a.audit)),
    },
    // Opt-in endpoints and stores that expose raw events or detections.
    ProtectedKey {
        key: "daemon.tap.enabled",
        strip: |c, _| {
            take_true(
                daemon(c)
                    .and_then(|d| d.tap.as_mut())
                    .map(|t| &mut t.enabled),
            )
        },
    },
    ProtectedKey {
        key: "daemon.tail.enabled",
        strip: |c, _| {
            take_true(
                daemon(c)
                    .and_then(|d| d.tail.as_mut())
                    .map(|t| &mut t.enabled),
            )
        },
    },
    ProtectedKey {
        key: "daemon.capture.enabled",
        strip: |c, _| {
            take_true(
                daemon(c)
                    .and_then(|d| d.capture.as_mut())
                    .map(|t| &mut t.enabled),
            )
        },
    },
    ProtectedKey {
        key: "daemon.capture.spool_dir",
        strip: |c, _| {
            take(
                daemon(c)
                    .and_then(|d| d.capture.as_mut())
                    .map(|t| &mut t.spool_dir),
            )
        },
    },
    // Egress and remote-include guards for HTTP clients and pipelines.
    ProtectedKey {
        key: "daemon.engine.egress_policy",
        strip: |c, _| take(engine(c).map(|e| &mut e.egress_policy)),
    },
    ProtectedKey {
        key: "daemon.engine.allow_remote_include",
        strip: |c, _| take_true(engine(c).map(|e| &mut e.allow_remote_include)),
    },
    // Files the CLI creates or truncates.
    ProtectedKey {
        key: "daemon.state.db",
        strip: |c, project_dir| {
            daemon(c)
                .and_then(|d| d.state.as_mut())
                .is_some_and(|s| take_outside(&mut s.db, project_dir))
        },
    },
    ProtectedKey {
        key: "eval.output",
        strip: |c, project_dir| {
            c.eval
                .as_mut()
                .is_some_and(|e| take_outside(&mut e.output, project_dir))
        },
    },
    ProtectedKey {
        key: "scorecard.report",
        strip: |c, project_dir| {
            c.scorecard
                .as_mut()
                .is_some_and(|s| take_outside(&mut s.report, project_dir))
        },
    },
];

/// Whether `spec` is a `unix://` address whose path lies outside
/// `project_dir`.
fn unix_path_outside(spec: &str, project_dir: &Path) -> bool {
    spec.strip_prefix("unix://")
        .is_some_and(|path| !path_within(Path::new(path), project_dir))
}

/// Whether a project file may set `addr` as the API address: a loopback
/// `host:port`, or a `unix://` path inside `project_dir`.
fn is_local_api_addr(addr: &str, project_dir: &Path) -> bool {
    if let Some(path) = addr.strip_prefix("unix://") {
        return path_within(Path::new(path), project_dir);
    }
    if let Ok(socket) = addr.parse::<std::net::SocketAddr>() {
        return socket.ip().is_loopback();
    }
    addr.rsplit_once(':').is_some_and(|(host, port)| {
        host.eq_ignore_ascii_case("localhost") && port.parse::<u16>().is_ok()
    })
}

/// Clear `path` when it lies outside `project_dir`. Returns whether it did.
fn take_outside(path: &mut Option<PathBuf>, project_dir: &Path) -> bool {
    if path
        .as_deref()
        .is_some_and(|p| !path_within(p, project_dir))
    {
        *path = None;
        true
    } else {
        false
    }
}

/// Remove every [`PROTECTED_KEYS`] entry from a project file's partial and
/// return the keys that were set.
fn strip_untrusted(config: &mut RsigmaConfigPartial, project_dir: &Path) -> Vec<&'static str> {
    PROTECTED_KEYS
        .iter()
        .filter(|protected| (protected.strip)(config, project_dir))
        .map(|protected| protected.key)
        .collect()
}

/// Whether `path` (relative paths resolve against the current directory, as
/// the commands that read them do) lies inside `dir`. Symlinks are resolved
/// in the longest prefix that exists, and the rest is normalized lexically,
/// so a path that does not exist yet cannot escape through a symlinked parent.
fn path_within(path: &Path, dir: &Path) -> bool {
    let cwd = std::env::current_dir().unwrap_or_default();
    let absolute = |p: &Path| {
        if p.is_absolute() {
            resolve_existing_prefix(p)
        } else {
            resolve_existing_prefix(&cwd.join(p))
        }
    };
    absolute(path).starts_with(absolute(dir))
}

/// Canonicalize the longest prefix of `path` that exists and append the
/// remaining components, folding `.` and `..`.
fn resolve_existing_prefix(path: &Path) -> PathBuf {
    let mut prefix = path.to_path_buf();
    let mut rest = Vec::new();
    loop {
        if let Ok(real) = prefix.canonicalize() {
            let mut out = real;
            out.extend(rest.iter().rev());
            return normalize_lexically(&out);
        }
        let Some(last) = prefix.components().next_back() else {
            return normalize_lexically(path);
        };
        rest.push(last.as_os_str().to_os_string());
        if !prefix.pop() {
            return normalize_lexically(path);
        }
    }
}

/// Drop `.` components and fold `..` into its parent without touching the
/// filesystem.
fn normalize_lexically(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
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
                 (global, daemon, eval, backtest, coverage, scorecard, visibility, doc, hygiene, mcp); got {raw}"
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
/// [`PROTECTED_KEYS`] set by a project file are dropped and recorded in
/// [`LoadedConfig::ignored_keys`].
pub(crate) fn load_layered(explicit: Option<&Path>) -> Result<LoadedConfig, ConfigError> {
    load_files(discover_layers(explicit))
}

/// Load and merge `files` in order, lowest precedence first.
fn load_files(files: Vec<(PathBuf, Layer)>) -> Result<LoadedConfig, ConfigError> {
    let mut loaded = LoadedConfig::default();
    for (path, layer) in files {
        let (mut partial, unknown) = load_file(&path)?;
        for key in unknown {
            loaded.unknown_keys.push((path.clone(), key));
        }
        if layer.is_project() {
            let project_dir = path.parent().unwrap_or(Path::new("."));
            for key in strip_untrusted(&mut partial, project_dir) {
                loaded.ignored_keys.push((path.clone(), key));
            }
        }
        loaded.config = std::mem::take(&mut loaded.config).merge(partial);
        loaded.sources.push(path);
    }
    Ok(loaded)
}

/// The warning printed for a protected key found in a project file.
pub(crate) fn ignored_key_warning(path: &Path, key: &str) -> String {
    format!(
        "warning: ignoring '{key}' from project config {}; security-sensitive keys are read only from --config, the user or system config, environment variables, or flags",
        path.display()
    )
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
        .is_some_and(|t| {
            t.cert.is_some() || t.key.is_some() || t.client_ca.is_some() || t.min_version.is_some()
        })
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

    const MCP_GATES: &str = "mcp:\n  http_addr: 0.0.0.0:9100\n  allow_unconfined_paths: true\n  allow_sigma_cli: true\n  daemon_url: http://127.0.0.1:9090\n  daemon_ca: /tmp/ca.pem\n  allow_operate_writes: true\n  lint_config: /etc/rsigma-lint.yml\n";

    fn write_config(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn project_layers_drop_protected_mcp_keys() {
        let dir = tempfile::tempdir().unwrap();
        for (name, layer) in [
            (".rsigmarc", Layer::ProjectRc),
            ("rsigma.yaml", Layer::ProjectYaml),
        ] {
            let path = write_config(dir.path(), name, MCP_GATES);
            let loaded = load_files(vec![(path.clone(), layer)]).unwrap();
            let mcp = loaded.config.mcp.unwrap();
            assert!(mcp.http_addr.is_none());
            assert!(mcp.allow_unconfined_paths.is_none());
            assert!(mcp.allow_sigma_cli.is_none());
            assert!(mcp.daemon_url.is_none());
            assert!(mcp.daemon_ca.is_none());
            assert!(mcp.allow_operate_writes.is_none());
            assert!(mcp.lint_config.is_none());
            let keys: Vec<&str> = loaded.ignored_keys.iter().map(|(_, k)| *k).collect();
            assert_eq!(
                keys,
                [
                    "mcp.http_addr",
                    "mcp.allow_unconfined_paths",
                    "mcp.allow_sigma_cli",
                    "mcp.daemon_url",
                    "mcp.daemon_ca",
                    "mcp.allow_operate_writes",
                    "mcp.lint_config",
                ]
            );
            assert!(loaded.ignored_keys.iter().all(|(p, _)| *p == path));
        }
    }

    #[test]
    fn operator_layers_keep_protected_mcp_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "config.yaml", MCP_GATES);
        for layer in [Layer::System, Layer::User, Layer::Explicit] {
            let loaded = load_files(vec![(path.clone(), layer)]).unwrap();
            let mcp = loaded.config.mcp.unwrap();
            assert_eq!(mcp.daemon_url.as_deref(), Some("http://127.0.0.1:9090"));
            assert_eq!(mcp.allow_operate_writes, Some(true));
            assert!(loaded.ignored_keys.is_empty(), "{layer:?}");
        }
    }

    #[test]
    fn project_value_does_not_shadow_user_value() {
        let dir = tempfile::tempdir().unwrap();
        let user = write_config(
            dir.path(),
            "config.yaml",
            "mcp:\n  daemon_url: http://user:9090\n",
        );
        let project = write_config(
            dir.path(),
            "rsigma.yaml",
            "mcp:\n  daemon_url: http://evil:9090\n",
        );
        let loaded = load_files(vec![(user, Layer::User), (project, Layer::ProjectYaml)]).unwrap();
        assert_eq!(
            loaded.config.mcp.unwrap().daemon_url.as_deref(),
            Some("http://user:9090")
        );
    }

    #[test]
    fn project_paths_must_stay_inside_the_project() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("rules")).unwrap();
        let inside = dir.path().join("rules");
        let outside = tempfile::tempdir().unwrap();
        let escape = dir.path().join("rules/../../elsewhere");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let through_link = dir.path().join("link");
        let missing_through_link = dir.path().join("link/missing/../../escaped");
        let missing_inside = dir.path().join("rules/new");
        let mut cases = vec![
            (inside.as_path(), true),
            (outside.path(), false),
            (escape.as_path(), false),
            (missing_inside.as_path(), true),
        ];
        if cfg!(unix) {
            cases.push((through_link.as_path(), false));
            cases.push((missing_through_link.as_path(), false));
        }
        for (key, field) in [
            ("mcp.rules_dir", "rules_dir"),
            ("mcp.lint_config", "lint_config"),
        ] {
            for (target, kept) in &cases {
                let body = format!("mcp:\n  {field}: {}\n", target.display());
                let path = write_config(dir.path(), ".rsigmarc", &body);
                let loaded = load_files(vec![(path, Layer::ProjectRc)]).unwrap();
                let mcp = loaded.config.mcp.unwrap();
                let got = match field {
                    "rules_dir" => mcp.rules_dir,
                    _ => mcp.lint_config,
                };
                assert_eq!(got.is_some(), *kept, "{key} = {}", target.display());
                assert_eq!(
                    loaded.ignored_keys.iter().any(|(_, k)| *k == key),
                    !kept,
                    "{key} = {}",
                    target.display()
                );
            }
        }
    }

    const DAEMON_GATES: &str = r#"
daemon:
  rules: rules/
  sources: [sources.yml]
  enrichers: enrich.yml
  dispositions:
    enabled: true
    source: dispositions.yml
  output:
    sinks: ["file:///tmp/out.ndjson"]
    dlq: "file:///tmp/dlq.ndjson"
    webhooks: [hooks/]
    batch_max: 64
  input:
    source: nats://127.0.0.1:4222/events
  nats:
    consumer_group: another-deployment
  state:
    db: /var/lib/elsewhere/state.db
    save_interval: 30
  api:
    addr: http://attacker.example:9090
    auth:
      tokens: [{ name: t, role: admin, token_env: HOME }]
    allow_unauthenticated: true
    tls:
      allow_plaintext: true
      client_ca: ca.pem
    audit:
      enabled: false
  tap:
    enabled: true
  tail:
    enabled: true
  capture:
    enabled: true
    spool_dir: /tmp/spool
  engine:
    egress_policy: permissive
    allow_remote_include: true
    bloom_prefilter: true
"#;

    #[test]
    fn project_layers_drop_protected_daemon_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "rsigma.yaml", DAEMON_GATES);
        let loaded = load_files(vec![(path, Layer::ProjectYaml)]).unwrap();
        let daemon = loaded.config.daemon.unwrap();

        assert_eq!(daemon.rules, Some(PathBuf::from("rules/")));
        assert!(daemon.sources.is_none());
        assert!(daemon.enrichers.is_none());
        let dispositions = daemon.dispositions.unwrap();
        assert_eq!(dispositions.enabled, Some(true));
        assert!(dispositions.source.is_none());
        let output = daemon.output.unwrap();
        assert!(output.sinks.is_none() && output.dlq.is_none() && output.webhooks.is_none());
        assert_eq!(output.batch_max, Some(64));
        assert!(daemon.input.unwrap().source.is_none());
        assert!(daemon.nats.unwrap().consumer_group.is_none());
        let state = daemon.state.unwrap();
        assert!(state.db.is_none());
        assert_eq!(state.save_interval, Some(30));
        let api = daemon.api.unwrap();
        assert!(api.addr.is_none());
        assert!(api.auth.is_none() && api.allow_unauthenticated.is_none() && api.audit.is_none());
        let tls = api.tls.unwrap();
        assert!(tls.allow_plaintext.is_none() && tls.client_ca.is_none());
        assert!(daemon.tap.unwrap().enabled.is_none());
        assert!(daemon.tail.unwrap().enabled.is_none());
        let capture = daemon.capture.unwrap();
        assert!(capture.enabled.is_none() && capture.spool_dir.is_none());
        let engine = daemon.engine.unwrap();
        assert!(engine.egress_policy.is_none() && engine.allow_remote_include.is_none());
        assert_eq!(engine.bloom_prefilter, Some(true));

        let ignored: Vec<&str> = loaded.ignored_keys.iter().map(|(_, k)| *k).collect();
        let daemon_keys: Vec<&str> = PROTECTED_KEYS
            .iter()
            .map(|p| p.key)
            .filter(|k| k.starts_with("daemon."))
            .collect();
        assert_eq!(ignored, daemon_keys);
    }

    #[test]
    fn project_layers_keep_local_daemon_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let inside = format!("unix://{}", dir.path().join("ingest.sock").display());
        for source in ["stdin", "http", inside.as_str()] {
            let body = format!("daemon:\n  input:\n    source: {source}\n");
            let path = write_config(dir.path(), "rsigma.yaml", &body);
            let loaded = load_files(vec![(path, Layer::ProjectYaml)]).unwrap();
            let input = loaded.config.daemon.unwrap().input.unwrap();
            assert_eq!(input.source.as_deref(), Some(source));
            assert!(loaded.ignored_keys.is_empty(), "{source}");
        }
    }

    #[test]
    fn project_unix_paths_and_api_addr_stay_local() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let inside_sock = format!("unix://{}", dir.path().join("api.sock").display());
        let outside_sock = format!("unix://{}", outside.path().join("victim.txt").display());
        let escape_sock = format!("unix://{}", dir.path().join("../victim.txt").display());

        for source in [outside_sock.as_str(), escape_sock.as_str()] {
            let body = format!("daemon:\n  input:\n    source: {source}\n");
            let path = write_config(dir.path(), "rsigma.yaml", &body);
            let loaded = load_files(vec![(path, Layer::ProjectYaml)]).unwrap();
            assert!(
                loaded
                    .config
                    .daemon
                    .unwrap()
                    .input
                    .unwrap()
                    .source
                    .is_none(),
                "{source}"
            );
        }

        for (addr, kept) in [
            ("127.0.0.1:9090", true),
            ("[::1]:9090", true),
            ("localhost:9090", true),
            (inside_sock.as_str(), true),
            ("0.0.0.0:9090", false),
            ("10.0.0.5:9090", false),
            ("http://127.0.0.1:9090", false),
            ("https://attacker.example", false),
            ("attacker.example:9090", false),
            (outside_sock.as_str(), false),
        ] {
            let body = format!("daemon:\n  api:\n    addr: \"{addr}\"\n");
            let path = write_config(dir.path(), "rsigma.yaml", &body);
            let loaded = load_files(vec![(path, Layer::ProjectYaml)]).unwrap();
            let got = loaded.config.daemon.unwrap().api.unwrap().addr;
            assert_eq!(got.is_some(), kept, "{addr}");
        }

        for (target, kept) in [
            (dir.path().join("out"), true),
            (outside.path().join("planted"), false),
        ] {
            let t = target.display();
            let body = format!(
                "daemon:\n  state:\n    db: {t}.db\neval:\n  output: {t}.ndjson\nscorecard:\n  report: {t}.md\n"
            );
            let path = write_config(dir.path(), "rsigma.yaml", &body);
            let loaded = load_files(vec![(path, Layer::ProjectYaml)]).unwrap();
            let config = loaded.config;
            assert_eq!(
                config.daemon.unwrap().state.unwrap().db.is_some(),
                kept,
                "{t}"
            );
            assert_eq!(config.eval.unwrap().output.is_some(), kept, "{t}");
            assert_eq!(config.scorecard.unwrap().report.is_some(), kept, "{t}");
            assert_eq!(loaded.ignored_keys.len(), if kept { 0 } else { 3 }, "{t}");
        }
    }

    #[test]
    fn config_init_template_sets_no_protected_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "rsigma.yaml", include_str!("template.yaml"));
        let loaded = load_files(vec![(path, Layer::ProjectYaml)]).unwrap();
        assert!(loaded.ignored_keys.is_empty(), "{:?}", loaded.ignored_keys);
    }

    #[test]
    fn project_layers_may_turn_gates_off() {
        let dir = tempfile::tempdir().unwrap();
        let body = "mcp:\n  allow_sigma_cli: false\n  allow_operate_writes: false\ndaemon:\n  api:\n    allow_unauthenticated: false\n  tap:\n    enabled: false\n  engine:\n    allow_remote_include: false\n";
        let path = write_config(dir.path(), ".rsigmarc", body);
        let loaded = load_files(vec![(path, Layer::ProjectRc)]).unwrap();
        assert!(loaded.ignored_keys.is_empty(), "{:?}", loaded.ignored_keys);
        let mcp = loaded.config.mcp.unwrap();
        assert_eq!(mcp.allow_sigma_cli, Some(false));
        assert_eq!(mcp.allow_operate_writes, Some(false));
        let daemon = loaded.config.daemon.unwrap();
        assert_eq!(daemon.api.unwrap().allow_unauthenticated, Some(false));
        assert_eq!(daemon.tap.unwrap().enabled, Some(false));
        assert_eq!(daemon.engine.unwrap().allow_remote_include, Some(false));
    }

    #[test]
    fn operator_layers_keep_protected_daemon_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "config.yaml", DAEMON_GATES);
        let loaded = load_files(vec![(path, Layer::User)]).unwrap();
        let daemon = loaded.config.daemon.unwrap();
        assert_eq!(daemon.enrichers, Some(PathBuf::from("enrich.yml")));
        assert_eq!(daemon.api.unwrap().allow_unauthenticated, Some(true));
        assert!(loaded.ignored_keys.is_empty());
    }

    #[test]
    fn api_url_maps_wildcard_to_loopback() {
        assert_eq!(
            api_url("0.0.0.0:9090", "/api/v1/status"),
            "http://127.0.0.1:9090/api/v1/status"
        );
        assert_eq!(
            api_url("[::]:9090", "/api/v1/status"),
            "http://[::1]:9090/api/v1/status"
        );
        assert_eq!(
            api_url("10.0.0.1:9090", "/api/v1/reload"),
            "http://10.0.0.1:9090/api/v1/reload"
        );
    }

    #[test]
    fn api_url_accepts_full_url() {
        assert_eq!(
            api_url("https://daemon.internal:9443/", "/api/v1/status"),
            "https://daemon.internal:9443/api/v1/status"
        );
        assert_eq!(
            api_url("http://127.0.0.1:9090", "/api/v1/reload"),
            "http://127.0.0.1:9090/api/v1/reload"
        );
    }
}
