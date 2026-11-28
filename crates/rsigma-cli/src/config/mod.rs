//! Layered YAML configuration for rsigma.
//!
//! Configuration is resolved with the precedence (low to high):
//! compiled defaults < `/etc/rsigma` (`%ProgramData%\rsigma` on Windows) <
//! `~/.config/rsigma` < nearest `.rsigmarc` (walked up from CWD, no further
//! than `$HOME` or the filesystem the walk started on) < `./rsigma.yaml` <
//! environment variables < CLI flags. A discovered file is read only when
//! it and its directory belong to the invoking user or an administrator
//! (see [`trust`]). An explicit `--config <path>` replaces the file-discovery
//! set entirely (only that file is loaded), mirroring
//! `rsigma rule lint --config`.
//!
//! This module owns the file layer: discovery, layered loading, and
//! unknown-key / inactive-section diagnostics. The env and flag layers, plus
//! the mapping from config keys to concrete command settings, live in
//! `resolve` (added alongside the per-command wiring).

pub(crate) mod commands;
pub(crate) mod defaults;
mod resolve;
mod schema;
mod trust;

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::fsutil::{path_within, with_suffix};

#[cfg(feature = "daemon")]
pub(crate) use schema::TenantQuotasPartial;
pub(crate) use schema::{
    ConvertGroupPartial, Merge, RsigmaConfigPartial, RulesetEntryPartial, WhenPartial,
    manifest_path,
};

/// Load the config files and fold them with the compiled defaults and the
/// `RSIGMA_*` environment layer into one typed partial (precedence:
/// default < file < env). Exits with `CONFIG_ERROR` if a discovered file
/// cannot be read or parsed, or sets a key the schema does not know, after
/// printing every unknown key.
///
/// The CLI-flag layer is applied separately by each command, since only the
/// command knows which of its flags were set explicitly.
pub(crate) fn load_and_merge(explicit: Option<&Path>) -> RsigmaConfigPartial {
    match load_layered(explicit) {
        Ok(loaded) => {
            if !loaded.unknown_keys.is_empty() {
                for (path, key) in &loaded.unknown_keys {
                    eprintln!("error: unknown config key '{key}' in {}", path.display());
                }
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
            for (path, reason) in &loaded.skipped_files {
                warn_once(skipped_file_warning(path, reason));
            }
            for (path, key) in &loaded.ignored_keys {
                warn_once(ignored_key_warning(path, key));
            }
            for section in inactive_sections(&loaded.config) {
                warn_once(format!(
                    "warning: config section '{section}' is set but inert in this build (feature disabled)"
                ));
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

/// Print a config warning to stderr unless this process already printed it.
/// A command can read the layered config more than once.
fn warn_once(message: String) {
    static PRINTED: std::sync::Mutex<std::collections::BTreeSet<String>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    let mut printed = PRINTED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !printed.contains(&message) {
        eprintln!("{message}");
        printed.insert(message);
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
    /// [`PROTECTED_KEYS`] and [`PROTECTED_ENTRY_KEYS`] a project file set, as
    /// dotted keys paired with that file. They are not part of
    /// [`Self::config`].
    pub ignored_keys: Vec<(PathBuf, String)>,
    /// Whether a project layer (`./rsigma.yaml`, `./rsigma.yml`, `.rsigmarc`)
    /// was loaded. Tenancy refuses to start when one was.
    pub project_layer_loaded: bool,
    /// Discovered files that were not read because another account could
    /// have written them, each with the reason.
    pub skipped_files: Vec<(PathBuf, String)>,
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

/// Walk up from `start` looking for a project `.rsigmarc`. The walk ends
/// after `home`, and before it would leave the filesystem `start` is on.
fn find_rsigmarc(start: &Path, home: Option<&Path>, probe: &dyn trust::Probe) -> Option<PathBuf> {
    let home = home.and_then(|home| std::fs::canonicalize(home).ok());
    let device = probe.device(start);
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join(".rsigmarc");
        if candidate.is_file() {
            return Some(candidate);
        }
        if home.is_some() && std::fs::canonicalize(&current).ok() == home {
            return None;
        }
        if !current.pop() || probe.device(&current) != device {
            return None;
        }
    }
}

/// The discovery layer a config file was loaded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    /// `/etc/rsigma/config.yaml`, or `%ProgramData%\rsigma\config.yaml` on
    /// Windows.
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

    /// The layer's name in `config path` output.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Layer::System => "system",
            Layer::User => "user",
            Layer::ProjectRc => "project_rc",
            Layer::ProjectYaml => "project_yaml",
            Layer::Explicit => "explicit",
        }
    }
}

/// A location config discovery searched, lowest precedence first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Location {
    pub layer: Layer,
    /// The file found, or where it was looked for. For a `.rsigmarc` that
    /// was not found, the directory the upward walk started in.
    pub path: PathBuf,
    pub status: LocationStatus,
}

/// Whether discovery read the file at a [`Location`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocationStatus {
    Loaded,
    Missing,
    /// Present, but not read because another account could have written it.
    Skipped(String),
}

/// The directories config discovery looks in.
struct SearchRoots {
    system: Option<PathBuf>,
    user: Option<PathBuf>,
    /// The absolute current directory, where the `.rsigmarc` walk starts.
    cwd: Option<PathBuf>,
    /// The walk stops after this directory.
    home: Option<PathBuf>,
    /// The directory holding `rsigma.yaml`.
    project: PathBuf,
}

impl SearchRoots {
    fn current() -> Self {
        Self {
            system: trust::system_config_dir(),
            user: user_config_dir(),
            cwd: std::env::current_dir().ok(),
            home: dirs::home_dir(),
            project: PathBuf::from("."),
        }
    }
}

/// Every location config discovery searches, lowest precedence first. With
/// `explicit`, only that file, which is read as given so a bad `--config`
/// surfaces a clear error.
pub(crate) fn search(explicit: Option<&Path>) -> Vec<Location> {
    match explicit {
        Some(path) => vec![Location {
            layer: Layer::Explicit,
            path: path.to_path_buf(),
            status: LocationStatus::Loaded,
        }],
        None => search_in(&SearchRoots::current(), &trust::SystemProbe),
    }
}

fn search_in(roots: &SearchRoots, probe: &dyn trust::Probe) -> Vec<Location> {
    let located = |layer: Layer, found: Option<PathBuf>, missing: PathBuf| match found {
        None => Location {
            layer,
            path: missing,
            status: LocationStatus::Missing,
        },
        Some(path) => {
            let status = match trust::untrusted_reason(&path, !layer.is_project(), probe) {
                Some(reason) => LocationStatus::Skipped(reason),
                None => LocationStatus::Loaded,
            };
            Location {
                layer,
                path,
                status,
            }
        }
    };
    let mut locations = Vec::new();
    for (layer, dir) in [(Layer::System, &roots.system), (Layer::User, &roots.user)] {
        if let Some(dir) = dir {
            locations.push(located(
                layer,
                first_existing(dir, "config"),
                dir.join("config.yaml"),
            ));
        }
    }
    if let Some(cwd) = &roots.cwd {
        locations.push(located(
            Layer::ProjectRc,
            find_rsigmarc(cwd, roots.home.as_deref(), probe),
            cwd.clone(),
        ));
    }
    locations.push(located(
        Layer::ProjectYaml,
        first_existing(&roots.project, "rsigma"),
        roots.project.join("rsigma.yaml"),
    ));
    locations
}

/// Resolve the ordered list of config files to load, lowest precedence first.
pub(crate) fn discover(explicit: Option<&Path>) -> Vec<PathBuf> {
    search(explicit)
        .into_iter()
        .filter(|location| location.status == LocationStatus::Loaded)
        .map(|location| location.path)
        .collect()
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
    // Tenancy identity and the source binding decide which tenant an event
    // belongs to. Turning tenancy off is the dangerous direction, so a project
    // file may not set them at all.
    ProtectedKey {
        key: "daemon.tenancy",
        strip: |c, _| take(daemon(c).map(|d| &mut d.tenancy)),
    },
    ProtectedKey {
        key: "daemon.input.tenant",
        strip: |c, _| {
            take(
                daemon(c)
                    .and_then(|d| d.input.as_mut())
                    .map(|i| &mut i.tenant),
            )
        },
    },
    ProtectedKey {
        key: "daemon.input.nats_tenants",
        strip: |c, _| {
            take(
                daemon(c)
                    .and_then(|d| d.input.as_mut())
                    .map(|i| &mut i.nats_tenants),
            )
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
        key: "daemon.api.allowed_hosts",
        strip: |c, _| take(api(c).map(|a| &mut a.allowed_hosts)),
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
    // Files the CLI creates or truncates. SQLite writes its write-ahead log,
    // shared-memory index, and rollback journal next to the database.
    ProtectedKey {
        key: "daemon.state.db",
        strip: |c, project_dir| {
            daemon(c).and_then(|d| d.state.as_mut()).is_some_and(|s| {
                take_outside_with(&mut s.db, project_dir, &["-wal", "-shm", "-journal"])
            })
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
        key: "backtest.findings",
        strip: |c, project_dir| {
            c.backtest
                .as_mut()
                .is_some_and(|b| take_outside(&mut b.findings, project_dir))
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
    ProtectedKey {
        key: "convert.defaults.output",
        strip: |c, project_dir| {
            c.convert
                .as_mut()
                .and_then(|convert| convert.defaults.as_mut())
                .is_some_and(|defaults| take_convert_output(defaults, project_dir))
        },
    },
];

/// A security-sensitive key inside every entry of a named map, such as
/// `rulesets.<name>.output`. Project files may not set it, as for
/// [`PROTECTED_KEYS`].
pub(crate) struct ProtectedEntryKey {
    /// Dotted config path with `*` standing for the entry name.
    pub key: &'static str,
    /// Clear the key from every entry of a project file's partial that may
    /// not set it. `project_dir` is the directory holding that file. Returns
    /// the names of the entries it was cleared from.
    strip: fn(&mut RsigmaConfigPartial, project_dir: &Path) -> Vec<String>,
}

/// Every per-entry key project files may not set.
/// `scripts/docs-audit/check_sources.py` checks that the configuration and
/// security references list each one.
pub(crate) const PROTECTED_ENTRY_KEYS: &[ProtectedEntryKey] = &[
    // `ruleset build` writes the directory and deletes stale files in it.
    ProtectedEntryKey {
        key: "rulesets.*.output",
        strip: |c, project_dir| {
            strip_entries(c.rulesets.as_mut(), |spec| {
                take_outside(&mut spec.output, project_dir)
            })
        },
    },
    ProtectedEntryKey {
        key: "convert.groups.*.output",
        strip: |c, project_dir| {
            strip_entries(
                c.convert
                    .as_mut()
                    .and_then(|convert| convert.groups.as_mut()),
                |group| take_convert_output(group, project_dir),
            )
        },
    },
];

/// Apply `strip` to every entry of `map` and return the names it cleared.
fn strip_entries<T>(
    map: Option<&mut BTreeMap<String, T>>,
    mut strip: impl FnMut(&mut T) -> bool,
) -> Vec<String> {
    map.into_iter()
        .flatten()
        .filter_map(|(name, entry)| strip(entry).then(|| name.clone()))
        .collect()
}

/// Clear a conversion group's output when it, or the manifest written next
/// to it, lies outside `project_dir`.
fn take_convert_output(group: &mut schema::ConvertGroupPartial, project_dir: &Path) -> bool {
    take_outside_with(&mut group.output, project_dir, &[schema::MANIFEST_SUFFIX])
}

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
    take_outside_with(path, project_dir, &[])
}

/// Clear `path` when it, or a sibling file `<path><suffix>` written along
/// with it, lies outside `project_dir`. Returns whether it did.
fn take_outside_with(path: &mut Option<PathBuf>, project_dir: &Path, suffixes: &[&str]) -> bool {
    let outside = path.as_deref().is_some_and(|p| {
        !path_within(p, project_dir)
            || suffixes
                .iter()
                .any(|suffix| !path_within(&with_suffix(p, suffix), project_dir))
    });
    if outside {
        *path = None;
    }
    outside
}

/// Remove every [`PROTECTED_KEYS`] and [`PROTECTED_ENTRY_KEYS`] entry from a
/// project file's partial and return the dotted keys that were set.
fn strip_untrusted(config: &mut RsigmaConfigPartial, project_dir: &Path) -> Vec<String> {
    let mut stripped: Vec<String> = PROTECTED_KEYS
        .iter()
        .filter(|protected| (protected.strip)(config, project_dir))
        .map(|protected| protected.key.to_string())
        .collect();
    for protected in PROTECTED_ENTRY_KEYS {
        for name in (protected.strip)(config, project_dir) {
            stripped.push(protected.key.replacen('*', &name, 1));
        }
    }
    stripped
}

/// Record `project_dir` as the root every conversion output kept from a
/// project file must stay inside when `backend build` writes it.
fn pin_convert_outputs(config: &mut RsigmaConfigPartial, project_dir: &Path) {
    let Some(convert) = config.convert.as_mut() else {
        return;
    };
    let root = std::path::absolute(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let groups = convert
        .groups
        .iter_mut()
        .flat_map(|groups| groups.values_mut());
    for group in convert.defaults.iter_mut().chain(groups) {
        if group.output.is_some() {
            group.output_root = Some(root.clone());
        }
    }
}

/// Render an ignored-key path as the dotted key an operator writes, such as
/// `daemon.api.adr`. `serde_ignored` prints `?` for each `Option` and newtype
/// layer, which is not part of the YAML.
fn dotted_key(path: &serde_ignored::Path<'_>) -> String {
    fn push(path: &serde_ignored::Path<'_>, segments: &mut Vec<String>) {
        match path {
            serde_ignored::Path::Root => {}
            serde_ignored::Path::Seq { parent, index } => {
                push(parent, segments);
                segments.push(index.to_string());
            }
            serde_ignored::Path::Map { parent, key } => {
                push(parent, segments);
                segments.push(key.clone());
            }
            serde_ignored::Path::Some { parent }
            | serde_ignored::Path::NewtypeStruct { parent }
            | serde_ignored::Path::NewtypeVariant { parent } => push(parent, segments),
        }
    }
    let mut segments = Vec::new();
    push(path, &mut segments);
    segments.join(".")
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
        serde_ignored::deserialize(doc, |path| unknown.push(dotted_key(&path))).map_err(|e| {
            let raw = e.to_string();
            // A top-level scalar/sequence/null produces serde's terse
            // "invalid type: …, expected struct RsigmaConfigPartial". Rewrite it
            // into something an operator can act on.
            let message = if raw.contains("expected struct RsigmaConfigPartial") {
                format!(
                    "top-level config must be a YAML mapping of sections \
                 (global, daemon, eval, backtest, coverage, scorecard, visibility, doc, hygiene, mcp, rulesets, convert); got {raw}"
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
    load_locations(search(explicit))
}

/// Load the [`LocationStatus::Loaded`] files of `locations` and record the
/// skipped ones.
fn load_locations(locations: Vec<Location>) -> Result<LoadedConfig, ConfigError> {
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    for location in locations {
        match location.status {
            LocationStatus::Loaded => files.push((location.path, location.layer)),
            LocationStatus::Skipped(reason) => skipped.push((location.path, reason)),
            LocationStatus::Missing => {}
        }
    }
    let mut loaded = load_files(files)?;
    loaded.skipped_files = skipped;
    Ok(loaded)
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
            loaded.project_layer_loaded = true;
            let project_dir = path
                .parent()
                .filter(|dir| !dir.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            for key in strip_untrusted(&mut partial, project_dir) {
                loaded.ignored_keys.push((path.clone(), key));
            }
            pin_convert_outputs(&mut partial, project_dir);
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

/// The warning printed for a discovered file that was not read.
pub(crate) fn skipped_file_warning(path: &Path, reason: &str) -> String {
    format!(
        "warning: skipping config {}: {reason}; pass it with --config to read it anyway",
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

    #[cfg(not(feature = "stix-enrich"))]
    if config
        .daemon
        .as_ref()
        .is_some_and(|d| d.stix_store.is_some() || d.stix_store_allow_custom)
    {
        inactive.push("daemon.stix_store");
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
        assert!(unknown.iter().any(|k| k == "daemon.nope"), "{unknown:?}");
    }

    #[test]
    fn feature_gated_keys_are_known_in_every_build() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rsigma.yaml");
        std::fs::write(
            &path,
            "daemon:\n  stix_store: ./stix\n  stix_store_allow_custom: true\n  nats:\n    consumer_group: workers\n  api:\n    tls:\n      cert: ./cert.pem\n",
        )
        .unwrap();

        let (partial, unknown) = load_file(&path).unwrap();
        assert!(unknown.is_empty(), "{unknown:?}");
        #[cfg(not(feature = "stix-enrich"))]
        assert!(inactive_sections(&partial).contains(&"daemon.stix_store"));
        #[cfg(feature = "stix-enrich")]
        assert!(!inactive_sections(&partial).contains(&"daemon.stix_store"));
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
            let keys: Vec<&str> = loaded
                .ignored_keys
                .iter()
                .map(|(_, k)| k.as_str())
                .collect();
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
                    loaded.ignored_keys.iter().any(|(_, k)| k == key),
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
    tenant: tenant-a
    nats_tenants:
      - subject: tenants.tenant-b.>
        tenant: tenant-b
  tenancy:
    enabled: true
  nats:
    consumer_group: another-deployment
  state:
    db: /var/lib/elsewhere/state.db
    save_interval: 30
  api:
    addr: http://attacker.example:9090
    auth:
      tokens: [{ name: t, role: admin, token_env: HOME }]
    allowed_hosts: ["attacker.example"]
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
        let input = daemon.input.unwrap();
        assert!(input.source.is_none());
        assert!(input.tenant.is_none() && input.nats_tenants.is_none());
        assert!(daemon.tenancy.is_none());
        assert!(daemon.nats.unwrap().consumer_group.is_none());
        let state = daemon.state.unwrap();
        assert!(state.db.is_none());
        assert_eq!(state.save_interval, Some(30));
        let api = daemon.api.unwrap();
        assert!(api.addr.is_none());
        assert!(api.auth.is_none() && api.allow_unauthenticated.is_none() && api.audit.is_none());
        assert!(api.allowed_hosts.is_none());
        let tls = api.tls.unwrap();
        assert!(tls.allow_plaintext.is_none() && tls.client_ca.is_none());
        assert!(daemon.tap.unwrap().enabled.is_none());
        assert!(daemon.tail.unwrap().enabled.is_none());
        let capture = daemon.capture.unwrap();
        assert!(capture.enabled.is_none() && capture.spool_dir.is_none());
        let engine = daemon.engine.unwrap();
        assert!(engine.egress_policy.is_none() && engine.allow_remote_include.is_none());
        assert_eq!(engine.bloom_prefilter, Some(true));

        let ignored: Vec<&str> = loaded
            .ignored_keys
            .iter()
            .map(|(_, k)| k.as_str())
            .collect();
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
            let body = format!("daemon:\n  api:\n    addr: '{addr}'\n");
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

    fn write_paths_config(target: &str) -> String {
        format!(
            "backtest:\n  findings: '{target}/findings.ndjson'\nrulesets:\n  r:\n    sources: [rules]\n    output: '{target}/ruleset'\nconvert:\n  defaults:\n    output: '{target}/default.txt'\n  groups:\n    a:\n      ruleset: r\n      target: test\n      output: '{target}/a.txt'\n    b:\n      ruleset: r\n      target: test\n"
        )
    }

    #[test]
    fn project_write_paths_must_stay_inside_the_project() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let inside = dir.path().join("build");
        let escape = dir.path().join("build/../..");
        for (target, kept) in [
            (inside.as_path(), true),
            (outside.path(), false),
            (escape.as_path(), false),
        ] {
            let body = write_paths_config(&target.display().to_string());
            let path = write_config(dir.path(), "rsigma.yaml", &body);
            let loaded = load_files(vec![(path, Layer::ProjectYaml)]).unwrap();
            let config = loaded.config;
            let t = target.display();
            assert_eq!(config.backtest.unwrap().findings.is_some(), kept, "{t}");
            assert_eq!(config.rulesets.unwrap()["r"].output.is_some(), kept, "{t}");
            let convert = config.convert.unwrap();
            assert_eq!(convert.defaults.unwrap().output.is_some(), kept, "{t}");
            let groups = convert.groups.unwrap();
            assert_eq!(groups["a"].output.is_some(), kept, "{t}");
            assert!(groups["b"].output.is_none());
            let keys: Vec<&str> = loaded
                .ignored_keys
                .iter()
                .map(|(_, k)| k.as_str())
                .collect();
            let expected: &[&str] = if kept {
                &[]
            } else {
                &[
                    "backtest.findings",
                    "convert.defaults.output",
                    "rulesets.r.output",
                    "convert.groups.a.output",
                ]
            };
            assert_eq!(keys, expected, "{t}");
        }
    }

    #[test]
    fn operator_layers_keep_write_paths_outside_the_project() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let body = write_paths_config(&outside.path().display().to_string());
        let path = write_config(dir.path(), "config.yaml", &body);
        for layer in [Layer::System, Layer::User, Layer::Explicit] {
            let loaded = load_files(vec![(path.clone(), layer)]).unwrap();
            assert!(loaded.ignored_keys.is_empty(), "{layer:?}");
            let convert = loaded.config.convert.unwrap();
            let group = convert.effective(&convert.groups.as_ref().unwrap()["a"]);
            assert!(group.output.is_some() && group.output_root.is_none());
            assert!(loaded.config.rulesets.unwrap()["r"].output.is_some());
        }
    }

    #[test]
    fn convert_output_root_follows_the_layer_that_set_the_output() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let user = write_config(
            dir.path(),
            "config.yaml",
            &format!(
                "convert:\n  defaults:\n    output: '{}'\n  groups:\n    operator:\n      ruleset: r\n      output: '{}'\n",
                outside.path().join("default.txt").display(),
                outside.path().join("operator.txt").display(),
            ),
        );
        let inside = dir.path().join("build/project.txt");
        let project = write_config(
            dir.path(),
            "rsigma.yaml",
            &format!(
                "convert:\n  groups:\n    project:\n      ruleset: r\n      output: '{}'\n    inherits:\n      ruleset: r\n",
                inside.display()
            ),
        );
        let loaded = load_files(vec![(user, Layer::User), (project, Layer::ProjectYaml)]).unwrap();
        let convert = loaded.config.convert.unwrap();
        let groups = convert.groups.as_ref().unwrap();
        let root = std::path::absolute(dir.path()).unwrap();

        let project = convert.effective(&groups["project"]);
        assert_eq!(project.output, Some(inside));
        assert_eq!(project.output_root, Some(root));
        let inherits = convert.effective(&groups["inherits"]);
        assert_eq!(inherits.output, Some(outside.path().join("default.txt")));
        assert!(inherits.output_root.is_none());
        let operator = convert.effective(&groups["operator"]);
        assert!(operator.output_root.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn project_state_db_sidecars_must_stay_inside_the_project() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        for sidecar in ["-wal", "-shm", "-journal"] {
            let db = dir.path().join(format!("state{sidecar}.db"));
            let victim = outside.path().join(format!("victim{sidecar}"));
            std::fs::write(&victim, "").unwrap();
            std::os::unix::fs::symlink(&victim, with_suffix(&db, sidecar)).unwrap();
            let body = format!("daemon:\n  state:\n    db: '{}'\n", db.display());
            let path = write_config(dir.path(), "rsigma.yaml", &body);
            let loaded = load_files(vec![(path, Layer::ProjectYaml)]).unwrap();
            let state = loaded.config.daemon.unwrap().state.unwrap();
            assert!(state.db.is_none(), "{sidecar}");
            assert_eq!(loaded.ignored_keys.len(), 1, "{sidecar}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn project_paths_through_a_missing_directory_cannot_reach_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let target = dir.path().join("missing/../link/out.ndjson");
        let body = format!("eval:\n  output: '{}'\n", target.display());
        let path = write_config(dir.path(), "rsigma.yaml", &body);
        let loaded = load_files(vec![(path, Layer::ProjectYaml)]).unwrap();
        assert!(loaded.config.eval.unwrap().output.is_none());
    }

    #[test]
    fn protected_keys_are_unique() {
        let mut keys: Vec<&str> = PROTECTED_KEYS.iter().map(|p| p.key).collect();
        keys.extend(PROTECTED_ENTRY_KEYS.iter().map(|p| p.key));
        let total = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), total);
        assert!(
            PROTECTED_ENTRY_KEYS
                .iter()
                .all(|p| p.key.matches('*').count() == 1)
        );
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

    fn other_owner() -> trust::Facts {
        trust::Facts {
            owner: trust::Owner::Other("uid 1001".into()),
            writable_by: None,
        }
    }

    fn roots(dir: &Path) -> SearchRoots {
        SearchRoots {
            system: Some(dir.join("system")),
            user: Some(dir.join("user")),
            cwd: Some(dir.join("project")),
            home: None,
            project: dir.join("project"),
        }
    }

    #[test]
    fn files_owned_by_another_user_are_skipped_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["system", "user", "project"] {
            std::fs::create_dir(dir.path().join(sub)).unwrap();
        }
        let system = write_config(&dir.path().join("system"), "config.yaml", MCP_GATES);
        let user = write_config(&dir.path().join("user"), "config.yml", "version: 1\n");
        let rc = write_config(&dir.path().join("project"), ".rsigmarc", "version: 1\n");
        let project = write_config(&dir.path().join("project"), "rsigma.yaml", "version: 1\n");
        let mut probe = trust::FakeProbe::default();
        for path in [&system, &project] {
            probe
                .facts
                .insert(std::fs::canonicalize(path).unwrap(), other_owner());
        }

        let locations = search_in(&roots(dir.path()), &probe);
        let summary: Vec<(Layer, &Path, bool)> = locations
            .iter()
            .map(|l| {
                (
                    l.layer,
                    l.path.as_path(),
                    l.status == LocationStatus::Loaded,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (Layer::System, system.as_path(), false),
                (Layer::User, user.as_path(), true),
                (Layer::ProjectRc, rc.as_path(), true),
                (Layer::ProjectYaml, project.as_path(), false),
            ]
        );
        let LocationStatus::Skipped(reason) = locations[0].status.clone() else {
            panic!("{locations:?}");
        };
        assert!(
            reason.starts_with("the file is owned by uid 1001"),
            "{reason}"
        );

        let loaded = load_locations(locations).unwrap();
        assert_eq!(loaded.sources, [user, rc]);
        assert!(loaded.config.mcp.is_none(), "the skipped file was read");
        let skipped: Vec<&Path> = loaded
            .skipped_files
            .iter()
            .map(|(p, _)| p.as_path())
            .collect();
        assert_eq!(skipped, [system.as_path(), project.as_path()]);
        let warning = skipped_file_warning(&system, &reason);
        assert!(warning.contains("pass it with --config"), "{warning}");
    }

    #[test]
    fn missing_locations_name_where_discovery_looked() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("project")).unwrap();
        let locations = search_in(&roots(dir.path()), &trust::FakeProbe::default());
        let paths: Vec<(Layer, PathBuf)> = locations
            .into_iter()
            .inspect(|l| assert_eq!(l.status, LocationStatus::Missing))
            .map(|l| (l.layer, l.path))
            .collect();
        assert_eq!(
            paths,
            [
                (Layer::System, dir.path().join("system/config.yaml")),
                (Layer::User, dir.path().join("user/config.yaml")),
                (Layer::ProjectRc, dir.path().join("project")),
                (Layer::ProjectYaml, dir.path().join("project/rsigma.yaml")),
            ]
        );
    }

    #[test]
    fn the_rsigmarc_walk_stops_at_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let cwd = home.join("repo/rules");
        std::fs::create_dir_all(&cwd).unwrap();
        write_config(dir.path(), ".rsigmarc", "version: 1\n");
        let probe = trust::FakeProbe::default();

        assert_eq!(find_rsigmarc(&cwd, Some(&home), &probe), None);
        assert_eq!(
            find_rsigmarc(&cwd, None, &probe),
            Some(dir.path().join(".rsigmarc"))
        );
        let in_home = write_config(&home, ".rsigmarc", "version: 1\n");
        assert_eq!(find_rsigmarc(&cwd, Some(&home), &probe), Some(in_home));
    }

    #[test]
    fn the_rsigmarc_walk_stops_at_a_filesystem_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let mount = dir.path().join("mnt");
        let cwd = mount.join("repo");
        std::fs::create_dir_all(&cwd).unwrap();
        write_config(dir.path(), ".rsigmarc", "version: 1\n");
        let mut probe = trust::FakeProbe::default();
        for path in [&mount, &cwd] {
            probe
                .devices
                .insert(std::fs::canonicalize(path).unwrap(), 2);
        }
        assert_eq!(find_rsigmarc(&cwd, None, &probe), None);
        let on_mount = write_config(&mount, ".rsigmarc", "version: 1\n");
        assert_eq!(find_rsigmarc(&cwd, None, &probe), Some(on_mount));
    }

    #[test]
    fn an_rsigmarc_owned_by_another_user_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().join("project/sub");
        std::fs::create_dir_all(&cwd).unwrap();
        let rc = write_config(&dir.path().join("project"), ".rsigmarc", MCP_GATES);
        let mut probe = trust::FakeProbe::default();
        probe
            .facts
            .insert(std::fs::canonicalize(&rc).unwrap(), other_owner());
        let mut roots = roots(dir.path());
        roots.cwd = Some(cwd);
        let locations = search_in(&roots, &probe);
        let rc_location = locations
            .iter()
            .find(|l| l.layer == Layer::ProjectRc)
            .unwrap();
        assert_eq!(rc_location.path, rc);
        assert!(matches!(rc_location.status, LocationStatus::Skipped(_)));
    }

    #[test]
    fn explicit_config_is_read_without_an_ownership_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "custom.yaml", "version: 1\n");
        assert_eq!(
            search(Some(&path)),
            [Location {
                layer: Layer::Explicit,
                path,
                status: LocationStatus::Loaded,
            }]
        );
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
