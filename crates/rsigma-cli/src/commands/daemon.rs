//! Daemon subcommand: long-running detection service.
//!
//! Hosts the `DaemonArgs` clap struct, the `cmd_daemon` entry point, and the
//! input-format / timezone parsing helpers that used to live in `main.rs`.

use std::path::PathBuf;
use std::process;

use clap::Args;

use crate::daemon;
use crate::exit_code;

/// Arguments for `rsigma engine daemon` (and the deprecated `rsigma daemon`).
#[derive(Args, Debug)]
pub(crate) struct DaemonArgs {
    /// Path to a Sigma rule file or directory of rules
    #[arg(short, long)]
    pub rules: PathBuf,

    /// Processing pipeline(s) to apply. Accepts builtin names (ecs_windows, sysmon) or YAML file paths
    #[arg(short = 'p', long = "pipeline")]
    pub pipelines: Vec<PathBuf>,

    /// jq filter to extract the event payload from each JSON object
    #[arg(long = "jq", conflicts_with = "jsonpath")]
    pub jq: Option<String>,

    /// JSONPath (RFC 9535) query to extract the event payload
    #[arg(long = "jsonpath", conflicts_with = "jq")]
    pub jsonpath: Option<String>,

    /// Include the full event JSON in each detection match output
    #[arg(long = "include-event")]
    pub include_event: bool,

    /// Pretty-print JSON output
    #[arg(long)]
    pub pretty: bool,

    /// Address for health, metrics, and API server (default: 0.0.0.0:9090)
    #[arg(long = "api-addr", default_value = "0.0.0.0:9090")]
    pub api_addr: String,

    /// Suppression window for correlation alerts (e.g. 5m, 1h, 30s)
    #[arg(long = "suppress")]
    pub suppress: Option<String>,

    /// Action after correlation fires: 'alert' (default) or 'reset'
    #[arg(long = "action", value_parser = ["alert", "reset"])]
    pub action: Option<String>,

    /// Suppress detection output for correlation-only rules
    #[arg(long = "no-detections")]
    pub no_detections: bool,

    /// Correlation event mode: none, full, or refs
    #[arg(long = "correlation-event-mode", default_value = "none")]
    pub correlation_event_mode: String,

    /// Max events per correlation window group
    #[arg(long = "max-correlation-events", default_value = "10")]
    pub max_correlation_events: usize,

    /// Event field name(s) for timestamp extraction in correlations
    #[arg(long = "timestamp-field")]
    pub timestamp_fields: Vec<String>,

    /// Path to SQLite database for persisting correlation state across restarts.
    /// When set, state is loaded on startup and saved periodically + on shutdown.
    #[arg(long = "state-db")]
    pub state_db: Option<PathBuf>,

    /// Interval in seconds between periodic state snapshots (default: 30).
    /// Only meaningful when --state-db is set.
    #[arg(long = "state-save-interval", default_value = "30", value_parser = clap::value_parser!(u64).range(1..))]
    pub state_save_interval: u64,

    /// Event input source. Supported schemes: stdin, http, nats://<host>:<port>/<subject>
    #[arg(long = "input", default_value = "stdin")]
    pub input: String,

    /// Detection output sink (can be repeated for fan-out).
    /// Supported schemes: stdout, file://<path>, nats://<host>:<port>/<subject>
    #[arg(long = "output", default_value = "stdout")]
    pub output: Vec<String>,

    /// Bounded channel capacity for source→engine and engine→sink queues.
    /// Higher values absorb bursts; lower values apply back-pressure sooner.
    #[arg(long = "buffer-size", default_value = "10000")]
    pub buffer_size: usize,

    /// Maximum events to process per engine lock acquisition.
    /// Reduces mutex overhead under load. 1 = process one at a time (default).
    #[arg(long = "batch-size", default_value = "1")]
    pub batch_size: usize,

    /// Seconds to wait for in-flight events to drain on shutdown (default: 5).
    #[arg(long = "drain-timeout", default_value = "5")]
    pub drain_timeout: u64,

    /// Dead-letter queue target for events that fail processing.
    /// Accepts same schemes as --output: stdout, file://<path>, nats://<host>:<port>/<subject>.
    /// When not set, failed events are logged and discarded.
    #[arg(long = "dlq")]
    pub dlq: Option<String>,

    /// Input log format for event parsing.
    /// auto: try JSON → syslog → plain (default).
    /// Explicit: json, syslog, plain, logfmt (requires logfmt feature),
    /// cef (requires cef feature).
    #[arg(long = "input-format", default_value = "auto")]
    pub input_format: String,

    /// Default timezone offset for RFC 3164 syslog (e.g. +05:00, -08:00).
    /// Only used when --input-format is syslog or auto. Defaults to UTC.
    #[arg(long = "syslog-tz", default_value = "+00:00")]
    pub syslog_tz: String,

    /// NATS credentials file (.creds) for JWT + NKey authentication.
    /// Also reads from NATS_CREDS environment variable.
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "nats-creds", env = "NATS_CREDS")]
    pub nats_creds: Option<PathBuf>,

    /// NATS authentication token. Also reads from NATS_TOKEN.
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "nats-token", env = "NATS_TOKEN", conflicts_with = "nats_creds")]
    pub nats_token: Option<String>,

    /// NATS username (requires --nats-password). Also reads from NATS_USER.
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "nats-user", env = "NATS_USER", requires = "nats_password", conflicts_with_all = ["nats_creds", "nats_token"])]
    pub nats_user: Option<String>,

    /// NATS password (requires --nats-user). Also reads from NATS_PASSWORD.
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "nats-password", env = "NATS_PASSWORD", requires = "nats_user")]
    pub nats_password: Option<String>,

    /// NATS NKey seed for authentication. Also reads from NATS_NKEY.
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "nats-nkey", env = "NATS_NKEY", conflicts_with_all = ["nats_creds", "nats_token", "nats_user"])]
    pub nats_nkey: Option<String>,

    /// TLS client certificate for mutual TLS with NATS.
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "nats-tls-cert", requires = "nats_tls_key")]
    pub nats_tls_cert: Option<PathBuf>,

    /// TLS client private key for mutual TLS with NATS.
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "nats-tls-key", requires = "nats_tls_cert")]
    pub nats_tls_key: Option<PathBuf>,

    /// Require TLS for NATS connections.
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "nats-require-tls")]
    pub nats_require_tls: bool,

    /// Replay from a specific JetStream sequence number.
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "replay-from-sequence", conflicts_with_all = ["replay_from_time", "replay_from_latest"])]
    pub replay_from_sequence: Option<u64>,

    /// Replay from a specific timestamp (ISO 8601, e.g. 2024-01-15T10:00:00Z).
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "replay-from-time", conflicts_with_all = ["replay_from_sequence", "replay_from_latest"])]
    pub replay_from_time: Option<String>,

    /// Start from the latest message, skipping stream history.
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "replay-from-latest", conflicts_with_all = ["replay_from_sequence", "replay_from_time"])]
    pub replay_from_latest: bool,

    /// Clear correlation state on startup. When used with --replay-from-*,
    /// forces a clean slate even if the replay starts after the stored position.
    #[arg(long = "clear-state", conflicts_with = "keep_state")]
    pub clear_state: bool,

    /// Force restore correlation state even during replay. Use when you know
    /// the replay starts after the last processed position (forward catch-up)
    /// and want to preserve cross-boundary correlation windows.
    #[arg(long = "keep-state", conflicts_with = "clear_state")]
    pub keep_state: bool,

    /// Behavior when no timestamp field is found in an event.
    /// 'wallclock' (default): use wall-clock time for correlation windows.
    /// 'skip': run detections but skip correlation state updates for that
    /// event. Recommended for forensic replay of logs without timestamps.
    #[arg(long = "timestamp-fallback", default_value = "wallclock",
           value_parser = ["wallclock", "skip"])]
    pub timestamp_fallback: String,

    /// Consumer group name for NATS JetStream load balancing.
    /// Multiple daemon instances using the same group name share the
    /// workload via a single durable pull consumer.
    #[cfg(feature = "daemon-nats")]
    #[arg(long = "consumer-group", env = "RSIGMA_CONSUMER_GROUP")]
    pub consumer_group: Option<String>,

    /// Allow include directives to reference remote (HTTP/NATS) sources.
    /// By default, includes are restricted to local sources (file/command)
    /// for security. Use this flag to opt in to remote include resolution.
    #[arg(long = "allow-remote-include")]
    pub allow_remote_include: bool,

    /// Enable bloom-filter pre-filtering of positive substring matchers.
    ///
    /// Off by default. When enabled, the engine builds a per-field bloom
    /// over every rule's `|contains` / `|startswith` / `|endswith`
    /// needles and short-circuits items whose field value cannot
    /// possibly contain a needle trigram. The probe costs ~1 µs per
    /// event, so this only pays off on rule sets where most events do
    /// NOT match any pattern (e.g. high-volume telemetry against
    /// substring-heavy threat-intel rules). Run the
    /// `eval_bloom_rejection` benchmark on representative data before
    /// flipping this on in production.
    #[arg(long = "bloom-prefilter")]
    pub bloom_prefilter: bool,

    /// Memory budget (in bytes) for the bloom index. Defaults to 1 MB
    /// (1048576). Lower the cap on memory-constrained deployments;
    /// raise it for very large rule sets where the default starts
    /// evicting useful filters. Has no effect unless
    /// `--bloom-prefilter` is set.
    #[arg(long = "bloom-max-bytes")]
    pub bloom_max_bytes: Option<usize>,

    /// Enable the cross-rule Aho-Corasick pre-filter (daachorse-index).
    ///
    /// Off by default. When enabled, the engine builds a single
    /// per-field `DoubleArrayAhoCorasick` over every rule's positive
    /// substring needles and drops AC-prunable rules (pure positive
    /// substring detections, no negation) from the candidate set when
    /// none of their patterns match the event. Pays off only on rule
    /// sets > ~5K rules with many shared substring patterns
    /// (threat-intel feeds, IOC packs). For smaller rule sets the
    /// per-rule Aho-Corasick matcher is already optimal. Build time
    /// scales linearly with total pattern count; pattern count per
    /// field is capped at 100K. Available when compiled with the
    /// `daachorse-index` Cargo feature.
    #[cfg(feature = "daachorse-index")]
    #[arg(long = "cross-rule-ac")]
    pub cross_rule_ac: bool,

    /// Path to a YAML file declaring post-evaluation enrichers.
    ///
    /// When set, every `EvaluationResult` produced by the engine flows
    /// through the configured enrichment pipeline (one or more of
    /// `template` / `lookup` / `http` / `command` primitives, plus any
    /// bespoke types registered via `register_builtin`) before being
    /// written to the sink. See the `Enrichers` section in the
    /// `rsigma-cli` README for the YAML schema and recipes.
    ///
    /// The validator runs at startup: a config that references the
    /// wrong template namespace (e.g. `${correlation.*}` inside a
    /// `kind: detection` enricher), declares an unknown `type:`, or
    /// has a malformed `scope:` rejects the daemon with a clear error.
    #[arg(long = "enrichers", value_name = "PATH")]
    pub enrichers: Option<PathBuf>,

    /// External source file(s) or directory of source files.
    ///
    /// Repeatable. Loads dynamic source declarations independently of
    /// any pipeline file. A file path loads one YAML file with a
    /// top-level `sources:` block; a directory path loads all
    /// `*.yml`/`*.yaml` files in it, alphabetically.
    ///
    /// Source IDs must be unique across all `--source` files and all
    /// pipeline-embedded `sources:` blocks; collisions are a startup
    /// error.
    #[arg(long = "source", value_name = "FILE_OR_DIR")]
    pub sources: Vec<PathBuf>,

    // ---------------------------------------------------------------
    // TLS (requires the `daemon-tls` build feature)
    // ---------------------------------------------------------------
    /// PEM-encoded TLS certificate (chain) for the API listener.
    ///
    /// When set together with `--tls-key`, the daemon terminates TLS
    /// for the HTTP REST API, the Prometheus `/metrics` endpoint, and
    /// (with `daemon-otlp`) both OTLP/HTTP and OTLP/gRPC on the same
    /// `--api-addr`. The leaf certificate and any intermediates may be
    /// concatenated in a single PEM file.
    ///
    /// Hot-reloaded on SIGHUP without dropping inflight connections.
    #[cfg(feature = "daemon-tls")]
    #[arg(long = "tls-cert", value_name = "PATH", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded TLS private key for the API listener.
    ///
    /// PKCS#8, PKCS#1 (RSA), and SEC1 (EC) formats are accepted.
    /// Encrypted keys are not supported yet; decrypt with
    /// `openssl rsa -in key.pem -out key-decrypted.pem` first.
    #[cfg(feature = "daemon-tls")]
    #[arg(long = "tls-key", value_name = "PATH", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,

    /// Password for an encrypted `--tls-key`. Currently rejected at
    /// startup; reserved for a future release to keep the flag stable.
    #[cfg(feature = "daemon-tls")]
    #[arg(long = "tls-key-password", env = "RSIGMA_TLS_KEY_PASSWORD")]
    pub tls_key_password: Option<String>,

    /// PEM bundle of trusted CA certificates used to verify inbound
    /// client certificates (mutual TLS).
    ///
    /// When set, clients must present a certificate signed by one of
    /// the listed CAs or the TLS handshake is rejected with
    /// `bad certificate`. Useful for agent-to-daemon pinning.
    #[cfg(feature = "daemon-tls")]
    #[arg(long = "tls-client-ca", value_name = "PATH", requires = "tls_cert")]
    pub tls_client_ca: Option<PathBuf>,

    /// Minimum TLS protocol version accepted by the server.
    ///
    /// Default is `1.3`. Use `1.2` only for compatibility with legacy
    /// agents that cannot negotiate TLS 1.3.
    #[cfg(feature = "daemon-tls")]
    #[arg(
        long = "tls-min-version",
        value_name = "VERSION",
        default_value = "1.3"
    )]
    pub tls_min_version: String,

    /// Allow the daemon to bind a non-loopback `--api-addr` without TLS.
    ///
    /// By default the daemon refuses to start on a public address
    /// (`0.0.0.0`, `::`, or any non-loopback IP) unless either
    /// `--tls-cert`/`--tls-key` is supplied or this flag is set.
    /// Loopback (`127.0.0.0/8`, `::1`) is always allowed in plaintext
    /// to keep local development friction-free.
    #[cfg(feature = "daemon-tls")]
    #[arg(long = "allow-plaintext")]
    pub allow_plaintext: bool,
}

/// Helper struct grouping NATS connection / auth flags so `cmd_daemon` does
/// not balloon back to 30+ positional parameters once we destructure the args.
#[cfg(feature = "daemon-nats")]
pub(crate) struct NatsAuthArgs {
    pub nats_creds: Option<PathBuf>,
    pub nats_token: Option<String>,
    pub nats_user: Option<String>,
    pub nats_password: Option<String>,
    pub nats_nkey: Option<String>,
    pub nats_tls_cert: Option<PathBuf>,
    pub nats_tls_key: Option<PathBuf>,
    pub nats_require_tls: bool,
}

/// Entry point for `rsigma engine daemon` (and the deprecated `rsigma daemon`).
pub(crate) fn cmd_daemon(args: DaemonArgs) {
    let DaemonArgs {
        rules: rules_path,
        pipelines: pipeline_paths,
        jq,
        jsonpath,
        include_event,
        pretty,
        api_addr,
        suppress,
        action,
        no_detections,
        correlation_event_mode,
        max_correlation_events,
        timestamp_fields,
        state_db,
        state_save_interval,
        input,
        output,
        buffer_size,
        batch_size,
        drain_timeout,
        dlq,
        input_format,
        syslog_tz,
        #[cfg(feature = "daemon-nats")]
        nats_creds,
        #[cfg(feature = "daemon-nats")]
        nats_token,
        #[cfg(feature = "daemon-nats")]
        nats_user,
        #[cfg(feature = "daemon-nats")]
        nats_password,
        #[cfg(feature = "daemon-nats")]
        nats_nkey,
        #[cfg(feature = "daemon-nats")]
        nats_tls_cert,
        #[cfg(feature = "daemon-nats")]
        nats_tls_key,
        #[cfg(feature = "daemon-nats")]
        nats_require_tls,
        #[cfg(feature = "daemon-nats")]
        replay_from_sequence,
        #[cfg(feature = "daemon-nats")]
        replay_from_time,
        #[cfg(feature = "daemon-nats")]
        replay_from_latest,
        clear_state,
        keep_state,
        timestamp_fallback,
        #[cfg(feature = "daemon-nats")]
        consumer_group,
        allow_remote_include,
        bloom_prefilter,
        bloom_max_bytes,
        #[cfg(feature = "daachorse-index")]
        cross_rule_ac,
        enrichers,
        sources: source_paths,
        #[cfg(feature = "daemon-tls")]
        tls_cert,
        #[cfg(feature = "daemon-tls")]
        tls_key,
        #[cfg(feature = "daemon-tls")]
        tls_key_password,
        #[cfg(feature = "daemon-tls")]
        tls_client_ca,
        #[cfg(feature = "daemon-tls")]
        tls_min_version,
        #[cfg(feature = "daemon-tls")]
        allow_plaintext,
    } = args;

    #[cfg(feature = "daemon-nats")]
    let nats_auth = NatsAuthArgs {
        nats_creds,
        nats_token,
        nats_user,
        nats_password,
        nats_nkey,
        nats_tls_cert,
        nats_tls_key,
        nats_require_tls,
    };

    #[cfg(feature = "daemon-nats")]
    let replay_policy = if let Some(seq) = replay_from_sequence {
        rsigma_runtime::ReplayPolicy::FromSequence(seq)
    } else if let Some(ref ts) = replay_from_time {
        let t = time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|e| {
                eprintln!("Invalid --replay-from-time '{ts}': {e}");
                process::exit(exit_code::CONFIG_ERROR);
            });
        rsigma_runtime::ReplayPolicy::FromTime(t)
    } else if replay_from_latest {
        rsigma_runtime::ReplayPolicy::Latest
    } else {
        rsigma_runtime::ReplayPolicy::Resume
    };

    let state_restore_mode = if clear_state {
        daemon::server::StateRestoreMode::ForceClear
    } else if keep_state {
        daemon::server::StateRestoreMode::ForceKeep
    } else {
        daemon::server::StateRestoreMode::Auto
    };

    #[cfg(feature = "daemon-tls")]
    let tls_args = TlsCliArgs {
        cert: tls_cert,
        key: tls_key,
        key_password: tls_key_password,
        client_ca: tls_client_ca,
        min_version: tls_min_version,
        allow_plaintext,
    };

    run_daemon(
        rules_path,
        pipeline_paths,
        jq,
        jsonpath,
        include_event,
        pretty,
        api_addr,
        suppress,
        action,
        no_detections,
        correlation_event_mode,
        max_correlation_events,
        timestamp_fields,
        timestamp_fallback,
        state_db,
        state_save_interval,
        input,
        output,
        buffer_size,
        batch_size,
        drain_timeout,
        dlq,
        input_format,
        syslog_tz,
        state_restore_mode,
        #[cfg(feature = "daemon-nats")]
        nats_auth,
        #[cfg(feature = "daemon-nats")]
        replay_policy,
        #[cfg(feature = "daemon-nats")]
        consumer_group,
        allow_remote_include,
        bloom_prefilter,
        bloom_max_bytes,
        #[cfg(feature = "daachorse-index")]
        cross_rule_ac,
        enrichers,
        source_paths,
        #[cfg(feature = "daemon-tls")]
        tls_args,
    );
}

/// Helper struct grouping TLS flags so `cmd_daemon` stays readable.
#[cfg(feature = "daemon-tls")]
pub(crate) struct TlsCliArgs {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub key_password: Option<String>,
    pub client_ca: Option<PathBuf>,
    pub min_version: String,
    pub allow_plaintext: bool,
}

#[allow(clippy::too_many_arguments)]
fn run_daemon(
    rules_path: PathBuf,
    pipeline_paths: Vec<PathBuf>,
    jq: Option<String>,
    jsonpath: Option<String>,
    include_event: bool,
    pretty: bool,
    api_addr: String,
    suppress: Option<String>,
    action: Option<String>,
    no_detections: bool,
    correlation_event_mode: String,
    max_correlation_events: usize,
    timestamp_fields: Vec<String>,
    timestamp_fallback: String,
    state_db: Option<PathBuf>,
    state_save_interval: u64,
    input: String,
    output: Vec<String>,
    buffer_size: usize,
    batch_size: usize,
    drain_timeout: u64,
    dlq: Option<String>,
    input_format: String,
    syslog_tz: String,
    state_restore_mode: daemon::server::StateRestoreMode,
    #[cfg(feature = "daemon-nats")] nats_auth: NatsAuthArgs,
    #[cfg(feature = "daemon-nats")] replay_policy: rsigma_runtime::ReplayPolicy,
    #[cfg(feature = "daemon-nats")] consumer_group: Option<String>,
    allow_remote_include: bool,
    bloom_prefilter: bool,
    bloom_max_bytes: Option<usize>,
    #[cfg(feature = "daachorse-index")] cross_rule_ac: bool,
    enrichers_path: Option<PathBuf>,
    source_paths: Vec<PathBuf>,
    #[cfg(feature = "daemon-tls")] tls_args: TlsCliArgs,
) {
    use rsigma_eval::resolve_builtin_pipeline;

    // Daemon installs its own JSON subscriber unconditionally so that operators
    // get consistent structured logs regardless of CLI invocation flags.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let pipelines = crate::load_pipelines(&pipeline_paths);
    let event_filter = std::sync::Arc::new(crate::build_event_filter(jq, jsonpath));
    let parsed_input_format = parse_input_format(&input_format, &syslog_tz);

    let corr_config = crate::build_correlation_config(
        suppress,
        action,
        no_detections,
        correlation_event_mode,
        max_correlation_events,
        timestamp_fields,
        &timestamp_fallback,
    );

    let addr: std::net::SocketAddr = api_addr.parse().unwrap_or_else(|e| {
        eprintln!("Invalid API address '{api_addr}': {e}");
        process::exit(exit_code::CONFIG_ERROR);
    });

    #[cfg(feature = "daemon-tls")]
    let tls_state = build_tls_state(&tls_args, addr);

    #[cfg(feature = "daemon-nats")]
    let nats_config = rsigma_runtime::NatsConnectConfig {
        credentials_file: nats_auth.nats_creds,
        token: nats_auth.nats_token,
        username: nats_auth.nats_user,
        password: nats_auth.nats_password,
        nkey: nats_auth.nats_nkey,
        tls_client_cert: nats_auth.nats_tls_cert,
        tls_client_key: nats_auth.nats_tls_key,
        require_tls: nats_auth.nats_require_tls,
        ..Default::default()
    };

    let file_pipeline_paths: Vec<PathBuf> = pipeline_paths
        .into_iter()
        .filter(|p| resolve_builtin_pipeline(p.to_str().unwrap_or("")).is_none())
        .collect();

    // Load external sources and build the daemon-wide registry.
    let external_sources = rsigma_runtime::sources::registry::load_external_sources(&source_paths)
        .unwrap_or_else(|e| {
            eprintln!("Error loading external sources: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        });

    let pipeline_sources: Vec<_> = pipelines
        .iter()
        .flat_map(|p| {
            p.sources
                .iter()
                .map(|s| (s.clone(), p.name.clone()))
                .collect::<Vec<_>>()
        })
        .collect();

    if !pipeline_sources.is_empty() {
        for p in &pipelines {
            if !p.sources.is_empty() {
                tracing::warn!(
                    pipeline = %p.name,
                    "pipeline declares inline 'sources:' block, which is deprecated; \
                     use '--source <file>' instead. Run 'rsigma rule migrate-sources' \
                     to extract sources into a standalone file."
                );
            }
        }
    }

    let source_registry = rsigma_runtime::sources::registry::DaemonSourceRegistry::new(
        external_sources,
        pipeline_sources,
    )
    .unwrap_or_else(|e| {
        eprintln!("Source ID collision: {e}");
        process::exit(exit_code::CONFIG_ERROR);
    });

    let config = daemon::server::DaemonConfig {
        rules_path,
        pipelines,
        pipeline_paths: file_pipeline_paths,
        corr_config,
        include_event,
        pretty,
        api_addr: addr,
        event_filter,
        state_db,
        state_save_interval,
        input,
        output,
        buffer_size,
        batch_size,
        drain_timeout,
        dlq,
        input_format: parsed_input_format,
        #[cfg(feature = "daemon-nats")]
        nats_config,
        #[cfg(feature = "daemon-nats")]
        replay_policy,
        #[cfg(feature = "daemon-nats")]
        consumer_group,
        state_restore_mode,
        allow_remote_include,
        bloom_prefilter,
        bloom_max_bytes,
        #[cfg(feature = "daachorse-index")]
        cross_rule_ac,
        enrichers_path,
        source_registry,
        #[cfg(feature = "daemon-tls")]
        tls_state,
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("Failed to create Tokio runtime: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        });

    rt.block_on(daemon::run_daemon(config));
}

// ---------------------------------------------------------------------------
// Input format parsing
// ---------------------------------------------------------------------------

pub(crate) fn parse_input_format(format_str: &str, syslog_tz: &str) -> rsigma_runtime::InputFormat {
    use rsigma_runtime::InputFormat;
    use rsigma_runtime::input::SyslogConfig;

    let tz_secs = parse_tz_offset(syslog_tz);

    match format_str {
        "auto" => InputFormat::Auto(SyslogConfig {
            default_tz_offset_secs: tz_secs,
        }),
        "json" => InputFormat::Json,
        "syslog" => InputFormat::Syslog(SyslogConfig {
            default_tz_offset_secs: tz_secs,
        }),
        "plain" => InputFormat::Plain,
        #[cfg(feature = "logfmt")]
        "logfmt" => InputFormat::Logfmt,
        #[cfg(feature = "cef")]
        "cef" => InputFormat::Cef,
        other => {
            eprintln!("Unknown input format: '{other}'");
            eprintln!("Supported formats: auto, json, syslog, plain");
            #[cfg(feature = "logfmt")]
            eprintln!("  (with logfmt feature): logfmt");
            #[cfg(feature = "cef")]
            eprintln!("  (with cef feature): cef");
            process::exit(exit_code::CONFIG_ERROR);
        }
    }
}

/// Build the TLS state from CLI flags and enforce the
/// "no plaintext on non-loopback" policy. Returns `None` when TLS is not
/// requested. Exits with `CONFIG_ERROR` on validation failure so the
/// operator sees the problem before the daemon spins up.
#[cfg(feature = "daemon-tls")]
fn build_tls_state(args: &TlsCliArgs, addr: std::net::SocketAddr) -> Option<daemon::tls::TlsState> {
    use daemon::tls::{TlsCliConfig, TlsMinVersion, TlsState, enforce_plaintext_policy};

    match (args.cert.as_ref(), args.key.as_ref()) {
        (Some(cert), Some(key)) => {
            let min_version: TlsMinVersion = args.min_version.parse().unwrap_or_else(|e| {
                eprintln!("{e}");
                process::exit(exit_code::CONFIG_ERROR);
            });
            let cli_cfg = TlsCliConfig {
                cert_path: cert.clone(),
                key_path: key.clone(),
                key_password: args.key_password.clone(),
                client_ca_path: args.client_ca.clone(),
                min_version,
            };
            match TlsState::from_paths(cli_cfg) {
                Ok(state) => Some(state),
                Err(e) => {
                    eprintln!("Failed to initialize TLS: {e}");
                    process::exit(exit_code::CONFIG_ERROR);
                }
            }
        }
        (None, None) => {
            if let Err(msg) = enforce_plaintext_policy(addr, args.allow_plaintext) {
                eprintln!("{msg}");
                process::exit(exit_code::CONFIG_ERROR);
            }
            None
        }
        _ => {
            // clap's `requires` should make this unreachable, but guard
            // anyway in case the validator is bypassed (e.g. tests).
            eprintln!("--tls-cert and --tls-key must be supplied together");
            process::exit(exit_code::CONFIG_ERROR);
        }
    }
}

/// Parse a timezone offset string like "+05:00" or "-08:00" into seconds east of UTC.
fn parse_tz_offset(s: &str) -> i32 {
    let s = s.trim();
    if s == "UTC" || s == "utc" || s == "Z" || s == "+00:00" {
        return 0;
    }

    let (sign, rest) = if let Some(rest) = s.strip_prefix('+') {
        (1i32, rest)
    } else if let Some(rest) = s.strip_prefix('-') {
        (-1i32, rest)
    } else {
        eprintln!("Invalid timezone offset: '{s}' (expected +HH:MM or -HH:MM)");
        process::exit(exit_code::CONFIG_ERROR);
    };

    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() != 2 {
        eprintln!("Invalid timezone offset: '{s}' (expected +HH:MM or -HH:MM)");
        process::exit(exit_code::CONFIG_ERROR);
    }

    let hours: i32 = parts[0].parse().unwrap_or_else(|_| {
        eprintln!("Invalid timezone offset hours: '{}'", parts[0]);
        process::exit(exit_code::CONFIG_ERROR);
    });
    let minutes: i32 = parts[1].parse().unwrap_or_else(|_| {
        eprintln!("Invalid timezone offset minutes: '{}'", parts[1]);
        process::exit(exit_code::CONFIG_ERROR);
    });

    sign * (hours * 3600 + minutes * 60)
}
