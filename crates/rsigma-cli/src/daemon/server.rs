use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

use arc_swap::ArcSwap;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rsigma_eval::{
    CorrelationConfig, MatchDetailLevel, OnUnknown, Pipeline, ProcessResult, RoutingPlan,
    load_schema_config,
};
use rsigma_runtime::{
    AckToken, AlertPipeline, AlertPipelineState, DeliveryConfig, DeliveryFailure, Dispatcher,
    EnrichmentPipeline, FieldObserver, FileSink, IncidentEnvelope, IncludeMode, InputFormat,
    LogProcessor, MetricsHook, OnFull, RawEvent, RiskLayer, RiskState, RoutingSpec, RuntimeEngine,
    SchemaClassifier, SchemaObserver, Silence, SilenceOrigin, SilenceSpec, Sink, StdinSource,
    StdoutSink, build_alert_pipeline, build_risk_layer, load_alert_pipeline_file, load_risk_file,
    load_schema_signatures, spawn_source,
};
use serde::Serialize;
use tokio::sync::mpsc;
use tower_http::trace::TraceLayer;
#[cfg(feature = "daemon-otlp")]
use tracing::Instrument;

/// A dead-letter queue entry for events that fail processing.
#[derive(Serialize)]
struct DlqEntry {
    original_event: String,
    error: String,
    timestamp: String,
}

use super::health::HealthState;
use super::listen::ListenAddr;
use super::metrics::Metrics;
use super::reload;
use super::store::{SourcePosition, SqliteStateStore};
use crate::EventFilter;

/// The bound API listener: a TCP socket, or a Unix domain socket on Unix.
enum BoundListener {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

/// Effective live event-tap limits, resolved from `daemon.tap.*` plus the
/// `--enable-tap` flag.
#[derive(Debug, Clone, Copy)]
pub struct TapSettings {
    /// Whether the tap accepts sessions. `false` makes `GET /api/v1/tap`
    /// return `503`.
    pub enabled: bool,
    /// Per-session bounded channel capacity.
    pub buffer_events: usize,
    /// Maximum concurrent capture sessions.
    pub max_sessions: usize,
    /// Largest accepted capture window.
    pub max_duration: std::time::Duration,
}

/// Effective live detection-tail limits, resolved from `daemon.tail.*` plus the
/// `--enable-tail` flag.
#[derive(Debug, Clone, Copy)]
pub struct TailSettings {
    /// Whether the tail accepts sessions. `false` makes
    /// `GET /api/v1/detections/stream` return `503`.
    pub enabled: bool,
    /// Per-session bounded channel capacity.
    pub buffer_events: usize,
    /// Maximum concurrent tail sessions.
    pub max_sessions: usize,
}

/// Effective triage-feedback settings, resolved from `daemon.dispositions.*`
/// plus the `--enable-dispositions` flag.
#[derive(Debug, Clone)]
pub struct DispositionSettings {
    /// Whether the disposition endpoints and the per-rule ratio are active.
    pub enabled: bool,
    /// Optional pull source spec (a `--source`-style file). `None` is
    /// endpoint-only ingest.
    pub source: Option<PathBuf>,
    /// The rolling-store configuration (window, numerator, min sample).
    pub config: rsigma_runtime::DispositionConfig,
}

/// Controls whether correlation state is restored from SQLite on startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateRestoreMode {
    /// Decide automatically. For NATS replay, compare the replay start point
    /// against the stored source position: restore when replaying forward,
    /// skip when replaying backward. For non-NATS and Resume, always restore.
    Auto,
    /// Unconditionally clear state (`--clear-state`).
    ForceClear,
    /// Unconditionally restore state (`--keep-state`).
    ForceKeep,
}

#[derive(Clone)]
struct AppState {
    processor: Arc<LogProcessor>,
    metrics: Arc<Metrics>,
    health: HealthState,
    reload_tx: mpsc::Sender<()>,
    start_time: Instant,
    /// Channel for HTTP event ingestion. Set when --input is http.
    event_tx: Option<mpsc::Sender<RawEvent>>,
    /// Channel for on-demand source resolution triggers.
    sources_trigger_tx: Option<mpsc::Sender<rsigma_runtime::sources::refresh::RefreshTrigger>>,
    /// The instrumented source resolver (provides cache access for invalidation API).
    source_resolver: Option<Arc<super::instrumented_resolver::InstrumentedResolver>>,
    /// Channel for OTLP event ingestion. Always set when daemon-otlp is compiled in.
    #[cfg(feature = "daemon-otlp")]
    otlp_event_tx: mpsc::Sender<RawEvent>,
    /// The daemon-wide source registry for API endpoints.
    source_registry: Arc<rsigma_runtime::sources::registry::DaemonSourceRegistry>,
    /// Opt-in field observer. `Some` when the daemon was started with
    /// `--observe-fields`; the engine task records observed field keys
    /// and the `/api/v1/fields/*` handlers (Phase 4) consume snapshots.
    field_observer: Option<Arc<FieldObserver>>,
    /// Opt-in schema observer. `Some` when the daemon was started with
    /// `--observe-schemas`; the engine task classifies each event and the
    /// `GET /api/v1/schemas` handler serves snapshots.
    schema_observer: Option<Arc<SchemaObserver>>,
    /// Live event-tap state. `Some` when the tap is enabled; the
    /// `GET /api/v1/tap` handler registers capture sessions on it.
    tap: Option<super::tap::TapState>,
    /// Live detection-tail state. `Some` when the tail is enabled; the
    /// `GET /api/v1/detections/stream` handler registers sessions on it.
    tail: Option<super::tail::TailState>,
    /// The alert-pipeline config swap, read by `GET /api/v1/incidents` to
    /// resolve the incident include mode.
    alert_pipeline_swap: Arc<ArcSwap<Option<Arc<AlertPipeline>>>>,
    /// Mutable alert-pipeline state (incidents + silences), shared with the
    /// sink task. Read by `/api/v1/incidents` and read/written by
    /// `/api/v1/silences`.
    alert_state: Arc<std::sync::RwLock<AlertPipelineState>>,
    /// The risk-layer config swap, read by `GET /api/v1/risk` to resolve the
    /// accumulation window for the open-entity view.
    risk_swap: Arc<ArcSwap<Option<Arc<RiskLayer>>>>,
    /// Mutable per-entity risk-accumulator state, shared with the sink task.
    /// Read by `GET /api/v1/risk`.
    risk_state: Arc<std::sync::RwLock<RiskState>>,
    /// Triage feedback loop. `Some` when `--enable-dispositions` (or
    /// `daemon.dispositions.enabled`) is set; the `/api/v1/dispositions`
    /// handlers ingest verdicts and serve the per-rule ratio view.
    disposition_state: Option<super::dispositions::DispositionState>,
}

#[derive(Clone)]
pub struct DaemonConfig {
    pub rules_path: PathBuf,
    pub pipelines: Vec<Pipeline>,
    pub pipeline_paths: Vec<PathBuf>,
    pub corr_config: CorrelationConfig,
    pub include_event: bool,
    pub pretty: bool,
    pub api_addr: super::listen::ListenAddr,
    pub event_filter: Arc<EventFilter>,
    pub state_db: Option<PathBuf>,
    pub state_save_interval: u64,
    pub input: String,
    pub output: Vec<String>,
    pub buffer_size: usize,
    pub batch_size: usize,
    /// Shared async delivery tuning applied to every sink worker.
    pub delivery_config: DeliveryConfig,
    pub dlq: Option<String>,
    #[cfg(feature = "daemon-nats")]
    pub nats_config: rsigma_runtime::NatsConnectConfig,
    #[cfg(feature = "daemon-nats")]
    pub replay_policy: rsigma_runtime::ReplayPolicy,
    #[cfg(feature = "daemon-nats")]
    pub consumer_group: Option<String>,
    pub state_restore_mode: StateRestoreMode,
    pub drain_timeout: u64,
    pub input_format: InputFormat,
    pub allow_remote_include: bool,
    /// Enable opt-in bloom-filter pre-filtering of positive substring
    /// matchers. Off by default; benefit is workload-dependent.
    pub bloom_prefilter: bool,
    /// Match-detail verbosity forwarded to the inner detection engine.
    /// `Off` by default (historical wire shape).
    pub match_detail: MatchDetailLevel,
    /// Optional override for the bloom memory budget (bytes). `None` means
    /// the crate default (1 MB).
    pub bloom_max_bytes: Option<usize>,
    /// Enable the opt-in field observer that counts every event's field
    /// keys so the `/api/v1/fields/*` endpoints can surface gap and
    /// broken-coverage signals. Off by default; when off the engine
    /// task does not iterate `Event::field_keys` at all.
    pub observe_fields: bool,
    /// Hard ceiling on the number of distinct field names tracked by
    /// the field observer. Once the ceiling is reached, new keys are
    /// dropped (and counted via
    /// `rsigma_fields_observer_overflow_dropped_total`); existing keys
    /// keep incrementing.
    pub observe_fields_max_keys: usize,
    /// Enable the opt-in schema observer that classifies every event so the
    /// `GET /api/v1/schemas` endpoint and the
    /// `rsigma_events_by_schema_total` / `rsigma_events_unknown_schema_total`
    /// counters can surface the schema mix and unknown rate. Off by default.
    pub observe_schemas: bool,
    /// Enable the discovery sampler: record redacted shapes of unrecognized
    /// (no-match or `generic_json`) events so `GET /api/v1/schemas/suggestions`
    /// can mine them into candidate signatures. Implies `observe_schemas`.
    pub discover_schemas: bool,
    /// Optional path to a YAML file of user-defined schema signatures (and,
    /// with `schema_routing`, the routing bindings), merged over the built-ins.
    pub schema_config: Option<PathBuf>,
    /// Enable schema routing: classify each event and route it to the
    /// pipeline-set bound to its schema, feeding a single shared correlation
    /// store. Bindings come from the `routing:` section of `schema_config`.
    pub schema_routing: bool,
    /// Opt-in, gated per-schema rule partitioning: compile each platform-locked
    /// per-schema engine with only the rules whose product can apply, cutting
    /// the N-copies memory cost. Off by default.
    pub schema_partition_rules: bool,
    /// Override for the `on_unknown` policy (`warn`/`drop`/`passthrough`/`error`).
    pub on_unknown: Option<String>,
    /// Enable conflict-based logsource pruning on the detection engine(s).
    pub logsource_routing: bool,
    /// Event field-name map for logsource extraction, as
    /// `product=...,service=...,category=...`. `None` uses the literal names.
    pub logsource_field_map: Option<String>,
    /// Static event logsource applied when the field is absent, as
    /// `product=windows,...`, for a single-source pipeline.
    pub event_logsource: Option<String>,
    /// Enable the cross-rule Aho-Corasick pre-filter. Off by default;
    /// benefit is workload-dependent (large rule sets with shared
    /// substring patterns). Available behind the `daachorse-index`
    /// Cargo feature.
    #[cfg(feature = "daachorse-index")]
    pub cross_rule_ac: bool,
    /// Optional path to the enrichers config (from `--enrichers`). Read
    /// at daemon startup and again on hot-reload (SIGHUP / file watcher
    /// / `POST /api/v1/reload`); failures during reload are logged and
    /// the previous pipeline stays active.
    pub enrichers_path: Option<PathBuf>,
    /// Optional path to the alert-pipeline config (from `--alert-pipeline`).
    /// Read at daemon startup and again on hot-reload; failures during
    /// reload are logged and the previous pipeline stays active.
    pub alert_pipeline_path: Option<PathBuf>,
    /// Optional path to the risk-based alerting config (from `--risk`). Read at
    /// daemon startup and again on hot-reload; failures during reload are
    /// logged and the previous config stays active.
    pub risk_path: Option<PathBuf>,
    /// Webhook config file/dir paths (from `--webhook`). Loaded and validated
    /// once at daemon startup, then built into lossy (`on_full=drop`) delivery
    /// leaves. Hot reload is not supported in v1.
    pub webhook_paths: Vec<PathBuf>,
    /// Daemon-scoped source registry built from `--source` flags and
    /// pipeline-embedded `sources:` blocks. Collision-checked at
    /// construction time.
    pub source_registry: rsigma_runtime::sources::registry::DaemonSourceRegistry,
    /// Effective live event-tap limits (`daemon.tap.*` + `--enable-tap`).
    pub tap: TapSettings,
    /// Effective live detection-tail limits (`daemon.tail.*` + `--enable-tail`).
    pub tail: TailSettings,
    /// Effective triage-feedback settings (`daemon.dispositions.*` +
    /// `--enable-dispositions`).
    pub dispositions: DispositionSettings,
    /// Optional API authentication table (`daemon.api.auth` +
    /// `--api-token-env`). `None` mounts the routes without auth, as before.
    pub api_auth: Option<super::auth::ApiAuth>,
    /// Optional server-side TLS state. `Some` when the operator passed
    /// `--tls-cert`/`--tls-key`; the daemon then terminates TLS on the
    /// API listener for HTTP REST, OTLP/HTTP, and OTLP/gRPC.
    #[cfg(feature = "daemon-tls")]
    pub tls_state: Option<super::tls::TlsState>,
}

pub async fn run_daemon(config: DaemonConfig) {
    let metrics = Arc::new(Metrics::new());
    let health = HealthState::new();

    // The enrichment pipeline is constructed below, after the dynamic
    // source resolver exists, so `lookup` enrichers can share the
    // resolver's `Arc<SourceCache>`. We hoist the `ArcSwap` here so
    // the sink task closure can capture it directly.
    let enrichment_metrics = metrics.clone() as Arc<dyn rsigma_runtime::MetricsHook>;
    let enrichment_swap: Arc<ArcSwap<Option<Arc<EnrichmentPipeline>>>> =
        Arc::new(ArcSwap::new(Arc::new(None)));

    // The alert pipeline (dedup and, in later stages, grouping / silencing /
    // inhibition) runs in the sink task after enrichment. Hoisted here so the
    // sink task and the reload task can both capture the `ArcSwap`.
    let alert_pipeline_swap: Arc<ArcSwap<Option<Arc<AlertPipeline>>>> =
        Arc::new(ArcSwap::new(Arc::new(None)));

    // Mutable alert-pipeline state (dedup, incidents, silences). Owned by the
    // sink task but shared behind an `RwLock` so the `/api/v1/incidents` and
    // `/api/v1/silences` handlers can read and mutate it.
    let alert_state: Arc<std::sync::RwLock<AlertPipelineState>> =
        Arc::new(std::sync::RwLock::new(AlertPipelineState::default()));

    // The risk layer (annotation and, in the incident layer, the per-entity
    // accumulator) runs in the sink task after enrichment and before the alert
    // pipeline. Hoisted here so the sink task and the reload task can both
    // capture the `ArcSwap`.
    let risk_swap: Arc<ArcSwap<Option<Arc<RiskLayer>>>> = Arc::new(ArcSwap::new(Arc::new(None)));

    // Mutable per-entity risk-accumulator state. Owned by the sink task but
    // shared behind an `RwLock` so the `GET /api/v1/risk` handler can read the
    // open entities.
    let risk_state: Arc<std::sync::RwLock<RiskState>> =
        Arc::new(std::sync::RwLock::new(RiskState::default()));

    // Open SQLite state store if configured
    let state_store = config.state_db.as_ref().map(|path| {
        let store = SqliteStateStore::open(path).unwrap_or_else(|e| {
            tracing::error!(error = %e, path = %path.display(), "Failed to open state database");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        });
        tracing::info!(path = %path.display(), "State database opened");
        Arc::new(store)
    });

    let mut engine = RuntimeEngine::new(
        config.rules_path.clone(),
        config.pipelines.clone(),
        config.corr_config.clone(),
        config.include_event,
    );
    engine.set_pipeline_paths(config.pipeline_paths.clone());
    engine.set_allow_remote_include(config.allow_remote_include);
    engine.set_match_detail(config.match_detail);
    engine.set_bloom_prefilter(config.bloom_prefilter);
    if let Some(budget) = config.bloom_max_bytes {
        engine.set_bloom_max_bytes(budget);
    }
    #[cfg(feature = "daachorse-index")]
    engine.set_cross_rule_ac(config.cross_rule_ac);

    if config.schema_routing {
        engine.set_routing(Some(build_routing_spec(
            config.schema_config.as_deref(),
            config.on_unknown.as_deref(),
            config.schema_partition_rules,
        )));
        tracing::info!("Schema routing enabled");
    }

    if config.logsource_routing {
        // The daemon ingests streams (no per-input EVTX detection), so the
        // format-derived default never applies here; it is an eval-only path.
        match crate::logsource_opts::build_logsource_extractor(
            true,
            config.logsource_field_map.as_deref(),
            config.event_logsource.as_deref(),
            false,
        ) {
            Ok(extractor) => {
                engine.set_logsource_extractor(extractor);
                tracing::info!("Logsource routing enabled");
            }
            Err(e) => {
                eprintln!("Error in logsource routing options: {e}");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
    }

    // Set up dynamic source resolver if the registry has sources or any
    // pipeline references external sources.
    let has_dynamic =
        !config.source_registry.is_empty() || config.pipelines.iter().any(|p| p.is_dynamic());
    let mut sources_trigger_tx_val: Option<
        mpsc::Sender<rsigma_runtime::sources::refresh::RefreshTrigger>,
    > = None;

    let mut source_resolver_val: Option<Arc<super::instrumented_resolver::InstrumentedResolver>> =
        None;

    if has_dynamic {
        let instrumented = Arc::new(super::instrumented_resolver::InstrumentedResolver::new(
            metrics.clone(),
        ));
        source_resolver_val = Some(instrumented.clone());
        let resolver: Arc<dyn rsigma_runtime::sources::SourceResolver> = instrumented;
        engine.set_source_resolver(resolver.clone());

        // Feed the engine the external source declarations so it can resolve
        // and expand `${source.*}` references in the pipelines.
        engine.set_external_sources(
            config
                .source_registry
                .sources()
                .into_iter()
                .cloned()
                .collect(),
        );

        // Resolve dynamic sources at startup (blocks on required sources)
        if let Err(e) = engine.resolve_dynamic_pipelines().await {
            tracing::error!(error = %e, "Failed to resolve required dynamic sources at startup");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }

        // Resolve external (registry-only) sources at startup
        let registry_only_sources: Vec<_> = config
            .source_registry
            .entries()
            .iter()
            .filter(|e| {
                matches!(
                    e.origin,
                    rsigma_runtime::sources::registry::SourceOrigin::External(_)
                )
            })
            .map(|e| e.source.clone())
            .collect();
        if !registry_only_sources.is_empty() {
            match rsigma_runtime::sources::resolve_all(&*resolver, &registry_only_sources).await {
                Ok(_) => {
                    tracing::info!(
                        count = registry_only_sources.len(),
                        "External sources resolved at startup"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to resolve required external sources at startup");
                    std::process::exit(crate::exit_code::CONFIG_ERROR);
                }
            }
        }

        // Collect all dynamic sources for the refresh scheduler: unified
        // registry instead of iterating pipelines.
        let all_sources: Vec<_> = config
            .source_registry
            .sources()
            .into_iter()
            .cloned()
            .collect();

        if !all_sources.is_empty() {
            let scheduler = rsigma_runtime::sources::refresh::RefreshScheduler::new();
            sources_trigger_tx_val = Some(scheduler.trigger_sender());

            // Spawn NATS control subject listener for remote re-resolution triggers
            #[cfg(feature = "daemon-nats")]
            {
                let nats_url = config.nats_config.url.clone();
                let trigger_tx = scheduler.trigger_sender();
                tokio::spawn(async move {
                    let subject = rsigma_runtime::sources::refresh::NATS_CONTROL_SUBJECT;
                    if let Err(e) = rsigma_runtime::sources::refresh::nats_control_loop(
                        &nats_url, subject, trigger_tx,
                    )
                    .await
                    {
                        tracing::warn!(
                            error = %e,
                            "NATS control subject listener failed"
                        );
                    }
                });
            }

            // Collect optional source IDs for background retry
            let optional_source_ids: Vec<String> = all_sources
                .iter()
                .filter(|s| !s.required)
                .map(|s| s.id.clone())
                .collect();

            let bg_trigger_tx = scheduler.trigger_sender();
            scheduler.run(all_sources, resolver);

            // Spawn background retry for optional sources that may have failed at startup
            if !optional_source_ids.is_empty() {
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    for id in optional_source_ids {
                        let _ = bg_trigger_tx
                            .send(rsigma_runtime::sources::refresh::RefreshTrigger::Single(id))
                            .await;
                    }
                });
            }
        }
    }

    let processor = Arc::new(LogProcessor::new(engine, metrics.clone()));

    // Initial rule load
    match processor.reload_rules() {
        Ok(stats) => {
            tracing::info!(
                detection_rules = stats.detection_rules,
                correlation_rules = stats.correlation_rules,
                path = %config.rules_path.display(),
                "Rules loaded"
            );
            metrics
                .detection_rules_loaded
                .set(stats.detection_rules as i64);
            metrics
                .correlation_rules_loaded
                .set(stats.correlation_rules as i64);
            health.set_ready(true);
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to load initial rules");
            std::process::exit(crate::exit_code::RULE_ERROR);
        }
    }

    // Restore correlation state from SQLite (after rules are loaded).
    //
    // The decision depends on `state_restore_mode`:
    // - ForceClear: always skip (--clear-state).
    // - ForceKeep: always restore (--keep-state).
    // - Auto: for NATS replay, compare the replay start point against the
    //   stored source position to avoid double-counting when replaying
    //   backward, while preserving cross-boundary correlations when
    //   replaying forward. For non-NATS and Resume, always restore.
    // Whether to restore persisted state on boot. `--clear-state` never
    // restores; the correlation block below refines this for the NATS
    // backward-replay case. The alert-pipeline restore reuses the decision.
    let mut restore_state = config.state_restore_mode != StateRestoreMode::ForceClear;
    if let Some(ref store) = state_store {
        match store.load().await {
            Ok(Some((snapshot, stored_position))) => {
                let should_restore = decide_state_restore(
                    config.state_restore_mode,
                    stored_position,
                    #[cfg(feature = "daemon-nats")]
                    &config.replay_policy,
                );
                restore_state = should_restore;
                if should_restore {
                    if processor.import_state(&snapshot) {
                        let entries = snapshot.windows.values().map(|g| g.len()).sum::<usize>();
                        tracing::info!(
                            state_entries = entries,
                            "Correlation state restored from database"
                        );
                    } else {
                        tracing::warn!(
                            snapshot_version = snapshot.version,
                            "Incompatible snapshot version, starting with fresh state"
                        );
                    }
                } else {
                    tracing::info!("Correlation state cleared (not restoring)");
                }
            }
            Ok(None) => {
                tracing::info!("No previous correlation state found in database");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load state from database, starting fresh");
            }
        }
    }

    // Build the post-evaluation enrichment pipeline now that the
    // dynamic source resolver (if any) has been constructed; `lookup`
    // enrichers share the resolver's `Arc<SourceCache>` so they read
    // from the same cache the resolver writes into. Failures here exit
    // cleanly because no I/O has started yet.
    let initial_source_cache = source_resolver_val.as_ref().map(|r| r.arc_cache());
    if let Some(path) = config.enrichers_path.as_ref() {
        match super::enrichment::load_enrichers_file(path).and_then(|file| {
            super::enrichment::build_enrichers_full(
                file,
                initial_source_cache.clone(),
                enrichment_metrics.clone(),
            )
        }) {
            Ok(p) => {
                tracing::info!(
                    enrichers = p.len(),
                    path = %path.display(),
                    "Enrichment pipeline loaded"
                );
                enrichment_swap.store(Arc::new(Some(Arc::new(p))));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to build enrichment pipeline");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
    }

    // Build the alert pipeline. Failures exit cleanly because no I/O has
    // started yet.
    if let Some(path) = config.alert_pipeline_path.as_ref() {
        match load_alert_pipeline_file(path).and_then(build_alert_pipeline) {
            Ok(pipeline) => {
                tracing::info!(path = %path.display(), "Alert pipeline loaded");
                if let Ok(mut state) = alert_state.write() {
                    state
                        .silences
                        .set_static(pipeline.static_silences().to_vec());
                }
                // Restore persisted alert-pipeline state (unless --clear-state),
                // pruning entries past their window at boot.
                if restore_state && let Some(ref store) = state_store {
                    match store.load_alert_pipeline().await {
                        Ok(Some(snap)) => {
                            let now = chrono::Utc::now().timestamp();
                            let restored = alert_state
                                .write()
                                .map(|mut state| pipeline.restore(&mut state, snap, now))
                                .unwrap_or(false);
                            if restored {
                                tracing::info!("Alert-pipeline state restored from database");
                            } else {
                                tracing::warn!(
                                    "Incompatible alert-pipeline snapshot version, starting fresh"
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to load alert-pipeline state");
                        }
                    }
                }
                alert_pipeline_swap.store(Arc::new(Some(Arc::new(pipeline))));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to build alert pipeline");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
    }

    // Build the risk layer. Failures exit cleanly because no I/O has started yet.
    if let Some(path) = config.risk_path.as_ref() {
        match load_risk_file(path).and_then(build_risk_layer) {
            Ok(layer) => {
                tracing::info!(path = %path.display(), "Risk layer loaded");
                // Restore persisted risk state (unless --clear-state), pruning
                // entries past their window at boot.
                if restore_state && let Some(ref store) = state_store {
                    match store.load_risk().await {
                        Ok(Some(snap)) => {
                            let now = chrono::Utc::now().timestamp();
                            let restored = risk_state
                                .write()
                                .map(|mut state| layer.restore(&mut state, snap, now))
                                .unwrap_or(false);
                            if restored {
                                tracing::info!("Risk state restored from database");
                            } else {
                                tracing::warn!(
                                    "Incompatible risk snapshot version, starting fresh"
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to load risk state");
                        }
                    }
                }
                risk_swap.store(Arc::new(Some(Arc::new(layer))));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to build risk layer");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
    }

    // Bounded channel acts as backpressure for reload requests. Capacity 4
    // allows the file watcher, SIGHUP handler, and HTTP endpoint to queue
    // reloads without blocking, while the consumer debounces with a 500ms
    // sleep + try_recv drain, collapsing bursts into a single reload.
    let (reload_tx, mut reload_rx) = mpsc::channel::<()>(4);

    // File watcher for hot-reload (rules + pipeline files)
    let pipeline_watch_paths: Vec<&std::path::Path> =
        config.pipeline_paths.iter().map(|p| p.as_path()).collect();
    let _watcher = if config.rules_path.is_dir() {
        reload::spawn_file_watcher(&config.rules_path, &pipeline_watch_paths, reload_tx.clone())
    } else {
        reload::spawn_file_watcher(
            config.rules_path.parent().unwrap_or(&config.rules_path),
            &pipeline_watch_paths,
            reload_tx.clone(),
        )
    };

    let start_time = Instant::now();

    // Create event channel early so both source and HTTP handler can use it
    let buffer_size = config.buffer_size;
    let (event_tx, mut event_rx) = mpsc::channel::<RawEvent>(buffer_size);

    let http_event_tx = if config.input == "http" {
        Some(event_tx.clone())
    } else {
        None
    };

    #[cfg(feature = "daemon-otlp")]
    let otlp_event_tx = event_tx.clone();

    let field_observer = if config.observe_fields {
        let observer = Arc::new(FieldObserver::new(config.observe_fields_max_keys));
        processor.set_field_observer(Some(observer.clone()));
        tracing::info!(
            max_keys = config.observe_fields_max_keys,
            "Field observer enabled"
        );
        Some(observer)
    } else {
        None
    };

    // `--discover-schemas` implies `--observe-schemas`: the discovery sampler
    // rides on the same observer.
    let schema_observer = if config.observe_schemas || config.discover_schemas {
        let classifier = match &config.schema_config {
            Some(path) => match load_schema_signatures(path) {
                Ok(sigs) => SchemaClassifier::with_user_signatures(sigs),
                Err(e) => {
                    tracing::error!(error = %e, "Failed to load schema signatures; using built-ins only");
                    SchemaClassifier::builtin()
                }
            },
            None => SchemaClassifier::builtin(),
        };
        let observer = Arc::new(SchemaObserver::new_with_discovery(
            classifier,
            config.discover_schemas,
        ));
        processor.set_schema_observer(Some(observer.clone()));
        if config.discover_schemas {
            tracing::info!(
                "Schema observer + discovery sampler enabled (GET /api/v1/schemas, \
                 GET /api/v1/schemas/suggestions)"
            );
        } else {
            tracing::info!("Schema observer enabled (GET /api/v1/schemas)");
        }
        Some(observer)
    } else {
        None
    };

    let tap = if config.tap.enabled {
        let registry = rsigma_runtime::TapRegistry::new(
            config.tap.buffer_events,
            config.tap.max_sessions,
            config.tap.max_duration,
        );
        processor.set_event_tap(Some(registry.clone()));
        tracing::info!(
            buffer_events = config.tap.buffer_events,
            max_sessions = config.tap.max_sessions,
            max_duration_secs = config.tap.max_duration.as_secs(),
            "Live event tap enabled (GET /api/v1/tap)"
        );
        Some(super::tap::TapState::new(registry, metrics.clone()))
    } else {
        None
    };

    let (tail, tail_registry) = if config.tail.enabled {
        let registry =
            super::tail::TailRegistry::new(config.tail.buffer_events, config.tail.max_sessions);
        tracing::info!(
            buffer_events = config.tail.buffer_events,
            max_sessions = config.tail.max_sessions,
            "Live detection tail enabled (GET /api/v1/detections/stream)"
        );
        (
            Some(super::tail::TailState::new(
                registry.clone(),
                metrics.clone(),
            )),
            Some(registry),
        )
    } else {
        (None, None)
    };

    // Triage feedback loop: build the shared disposition store when enabled.
    // Shares the alert-pipeline state so `scope: incident` verdicts resolve to
    // their contributing rules through the live incident map.
    let disposition_state = if config.dispositions.enabled {
        tracing::info!("Triage feedback loop enabled (POST/GET /api/v1/dispositions)");
        let state = super::dispositions::DispositionState::new(
            config.dispositions.config.clone(),
            metrics.clone(),
            alert_state.clone(),
        );
        // Roll the window forward for idle rules on a timer.
        state.spawn_pruner();
        // Restore persisted disposition state (unless --clear-state), pruning
        // buckets past the window at boot.
        if restore_state && let Some(ref store) = state_store {
            match store.load_dispositions().await {
                Ok(Some(snap)) => {
                    let now = chrono::Utc::now().timestamp();
                    if state.restore(snap, now) {
                        tracing::info!("Disposition state restored from database");
                    } else {
                        tracing::warn!("Incompatible disposition snapshot version, starting fresh");
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "Failed to load disposition state"),
            }
        }
        // Optional pull source: load the declared dynamic source(s) and ingest
        // each refreshed payload as dispositions over the Phase 0 seam.
        if let Some(src_path) = config.dispositions.source.as_ref() {
            match rsigma_runtime::sources::registry::load_external_sources(std::slice::from_ref(
                src_path,
            )) {
                Ok(loaded) => {
                    let sources: Vec<_> = loaded.into_iter().map(|(s, _)| s).collect();
                    if sources.is_empty() {
                        tracing::warn!(
                            path = %src_path.display(),
                            "Disposition source declared no sources"
                        );
                    } else {
                        tracing::info!(
                            path = %src_path.display(),
                            count = sources.len(),
                            "Disposition pull source loaded"
                        );
                        state.spawn_source(sources);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        path = %src_path.display(),
                        "Failed to load disposition source"
                    );
                    std::process::exit(crate::exit_code::CONFIG_ERROR);
                }
            }
        }
        Some(state)
    } else {
        None
    };
    // A handle for the periodic and shutdown state savers (the field itself is
    // moved into `AppState` below).
    let disposition_state_for_save = disposition_state.clone();

    let app_state = AppState {
        processor: processor.clone(),
        metrics: metrics.clone(),
        health: health.clone(),
        reload_tx: reload_tx.clone(),
        start_time,
        event_tx: http_event_tx,
        sources_trigger_tx: sources_trigger_tx_val.clone(),
        source_resolver: source_resolver_val,
        #[cfg(feature = "daemon-otlp")]
        otlp_event_tx,
        source_registry: Arc::new(config.source_registry.clone()),
        field_observer: field_observer.clone(),
        schema_observer: schema_observer.clone(),
        tap: tap.clone(),
        tail: tail.clone(),
        alert_pipeline_swap: alert_pipeline_swap.clone(),
        alert_state: alert_state.clone(),
        risk_swap: risk_swap.clone(),
        risk_state: risk_state.clone(),
        disposition_state,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .route("/api/v1/rules", get(list_rules))
        .route("/api/v1/status", get(status))
        .route("/api/v1/correlations", get(list_correlations))
        .route("/api/v1/correlations/state", get(correlations_state))
        .route("/api/v1/incidents", get(list_incidents))
        .route("/api/v1/risk", get(list_risk_entities))
        .route("/api/v1/silences", get(list_silences).post(create_silence))
        .route("/api/v1/silences/{id}", delete(delete_silence))
        .route(
            "/api/v1/dispositions",
            get(list_dispositions).post(ingest_dispositions),
        )
        .route("/api/v1/reload", post(trigger_reload))
        .route("/api/v1/events", post(ingest_events))
        .route("/api/v1/sources", get(list_sources))
        .route("/api/v1/sources/resolve", post(resolve_sources))
        .route(
            "/api/v1/sources/resolve/{source_id}",
            post(resolve_source_by_id),
        )
        .route(
            "/api/v1/sources/cache/{source_id}",
            delete(invalidate_source_cache),
        )
        .route("/api/v1/fields", get(fields_full))
        .route("/api/v1/fields/unknown", get(fields_unknown))
        .route("/api/v1/fields/missing", get(fields_missing))
        .route("/api/v1/fields/observer", delete(fields_observer_reset))
        .route("/api/v1/schemas", get(schemas_full).delete(schemas_reset))
        .route("/api/v1/schemas/suggestions", get(schema_suggestions))
        .route("/api/v1/tap", get(tap_stream))
        .route("/api/v1/detections/stream", get(detections_stream));

    #[cfg(feature = "daemon-otlp")]
    let app = app.route("/v1/logs", post(otlp_http_logs));

    // Bearer-token auth (opt-in). Mounted with `Router::route_layer` so it
    // runs only for matched routes (a 404 needs no credentials) and after
    // routing, where `MatchedPath` carries the route pattern into the
    // permission lookup. The TraceLayer added below wraps it, so rejected
    // requests are traced too. OTLP/gRPC does not pass through this layer;
    // the gRPC service checks its own request metadata (see
    // `OtlpLogsGrpcService::export`).
    let app = match config.api_auth.as_ref() {
        Some(auth) => {
            tracing::info!("API authentication enabled");
            let state = Arc::new(super::auth::AuthLayerState {
                auth: auth.clone(),
                metrics: metrics.clone(),
            });
            app.route_layer(axum::middleware::from_fn_with_state(
                state,
                super::auth::api_auth_middleware,
            ))
        }
        None => app,
    };

    let app = app.layer(TraceLayer::new_for_http()).with_state(app_state);

    // The UDS guard unlinks the socket file when `run_daemon` returns (after
    // the drain), so a clean shutdown leaves no stale socket behind.
    #[cfg(unix)]
    let mut _uds_guard: Option<rsigma_runtime::UnixSocketGuard> = None;
    let (bound, actual_addr) = match &config.api_addr {
        ListenAddr::Tcp(addr) => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(addr = %addr, error = %e, "Failed to bind API server");
                    std::process::exit(crate::exit_code::CONFIG_ERROR);
                });
            let actual = listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| addr.to_string());
            (BoundListener::Tcp(listener), actual)
        }
        #[cfg(unix)]
        ListenAddr::Unix(path) => {
            let (listener, guard) = rsigma_runtime::bind_unix_listener(path)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(path = %path.display(), error = %e, "Failed to bind API server unix socket");
                    std::process::exit(crate::exit_code::CONFIG_ERROR);
                });
            _uds_guard = Some(guard);
            (
                BoundListener::Unix(listener),
                format!("unix://{}", path.display()),
            )
        }
    };

    // Install the OS signal handlers eagerly, before the listener is
    // announced and reachable. The kernel completes the TCP handshake for
    // an incoming connection from the listen backlog the moment the socket
    // is bound, well before the serve task first polls its graceful-shutdown
    // future, so a SIGINT/SIGTERM arriving in that window would otherwise
    // hit the default disposition and kill the process. `signal()` registers
    // the handler at creation time (not on first poll like `ctrl_c()`), so
    // building the shutdown future here guarantees the handler is in place
    // before any client can observe the daemon as ready. The same streams
    // are moved into the serve task below, so a signal delivered during the
    // remaining setup is coalesced and still triggers a clean drain.
    let mut shutdown_fut: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> = {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
            let sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
            Some(Box::pin(shutdown_signal(sigint, sigterm)))
        }
        #[cfg(not(unix))]
        {
            Some(Box::pin(shutdown_signal()))
        }
    };

    #[cfg(feature = "daemon-otlp")]
    let otlp_routes = {
        let grpc_service = rsigma_runtime::LogsServiceServer::new(OtlpLogsGrpcService {
            event_tx: event_tx.clone(),
            metrics: metrics.clone(),
            auth: config.api_auth.clone(),
        })
        .accept_compressed(tonic::codec::CompressionEncoding::Gzip)
        .send_compressed(tonic::codec::CompressionEncoding::Gzip);
        tonic::service::Routes::from(app).add_service(grpc_service)
    };

    // TLS state is consumed below to build either a plaintext or TLS-wrapped
    // listener; pull it out of `config` here so the borrow ends before the
    // serve task captures the rest of the config by move.
    #[cfg(feature = "daemon-tls")]
    let tls_state = config.tls_state.clone();
    #[cfg(feature = "daemon-tls")]
    let tls_enabled = tls_state.is_some();
    #[cfg(not(feature = "daemon-tls"))]
    let tls_enabled = false;

    #[cfg(feature = "daemon-tls")]
    if let Some(ref state) = tls_state {
        update_tls_metrics(&metrics, state.expiry_unix.load(Ordering::Relaxed));
        warn_if_cert_expiring_soon(state.expiry_unix.load(Ordering::Relaxed));
    }

    #[cfg(feature = "daemon-otlp")]
    if tls_enabled {
        tracing::info!(addr = %actual_addr, "API server listening (HTTPS, HTTP/2 + gRPC)");
    } else {
        tracing::info!(addr = %actual_addr, "API server listening (HTTP/2 + gRPC)");
    }
    #[cfg(not(feature = "daemon-otlp"))]
    if tls_enabled {
        tracing::info!(addr = %actual_addr, "API server listening (HTTPS)");
    } else {
        tracing::info!(addr = %actual_addr, "API server listening");
    }

    // Spawn SIGHUP listener (Unix-only; routes the signal into the
    // same `reload_tx` channel the file watcher and HTTP endpoint
    // use, so every reload trigger funnels through one task).
    let sighup_reload_tx = reload_tx.clone();
    let sighup_sources_tx = sources_trigger_tx_val.clone();
    tokio::spawn(async move {
        reload::sighup_listener(sighup_reload_tx, sighup_sources_tx).await;
    });

    // Spawn reload handler — uses LogProcessor::reload_rules for atomic hot-reload.
    // Also re-reads enricher config and (when `daemon-tls` is built in) the TLS
    // certificate / key so a single `POST /api/v1/reload`, SIGHUP, or file-watcher
    // event rotates every hot-reloadable component in one debounced pass.
    let reload_processor = processor.clone();
    let reload_metrics = metrics.clone();
    let reload_health = health.clone();
    let reload_enrichment_swap = enrichment_swap.clone();
    let reload_enrichers_path = config.enrichers_path.clone();
    let reload_enrichment_metrics = enrichment_metrics.clone();
    let reload_source_cache = initial_source_cache.clone();
    let reload_alert_pipeline_swap = alert_pipeline_swap.clone();
    let reload_alert_pipeline_path = config.alert_pipeline_path.clone();
    let reload_alert_state = alert_state.clone();
    let reload_risk_swap = risk_swap.clone();
    let reload_risk_state = risk_state.clone();
    let reload_risk_path = config.risk_path.clone();
    #[cfg(feature = "daemon-tls")]
    let reload_tls_state = tls_state.clone();
    #[cfg(feature = "daemon-tls")]
    let reload_tls_metrics = metrics.clone();
    tokio::spawn(async move {
        while reload_rx.recv().await.is_some() {
            // Debounce: batch rapid file changes
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            while reload_rx.try_recv().is_ok() {}

            reload_metrics.reloads_total.inc();
            tracing::info!("Reloading rules and pipelines...");

            match reload_processor.reload_rules() {
                Ok(stats) => {
                    tracing::info!(
                        detection_rules = stats.detection_rules,
                        correlation_rules = stats.correlation_rules,
                        path = %reload_processor.rules_path().display(),
                        "Rules and pipelines reloaded"
                    );
                    reload_metrics
                        .detection_rules_loaded
                        .set(stats.detection_rules as i64);
                    reload_metrics
                        .correlation_rules_loaded
                        .set(stats.correlation_rules as i64);
                    reload_health.set_ready(true);
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to reload rules");
                    reload_metrics.reloads_failed.inc();
                }
            }

            // Reload enrichers. Failures here log + bump
            // `reloads_failed` and leave the previous pipeline in place
            // so a typo in the enrichers config doesn't take down
            // detection enrichment in production.
            if let Some(path) = reload_enrichers_path.as_deref() {
                match super::enrichment::load_enrichers_file(path).and_then(|file| {
                    super::enrichment::build_enrichers_full(
                        file,
                        reload_source_cache.clone(),
                        reload_enrichment_metrics.clone(),
                    )
                }) {
                    Ok(new_pipeline) => {
                        let prev_count = reload_enrichment_swap
                            .load()
                            .as_ref()
                            .as_ref()
                            .map(|p| p.len())
                            .unwrap_or(0);
                        let new_count = new_pipeline.len();
                        reload_enrichment_swap.store(Arc::new(Some(Arc::new(new_pipeline))));
                        tracing::info!(
                            previous = prev_count,
                            current = new_count,
                            path = %path.display(),
                            "Enrichment pipeline reloaded"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            path = %path.display(),
                            "Failed to reload enrichers config; keeping previous pipeline"
                        );
                        reload_metrics.reloads_failed.inc();
                    }
                }
            }

            // Reload the alert pipeline. Failures keep the previous pipeline
            // in place so a typo cannot take down dedup in production. The
            // in-flight active-alert store is owned by the sink task and
            // survives a config swap; stale alerts age out via the new
            // pipeline's resolve_timeout.
            if let Some(path) = reload_alert_pipeline_path.as_deref() {
                match load_alert_pipeline_file(path).and_then(build_alert_pipeline) {
                    Ok(new_pipeline) => {
                        // Re-seed static silences (replacing the previous static
                        // set); API-created silences are preserved.
                        if let Ok(mut state) = reload_alert_state.write() {
                            state
                                .silences
                                .set_static(new_pipeline.static_silences().to_vec());
                        }
                        reload_alert_pipeline_swap.store(Arc::new(Some(Arc::new(new_pipeline))));
                        tracing::info!(path = %path.display(), "Alert pipeline reloaded");
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            path = %path.display(),
                            "Failed to reload alert pipeline; keeping previous pipeline"
                        );
                        reload_metrics.reloads_failed.inc();
                    }
                }
            }

            // Reload the risk layer. Failures keep the previous config in place
            // so a typo cannot take down risk scoring in production. In-flight
            // per-entity accumulators are owned by the sink task and survive a
            // config swap; stale entries age out via the new window.
            if let Some(path) = reload_risk_path.as_deref() {
                match load_risk_file(path).and_then(build_risk_layer) {
                    Ok(new_layer) => {
                        // If the reloaded config drops the accumulator, clear
                        // in-flight entities: with no `incident` block the tick
                        // no longer prunes them, so they would otherwise linger
                        // forever and keep being snapshotted.
                        if new_layer.incident_config().is_none()
                            && let Ok(mut st) = reload_risk_state.write()
                        {
                            *st = RiskState::default();
                        }
                        reload_risk_swap.store(Arc::new(Some(Arc::new(new_layer))));
                        tracing::info!(path = %path.display(), "Risk layer reloaded");
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            path = %path.display(),
                            "Failed to reload risk layer; keeping previous config"
                        );
                        reload_metrics.reloads_failed.inc();
                    }
                }
            }

            // Reload TLS certificate / key from disk when daemon-tls is
            // built in and configured. Failures keep the previous
            // certificate active so a typo in the cert path cannot
            // black-hole the listener; the operator sees the error in
            // the daemon log and via `rsigma_reloads_failed_total`.
            #[cfg(feature = "daemon-tls")]
            if let Some(ref state) = reload_tls_state {
                match state.reload() {
                    Ok(new_expiry) => {
                        update_tls_metrics(&reload_tls_metrics, new_expiry);
                        warn_if_cert_expiring_soon(new_expiry);
                        tracing::info!(not_after = new_expiry, "TLS certificate hot-reloaded");
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "Failed to reload TLS certificate; keeping previous one active"
                        );
                        reload_metrics.reloads_failed.inc();
                    }
                }
            }
        }
    });

    // High-water mark for the last acked NATS stream position.
    // Updated by the ack task, read by the periodic/shutdown state saver.
    let high_water_seq = Arc::new(AtomicU64::new(0));
    let high_water_ts = Arc::new(AtomicI64::new(0));

    // Spawn periodic state saver
    if let Some(ref store) = state_store {
        let save_processor = processor.clone();
        let save_store = store.clone();
        let save_interval_secs = config.state_save_interval;
        let save_hw_seq = high_water_seq.clone();
        let save_hw_ts = high_water_ts.clone();
        let save_alert_swap = alert_pipeline_swap.clone();
        let save_alert_state = alert_state.clone();
        let save_risk_swap = risk_swap.clone();
        let save_risk_state = risk_state.clone();
        let save_dispositions = disposition_state_for_save.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(save_interval_secs));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                if let Some(snapshot) = save_processor.export_state() {
                    let position = source_position_from_atomics(&save_hw_seq, &save_hw_ts);
                    let snapshot_size = serde_json::to_vec(&snapshot).map(|v| v.len()).unwrap_or(0);
                    let window_count = snapshot.windows.len();
                    let save_start = std::time::Instant::now();
                    if let Err(e) = save_store.save(&snapshot, position.as_ref()).await {
                        tracing::warn!(
                            error = %e,
                            size_bytes = snapshot_size,
                            windows = window_count,
                            "Failed to save periodic state snapshot",
                        );
                    } else {
                        tracing::debug!(
                            duration_ms = save_start.elapsed().as_millis() as u64,
                            size_bytes = snapshot_size,
                            windows = window_count,
                            "Periodic state snapshot saved",
                        );
                    }
                }
                // Persist the alert-pipeline state when configured.
                if let Some(pipeline) = save_alert_swap.load_full().as_ref() {
                    let snap = {
                        let st = save_alert_state.read().unwrap_or_else(|e| e.into_inner());
                        pipeline.snapshot(&st)
                    };
                    if let Err(e) = save_store.save_alert_pipeline(&snap).await {
                        tracing::warn!(error = %e, "Failed to save alert-pipeline snapshot");
                    }
                }
                // Persist the risk-accumulator state when configured.
                if let Some(risk_layer) = save_risk_swap.load_full().as_ref() {
                    let snap = {
                        let st = save_risk_state.read().unwrap_or_else(|e| e.into_inner());
                        risk_layer.snapshot(&st)
                    };
                    if let Err(e) = save_store.save_risk(&snap).await {
                        tracing::warn!(error = %e, "Failed to save risk snapshot");
                    }
                }
                // Persist the disposition store when the triage loop is enabled.
                if let Some(dispositions) = save_dispositions.as_ref()
                    && let Some(snap) = dispositions.snapshot()
                    && let Err(e) = save_store.save_dispositions(&snap).await
                {
                    tracing::warn!(error = %e, "Failed to save disposition snapshot");
                }
            }
        });
    }

    // --- Streaming pipeline: source -> engine -> sink -> ack ---
    let (sink_tx, mut sink_rx) = mpsc::channel::<(ProcessResult, Vec<AckToken>)>(buffer_size);
    let (ack_tx, mut ack_rx) = mpsc::unbounded_channel::<AckToken>();

    // Select source based on --input flag
    #[cfg_attr(not(feature = "daemon-otlp"), allow(unused_mut))]
    let mut source_handle: Option<tokio::task::JoinHandle<()>> = match config.input.as_str() {
        "stdin" | "stdin://" => {
            let h = spawn_source(
                StdinSource::new(),
                event_tx,
                Some(metrics.clone() as Arc<dyn rsigma_runtime::MetricsHook>),
            );
            tracing::info!(input = "stdin", "Event source started");
            Some(h)
        }
        "http" => {
            drop(event_tx);
            tracing::info!(input = "http", "Event source started (POST /api/v1/events)");
            None
        }
        #[cfg(feature = "daemon-nats")]
        input if input.starts_with("nats://") => {
            let (url, subject) = parse_nats_url(input);
            let mut nats_cfg = config.nats_config.clone();
            nats_cfg.url = url.clone();
            match rsigma_runtime::NatsSource::connect(
                &nats_cfg,
                &subject,
                &config.replay_policy,
                config.consumer_group.as_deref(),
            )
            .await
            {
                Ok(source) => {
                    let h = spawn_source(
                        source,
                        event_tx,
                        Some(metrics.clone() as Arc<dyn rsigma_runtime::MetricsHook>),
                    );
                    tracing::info!(url = url, subject = subject, "NATS source started");
                    Some(h)
                }
                Err(e) => {
                    tracing::error!(error = %e, url = url, "Failed to connect NATS source");
                    std::process::exit(crate::exit_code::CONFIG_ERROR);
                }
            }
        }
        #[cfg(unix)]
        input if input.starts_with("unix://") => {
            let path = input.strip_prefix("unix://").unwrap_or(input);
            match rsigma_runtime::UnixSocketSource::bind(std::path::Path::new(path)).await {
                Ok(source) => {
                    let h = spawn_source(
                        source,
                        event_tx,
                        Some(metrics.clone() as Arc<dyn rsigma_runtime::MetricsHook>),
                    );
                    tracing::info!(path = path, "Unix socket source started");
                    Some(h)
                }
                Err(e) => {
                    tracing::error!(error = %e, path = path, "Failed to bind unix socket source");
                    std::process::exit(crate::exit_code::CONFIG_ERROR);
                }
            }
        }
        other => {
            tracing::error!(
                input = other,
                "Unsupported input source (supported: stdin, http, nats://, unix://)"
            );
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
    };

    // Build optional DLQ sink from --dlq flag
    let (dlq_tx, mut dlq_rx) = mpsc::channel::<DlqEntry>(buffer_size);
    let dlq_sink = if let Some(ref dlq_spec) = config.dlq {
        let (sink, _) = build_sink(dlq_spec, false, &config).await;
        tracing::info!(dlq = dlq_spec, "Dead-letter queue enabled");
        Some(sink)
    } else {
        None
    };

    // When a finite source (stdin/NATS) completes but OTLP handlers still hold
    // event_tx clones, event_rx.recv() would block forever. This notify signals
    // the engine to close its receiver so it drains remaining events and exits.
    #[cfg(feature = "daemon-otlp")]
    let source_done_notify = std::sync::Arc::new(tokio::sync::Notify::new());
    #[cfg(feature = "daemon-otlp")]
    if let Some(h) = source_handle.take() {
        let done = source_done_notify.clone();
        tokio::spawn(async move {
            let _ = h.await;
            done.notify_one();
        });
    }

    // Engine task: reads RawEvents, evaluates rules, sends results + ack tokens
    // to the sink channel. Events with no detections are acked immediately.
    // Parse errors are routed to the DLQ.
    let engine_processor = processor.clone();
    let engine_metrics = metrics.clone();
    let event_filter = config.event_filter.clone();
    let batch_size = config.batch_size;
    let input_format = config.input_format.clone();
    let engine_ack_tx = ack_tx.clone();
    let engine_dlq_tx = dlq_tx.clone();
    let dlq_enabled = config.dlq.is_some();
    #[cfg(feature = "daemon-otlp")]
    let engine_source_done = source_done_notify.clone();
    let engine_handle = tokio::spawn(async move {
        let filter_fn = move |v: &serde_json::Value| crate::apply_event_filter(v, &event_filter);
        #[cfg(feature = "daemon-otlp")]
        let source_done = engine_source_done;
        #[cfg(feature = "daemon-otlp")]
        let mut source_finished = false;
        loop {
            let pipeline_start = std::time::Instant::now();

            let first = {
                #[cfg(feature = "daemon-otlp")]
                {
                    if source_finished {
                        match event_rx.recv().await {
                            Some(e) => e,
                            None => break,
                        }
                    } else {
                        tokio::select! {
                            event = event_rx.recv() => match event {
                                Some(e) => e,
                                None => break,
                            },
                            _ = source_done.notified() => {
                                source_finished = true;
                                event_rx.close();
                                match event_rx.recv().await {
                                    Some(e) => e,
                                    None => break,
                                }
                            }
                        }
                    }
                }
                #[cfg(not(feature = "daemon-otlp"))]
                match event_rx.recv().await {
                    Some(raw_event) => raw_event,
                    None => break,
                }
            };
            engine_metrics.on_input_queue_depth_change(-1);

            let mut batch = Vec::with_capacity(batch_size.min(64));
            batch.push(first);
            while batch.len() < batch_size {
                match event_rx.try_recv() {
                    Ok(raw_event) => {
                        engine_metrics.on_input_queue_depth_change(-1);
                        batch.push(raw_event);
                    }
                    Err(_) => break,
                }
            }
            let initial_batch_size = batch.len();
            engine_metrics.observe_batch_size(initial_batch_size as u64);
            let batch_span = tracing::debug_span!(
                "process_batch",
                batch_size = initial_batch_size,
                input_format = ?input_format,
            );

            // Use Instrument rather than .enter() because the batch processing
            // awaits on multiple channels; .enter() across .await produces
            // confused span nesting on the multi-threaded runtime.
            let shutdown = tracing::Instrument::instrument(
                async {
                    let mut valid_payloads = Vec::with_capacity(batch.len());
                    let mut valid_tokens = Vec::with_capacity(batch.len());

                    for raw_event in batch {
                        if dlq_enabled
                            && !raw_event.payload.trim().is_empty()
                            && rsigma_runtime::parse_line(&raw_event.payload, &input_format)
                                .is_none()
                        {
                            tracing::debug!("Event routed to DLQ: parse error");
                            if engine_dlq_tx
                                .send(DlqEntry {
                                    original_event: raw_event.payload,
                                    error: "parse error".to_string(),
                                    timestamp: chrono::Utc::now().to_rfc3339(),
                                })
                                .await
                                .is_err()
                            {
                                tracing::warn!("DLQ channel closed, parse-error event dropped");
                            }
                            if engine_ack_tx.send(raw_event.ack_token).is_err() {
                                return true;
                            }
                            continue;
                        }
                        valid_payloads.push(raw_event.payload);
                        valid_tokens.push(raw_event.ack_token);
                    }

                    if valid_payloads.is_empty() {
                        return false;
                    }

                    let process_start = std::time::Instant::now();
                    let results: Vec<ProcessResult> = engine_processor.process_batch_with_format(
                        &valid_payloads,
                        &input_format,
                        Some(&filter_fn),
                    );
                    let process_elapsed_ms = process_start.elapsed().as_millis() as u64;
                    let match_count = results.iter().filter(|r| !r.is_empty()).count();
                    tracing::debug!(
                        batch_size = valid_payloads.len(),
                        matches = match_count,
                        elapsed_ms = process_elapsed_ms,
                        "Batch processed",
                    );

                    for (result, ack_token) in results.into_iter().zip(valid_tokens) {
                        if result.is_empty() {
                            if engine_ack_tx.send(ack_token).is_err() {
                                tracing::debug!("Ack channel closed, engine shutting down");
                                return true;
                            }
                            continue;
                        }
                        engine_metrics.on_output_queue_depth_change(1);
                        if sink_tx.send((result, vec![ack_token])).await.is_err() {
                            tracing::debug!("Sink channel closed, engine shutting down");
                            return true;
                        }
                    }

                    false
                },
                batch_span,
            )
            .await;

            engine_metrics.observe_pipeline_latency(pipeline_start.elapsed().as_secs_f64());

            if shutdown {
                break;
            }
        }
        tracing::info!("Event source exhausted, engine shutting down");
    });

    // Build leaf sinks from --output flags. The dispatcher runs one worker per
    // leaf, so fan-out is realized by the dispatcher rather than a FanOut sink.
    let pretty = config.pretty;
    let output_specs = if config.output.is_empty() {
        vec!["stdout".to_string()]
    } else {
        config.output.clone()
    };
    let mut leaves: Vec<(Sink, OnFull, DeliveryConfig)> = Vec::new();
    for spec in &output_specs {
        let (sink, on_full) = build_sink(spec, pretty, &config).await;
        for leaf in sink.into_leaves() {
            leaves.push((leaf, on_full, config.delivery_config));
        }
    }

    // Webhook sinks are built once at startup and run as lossy (on_full=drop)
    // leaves so a third-party HTTP endpoint never blocks the at-least-once
    // token release for the durable sinks; anything undeliverable lands in the
    // DLQ via the shared worker.
    if !config.webhook_paths.is_empty() {
        let webhook_metrics = metrics.clone() as Arc<dyn MetricsHook>;
        match super::webhook::load_and_build_webhooks(&config.webhook_paths, webhook_metrics) {
            Ok(built) => {
                for bw in built {
                    leaves.push((Sink::Webhook(Box::new(bw.sink)), OnFull::Drop, bw.delivery));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to load webhooks");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
    }
    tracing::info!(output = ?output_specs, sinks = leaves.len(), "Sink started");

    // Bridge the delivery layer's terminal failures into the existing DLQ
    // writer so failed deliveries land alongside parse errors.
    let (df_tx, mut df_rx) = mpsc::channel::<DeliveryFailure>(buffer_size);
    let df_handle = tokio::spawn(async move {
        while let Some(failure) = df_rx.recv().await {
            let _ = dlq_tx
                .send(DlqEntry {
                    original_event: failure.serialized,
                    error: failure.error,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                })
                .await;
        }
    });

    // Sink task: drains the engine->sink channel, runs post-evaluation
    // enrichment, then dispatches each result to the per-sink workers. The
    // dispatcher's ack-join releases ack tokens only once every sink has
    // committed the result (delivered or DLQ-parked), preserving at-least-once
    // across fan-out. On shutdown it drains the worker queues.
    let sink_metrics = metrics.clone();
    let enrichment_swap_for_sink = enrichment_swap.clone();
    let alert_pipeline_swap_for_sink = alert_pipeline_swap.clone();
    let alert_state_for_sink = alert_state.clone();
    let alert_pipeline_metrics = metrics.clone() as Arc<dyn MetricsHook>;
    let risk_swap_for_sink = risk_swap.clone();
    let risk_state_for_sink = risk_state.clone();
    let risk_metrics = metrics.clone() as Arc<dyn MetricsHook>;
    let delivery_metrics = metrics.clone() as Arc<dyn MetricsHook>;
    let dispatch_ack_tx = ack_tx.clone();
    let empty_ack_tx = ack_tx.clone();
    let tail_for_sink = tail_registry.clone();
    drop(ack_tx);
    let sink_handle = tokio::spawn(async move {
        let dispatcher = Dispatcher::spawn(leaves, Some(df_tx), dispatch_ack_tx, delivery_metrics);
        // 1s tick drives the alert pipeline's repeat re-emits, resolved
        // records, incident emissions, and silence GC. A no-op when no alert
        // pipeline is configured.
        let mut alert_tick = tokio::time::interval(tokio::time::Duration::from_secs(1));
        alert_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                maybe = sink_rx.recv() => {
                    let Some((mut result, ack_tokens)) = maybe else { break };
                    sink_metrics.on_output_queue_depth_change(-1);

                    // Post-evaluation enrichment may suppress every entry; if
                    // so, ack the events and skip sink delivery. `load_full`
                    // keeps the pipeline alive across the await without holding
                    // an `ArcSwap` guard.
                    let pipeline_snapshot = enrichment_swap_for_sink.load_full();
                    if let Some(pipeline) = pipeline_snapshot.as_ref()
                        && !pipeline.is_empty()
                    {
                        pipeline.run(&mut result).await;
                        if result.is_empty() {
                            for token in ack_tokens {
                                let _ = empty_ack_tx.send(token);
                            }
                            continue;
                        }
                    }

                    // Risk layer: annotate each in-scope firing with a risk
                    // score and risk objects, then (opt-in) emit a compact risk
                    // event per (detection, risk object) pair. Runs before the
                    // alert pipeline so risk accrues on every firing, before
                    // dedup, silencing, or inhibition can fold or drop it.
                    let risk_snapshot = risk_swap_for_sink.load_full();
                    if let Some(risk_layer) = risk_snapshot.as_ref() {
                        let now = chrono::Utc::now().timestamp();
                        let out = {
                            let mut st = risk_state_for_sink
                                .write()
                                .unwrap_or_else(|e| e.into_inner());
                            risk_layer.process(result, &mut st, now, risk_metrics.as_ref())
                        };
                        result = out.kept;
                        if !out.risk_events.is_empty() {
                            let subject =
                                risk_layer.risk_event_nats_subject().map(|s| s.to_string());
                            for event in out.risk_events {
                                match serde_json::to_string(&event) {
                                    Ok(json) => {
                                        dispatcher
                                            .dispatch_incident(IncidentEnvelope {
                                                json,
                                                nats_subject: subject.clone(),
                                            })
                                            .await;
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "Failed to serialize risk event");
                                    }
                                }
                            }
                        }
                        if !out.incidents.is_empty() {
                            let subject =
                                risk_layer.incident_nats_subject().map(|s| s.to_string());
                            for incident in out.incidents {
                                match serde_json::to_string(&incident) {
                                    Ok(json) => {
                                        dispatcher
                                            .dispatch_incident(IncidentEnvelope {
                                                json,
                                                nats_subject: subject.clone(),
                                            })
                                            .await;
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "Failed to serialize risk incident");
                                    }
                                }
                            }
                        }
                    }

                    // Alert pipeline: dedup folds duplicates and grouping
                    // assigns survivors to incidents (annotating `incident_id`).
                    // If the whole batch folds away, ack and skip dispatch,
                    // mirroring the enrichment empty-result path. The incident
                    // store is locked only for the synchronous process call.
                    let alert_snapshot = alert_pipeline_swap_for_sink.load_full();
                    if let Some(alert_pipeline) = alert_snapshot.as_ref() {
                        let now = chrono::Utc::now().timestamp();
                        let kept = {
                            let mut st = alert_state_for_sink
                                .write()
                                .unwrap_or_else(|e| e.into_inner());
                            alert_pipeline.process(
                                result,
                                &mut st,
                                now,
                                alert_pipeline_metrics.as_ref(),
                            )
                        };
                        if kept.is_empty() {
                            for token in ack_tokens {
                                let _ = empty_ack_tx.send(token);
                            }
                            continue;
                        }
                        result = kept;
                    }

                    // Live detection tail: fan the post-enrichment result out to
                    // any active tail sessions before dispatch. Lossy and
                    // non-blocking, so it can never stall the sink task or the
                    // ack-join.
                    if let Some(tail) = &tail_for_sink {
                        tail.capture(&result);
                    }

                    dispatcher.dispatch(result, ack_tokens).await;
                }
                _ = alert_tick.tick() => {
                    // Emit any due dedup repeat/resolved records and incident
                    // emissions. These are synthetic (no input event): dedup
                    // records dispatch with no ack tokens, incidents via the
                    // incident path (optionally to a dedicated NATS subject).
                    let alert_snapshot = alert_pipeline_swap_for_sink.load_full();
                    if let Some(alert_pipeline) = alert_snapshot.as_ref() {
                        let now = chrono::Utc::now().timestamp();
                        let out = {
                            let mut st = alert_state_for_sink
                                .write()
                                .unwrap_or_else(|e| e.into_inner());
                            alert_pipeline.tick(&mut st, now, alert_pipeline_metrics.as_ref())
                        };
                        for line in out.dedup_lines {
                            dispatcher
                                .dispatch_incident(IncidentEnvelope {
                                    json: line.to_string(),
                                    nats_subject: None,
                                })
                                .await;
                        }
                        let subject =
                            alert_pipeline.incident_nats_subject().map(|s| s.to_string());
                        for incident in out.incidents {
                            match serde_json::to_string(&incident) {
                                Ok(json) => {
                                    dispatcher
                                        .dispatch_incident(IncidentEnvelope {
                                            json,
                                            nats_subject: subject.clone(),
                                        })
                                        .await;
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Failed to serialize incident");
                                }
                            }
                        }
                    }

                    // Age out risk entities whose windows have fully elapsed and
                    // refresh the risk gauges. A no-op when no accumulator is
                    // configured.
                    let risk_snapshot = risk_swap_for_sink.load_full();
                    if let Some(risk_layer) = risk_snapshot.as_ref() {
                        let now = chrono::Utc::now().timestamp();
                        let mut st = risk_state_for_sink
                            .write()
                            .unwrap_or_else(|e| e.into_inner());
                        risk_layer.tick(&mut st, now, risk_metrics.as_ref());
                    }
                }
            }
        }
        dispatcher.shutdown().await;
    });

    // DLQ writer task: writes DLQ entries to the configured DLQ sink.
    let dlq_metrics = metrics.clone();
    let dlq_handle = tokio::spawn(async move {
        tracing::debug!("DLQ task started");
        let mut dlq_sink = dlq_sink;
        let mut no_sink_logged = false;
        while let Some(entry) = dlq_rx.recv().await {
            dlq_metrics.dlq_events.inc();
            if let Some(ref mut sink) = dlq_sink {
                let json = serde_json::to_string(&entry).unwrap_or_default();
                if let Err(e) = sink.send_raw(&json).await {
                    tracing::warn!(error = %e, "Failed to write to DLQ sink");
                }
            } else if !no_sink_logged {
                tracing::debug!("DLQ entry counted but no sink configured (use --dlq to persist)");
                no_sink_logged = true;
            }
        }
        tracing::debug!("DLQ task finished");
    });

    // Ack task: resolves ack tokens after the sink confirms delivery.
    // For NATS tokens, extracts the stream sequence before acking to maintain
    // the high-water mark used by the state saver.
    #[cfg(feature = "daemon-nats")]
    let (ack_hw_seq, ack_hw_ts) = (high_water_seq.clone(), high_water_ts.clone());
    let ack_handle = tokio::spawn(async move {
        while let Some(token) = ack_rx.recv().await {
            #[cfg(feature = "daemon-nats")]
            if let Some((seq, ts)) = token.nats_stream_position() {
                ack_hw_seq.fetch_max(seq, Ordering::Relaxed);
                ack_hw_ts.fetch_max(ts, Ordering::Relaxed);
            }
            token.ack().await;
        }
    });

    let drain_duration = std::time::Duration::from_secs(config.drain_timeout);

    // Build the unified axum router: with `daemon-otlp`, the OTLP/gRPC
    // service is folded into the same axum::Router via Tonic's
    // `Routes::into_axum_router`. axum::serve handles HTTP/1 and HTTP/2
    // (including h2c for plaintext gRPC) via hyper-util's auto::Builder.
    #[cfg(feature = "daemon-otlp")]
    let unified_app: axum::Router = otlp_routes.into_axum_router();
    #[cfg(not(feature = "daemon-otlp"))]
    let unified_app: axum::Router = app;

    let mut serve_handle = match bound {
        BoundListener::Tcp(listener) => {
            #[cfg(feature = "daemon-tls")]
            {
                if let Some(state) = tls_state {
                    let tls_listener = super::tls::RustlsListener::new(
                        listener,
                        state.config.clone(),
                        metrics.tls_active_connections.clone(),
                    );
                    let shutdown_fut = shutdown_fut.take().expect("shutdown future consumed once");
                    tokio::spawn(async move {
                        if let Err(e) = axum::serve(tls_listener, unified_app)
                            .with_graceful_shutdown(shutdown_fut)
                            .await
                        {
                            tracing::error!(error = %e, "server error");
                        }
                    })
                } else {
                    let shutdown_fut = shutdown_fut.take().expect("shutdown future consumed once");
                    tokio::spawn(async move {
                        if let Err(e) = axum::serve(listener, unified_app)
                            .with_graceful_shutdown(shutdown_fut)
                            .await
                        {
                            tracing::error!(error = %e, "server error");
                        }
                    })
                }
            }
            #[cfg(not(feature = "daemon-tls"))]
            {
                let shutdown_fut = shutdown_fut.take().expect("shutdown future consumed once");
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(listener, unified_app)
                        .with_graceful_shutdown(shutdown_fut)
                        .await
                    {
                        tracing::error!(error = %e, "server error");
                    }
                })
            }
        }
        // A unix:// listener never terminates TLS (rejected at config time), so
        // it always serves plaintext over the socket.
        #[cfg(unix)]
        BoundListener::Unix(listener) => {
            let shutdown_fut = shutdown_fut.take().expect("shutdown future consumed once");
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, unified_app)
                    .with_graceful_shutdown(shutdown_fut)
                    .await
                {
                    tracing::error!(error = %e, "server error");
                }
            })
        }
    };

    let shutdown_triggered = tokio::select! {
        _ = &mut serve_handle => true,
        _ = engine_handle => {
            tracing::info!("Streaming pipeline complete");
            serve_handle.abort();
            false
        }
    };

    if shutdown_triggered {
        tracing::info!("Shutdown signal received, draining pipeline...");

        if let Some(h) = source_handle {
            h.abort();
            tracing::info!("Source task aborted");
        }

        // Tell the engine to stop pulling new events and drain what is already
        // buffered. The stdin reader cannot be cancelled mid-read, so without
        // this the engine would block on `event_rx.recv()` (holding `sink_tx`
        // open) until the drain timeout elapses, falsely warning that events
        // were lost. The engine closes its receiver on this signal, drains the
        // buffered events, then exits, which lets the sink/ack tasks finish.
        #[cfg(feature = "daemon-otlp")]
        source_done_notify.notify_one();

        let drain = async {
            let _ = sink_handle.await;
            tracing::debug!("Sink task finished");
            let _ = df_handle.await;
            tracing::debug!("DLQ bridge finished");
            let _ = dlq_handle.await;
            tracing::debug!("DLQ task finished");
            let _ = ack_handle.await;
            tracing::debug!("Ack task finished");
        };
        if tokio::time::timeout(drain_duration, drain).await.is_err() {
            tracing::warn!(
                timeout_secs = config.drain_timeout,
                "Drain timeout exceeded, some events may be lost"
            );
        }
    } else {
        let _ = sink_handle.await;
        tracing::debug!("Sink task finished");
        let _ = df_handle.await;
        tracing::debug!("DLQ bridge finished");
        let _ = dlq_handle.await;
        tracing::debug!("DLQ task finished");
        let _ = ack_handle.await;
        tracing::debug!("Ack task finished");
    }

    // Save state on shutdown
    if let Some(ref store) = state_store
        && let Some(snapshot) = processor.export_state()
    {
        let position = source_position_from_atomics(&high_water_seq, &high_water_ts);
        match store.save(&snapshot, position.as_ref()).await {
            Ok(()) => {
                if let Some(ref pos) = position {
                    tracing::info!(
                        source_sequence = pos.sequence,
                        "Correlation state saved to database on shutdown"
                    );
                } else {
                    tracing::info!("Correlation state saved to database on shutdown");
                }
            }
            Err(e) => tracing::error!(error = %e, "Failed to save state on shutdown"),
        }
    }

    // Save the alert-pipeline state on shutdown when configured.
    if let Some(ref store) = state_store
        && let Some(pipeline) = alert_pipeline_swap.load_full().as_ref()
    {
        let snap = {
            let st = alert_state.read().unwrap_or_else(|e| e.into_inner());
            pipeline.snapshot(&st)
        };
        match store.save_alert_pipeline(&snap).await {
            Ok(()) => tracing::info!("Alert-pipeline state saved to database on shutdown"),
            Err(e) => {
                tracing::error!(error = %e, "Failed to save alert-pipeline state on shutdown")
            }
        }
    }

    // Save the risk-accumulator state on shutdown when configured.
    if let Some(ref store) = state_store
        && let Some(risk_layer) = risk_swap.load_full().as_ref()
    {
        let snap = {
            let st = risk_state.read().unwrap_or_else(|e| e.into_inner());
            risk_layer.snapshot(&st)
        };
        match store.save_risk(&snap).await {
            Ok(()) => tracing::info!("Risk state saved to database on shutdown"),
            Err(e) => tracing::error!(error = %e, "Failed to save risk state on shutdown"),
        }
    }

    // Save the disposition state on shutdown when the triage loop is enabled.
    if let Some(ref store) = state_store
        && let Some(dispositions) = disposition_state_for_save.as_ref()
        && let Some(snap) = dispositions.snapshot()
    {
        match store.save_dispositions(&snap).await {
            Ok(()) => tracing::info!("Disposition state saved to database on shutdown"),
            Err(e) => tracing::error!(error = %e, "Failed to save disposition state on shutdown"),
        }
    }
}

/// Wait for either SIGINT (Ctrl+C) or SIGTERM, then log and return.
///
/// The signal streams are created by the caller (before the API listener is
/// announced) and moved in here, so the OS handlers are installed eagerly and
/// a signal that races daemon startup is caught rather than killing the
/// process under the default disposition.
#[cfg(unix)]
async fn shutdown_signal(
    mut sigint: tokio::signal::unix::Signal,
    mut sigterm: tokio::signal::unix::Signal,
) {
    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
    }
    tracing::info!("Shutdown signal received");
}

/// Wait for Ctrl+C, then log and return (non-Unix platforms).
#[cfg(not(unix))]
async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("Shutdown signal received");
}

/// Split an output spec into its base (scheme + target) and `key=value` query
/// parameters: `file:///p?on_full=drop`, `otlp://host:4317?compression=gzip`.
fn split_query(spec: &str) -> (&str, Vec<(&str, &str)>) {
    match spec.split_once('?') {
        Some((base, query)) => {
            let params = query
                .split('&')
                .filter_map(|kv| kv.split_once('='))
                .collect();
            (base, params)
        }
        None => (spec, Vec::new()),
    }
}

/// Resolve the full-queue policy from query params. Defaults to `Block`
/// (at-least-once); `on_full=drop` opts into best-effort delivery.
fn on_full_from_params(params: &[(&str, &str)]) -> OnFull {
    match params
        .iter()
        .find(|(k, _)| *k == "on_full")
        .map(|(_, v)| *v)
    {
        Some("drop") => OnFull::Drop,
        Some("block") | None => OnFull::Block,
        Some(other) => {
            tracing::warn!(value = other, "Unknown on_full value, using block");
            OnFull::Block
        }
    }
}

/// Read OTLP client TLS material referenced by `ca`, `client_cert`,
/// `client_key`, and `tls_domain` query parameters on an `otlps`/`otlphttps`
/// sink URL. A read failure is a fatal config error.
#[cfg(feature = "daemon-otlp")]
fn build_otlp_tls(params: &[(&str, &str)]) -> rsigma_runtime::OtlpClientTls {
    let read_pem = |key: &str| -> Option<Vec<u8>> {
        params.iter().find(|(k, _)| *k == key).map(|(_, path)| {
            std::fs::read(path).unwrap_or_else(|e| {
                tracing::error!(key, path, error = %e, "Failed to read OTLP TLS material");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            })
        })
    };
    rsigma_runtime::OtlpClientTls {
        ca_pem: read_pem("ca"),
        client_cert_pem: read_pem("client_cert"),
        client_key_pem: read_pem("client_key"),
        domain: params
            .iter()
            .find(|(k, _)| *k == "tls_domain")
            .map(|(_, v)| v.to_string()),
    }
}

/// Build a single Sink from an output spec string, plus its full-queue policy.
async fn build_sink(
    spec: &str,
    pretty: bool,
    #[cfg_attr(not(feature = "daemon-nats"), allow(unused))] config: &DaemonConfig,
) -> (Sink, OnFull) {
    let (base, params) = split_query(spec);
    let on_full = on_full_from_params(&params);

    if base == "stdout" || base == "stdout://" {
        return (Sink::Stdout(StdoutSink::new(pretty)), on_full);
    }

    if let Some(path) = base.strip_prefix("file://") {
        let path = std::path::Path::new(path);
        return match FileSink::open(path) {
            Ok(file_sink) => {
                tracing::info!(path = %path.display(), "File sink opened");
                (Sink::File(file_sink), on_full)
            }
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "Failed to open file sink");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
        };
    }

    #[cfg(feature = "daemon-nats")]
    if base.starts_with("nats://") {
        let (url, subject) = parse_nats_url(base);
        let mut nats_cfg = config.nats_config.clone();
        nats_cfg.url = url.clone();
        return match rsigma_runtime::NatsSink::connect(&nats_cfg, &subject).await {
            Ok(nats_sink) => {
                tracing::info!(url = url, subject = subject, "NATS sink started");
                (Sink::Nats(Box::new(nats_sink)), on_full)
            }
            Err(e) => {
                tracing::error!(error = %e, url = url, "Failed to connect NATS sink");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
        };
    }

    #[cfg(feature = "daemon-otlp")]
    {
        use rsigma_runtime::OtlpProtocol;
        // `otlps`/`otlphttps` select TLS; the plaintext forms do not. Order so
        // the longer TLS prefixes win (they are not prefixes of each other, so
        // this is just for clarity).
        let otlp = base
            .strip_prefix("otlphttps://")
            .map(|e| (OtlpProtocol::Http, e, true))
            .or_else(|| {
                base.strip_prefix("otlphttp://")
                    .map(|e| (OtlpProtocol::Http, e, false))
            })
            .or_else(|| {
                base.strip_prefix("otlps://")
                    .map(|e| (OtlpProtocol::Grpc, e, true))
            })
            .or_else(|| {
                base.strip_prefix("otlp://")
                    .map(|e| (OtlpProtocol::Grpc, e, false))
            });
        if let Some((protocol, endpoint, tls_enabled)) = otlp {
            let gzip = params
                .iter()
                .any(|(k, v)| *k == "compression" && *v == "gzip");
            let tls = tls_enabled.then(|| build_otlp_tls(&params));
            return match rsigma_runtime::OtlpSink::new(protocol, endpoint, gzip, tls) {
                Ok(sink) => {
                    tracing::info!(
                        endpoint,
                        ?protocol,
                        gzip,
                        tls = tls_enabled,
                        "OTLP sink started"
                    );
                    (Sink::Otlp(Box::new(sink)), on_full)
                }
                Err(e) => {
                    tracing::error!(endpoint, error = %e, "Failed to build OTLP sink");
                    std::process::exit(crate::exit_code::CONFIG_ERROR);
                }
            };
        }
    }

    #[cfg(unix)]
    if let Some(path) = base.strip_prefix("unix://") {
        return match rsigma_runtime::UnixSocketSink::connect(std::path::Path::new(path)).await {
            Ok(unix_sink) => {
                tracing::info!(path, "Unix socket sink started");
                (Sink::Unix(Box::new(unix_sink)), on_full)
            }
            Err(e) => {
                tracing::error!(path, error = %e, "Failed to connect unix socket sink");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
        };
    }

    tracing::error!(
        output = base,
        "Unsupported output sink (supported: stdout, file://<path>, nats://, otlp://, otlphttp://, unix://)"
    );
    std::process::exit(crate::exit_code::CONFIG_ERROR);
}

/// Parse a nats:// URL into (server_url, subject).
///
/// Input: "nats://host:port/subject.path.>"
/// Output: ("nats://host:port", "subject.path.>")
#[cfg(feature = "daemon-nats")]
fn parse_nats_url(url: &str) -> (String, String) {
    let without_scheme = url.strip_prefix("nats://").unwrap_or(url);
    match without_scheme.find('/') {
        Some(pos) => {
            let server = format!("nats://{}", &without_scheme[..pos]);
            let subject = without_scheme[pos + 1..].to_string();
            (server, subject)
        }
        None => (format!("nats://{without_scheme}"), ">".to_string()),
    }
}

// ---------------------------------------------------------------------------
// State restore decision
// ---------------------------------------------------------------------------

/// Decide whether to restore correlation state from SQLite.
fn decide_state_restore(
    mode: StateRestoreMode,
    stored_position: Option<SourcePosition>,
    #[cfg(feature = "daemon-nats")] replay_policy: &rsigma_runtime::ReplayPolicy,
) -> bool {
    match mode {
        StateRestoreMode::ForceClear => {
            tracing::info!("State restore skipped (--clear-state)");
            false
        }
        StateRestoreMode::ForceKeep => {
            tracing::info!("State restore forced (--keep-state)");
            true
        }
        StateRestoreMode::Auto => {
            #[cfg(feature = "daemon-nats")]
            {
                use rsigma_runtime::ReplayPolicy;
                match replay_policy {
                    ReplayPolicy::Resume => true,
                    ReplayPolicy::Latest => {
                        tracing::info!("State restore skipped (--replay-from-latest starts fresh)");
                        false
                    }
                    ReplayPolicy::FromSequence(replay_seq) => match stored_position {
                        Some(pos) if *replay_seq > pos.sequence => {
                            tracing::info!(
                                replay_from = replay_seq,
                                stored_sequence = pos.sequence,
                                "Restoring state (replay starts after stored position)"
                            );
                            true
                        }
                        Some(pos) => {
                            tracing::info!(
                                replay_from = replay_seq,
                                stored_sequence = pos.sequence,
                                "State restore skipped (replay starts at or before stored position, would double-count)"
                            );
                            false
                        }
                        None => {
                            tracing::info!(
                                "State restore skipped (no stored position to compare against replay)"
                            );
                            false
                        }
                    },
                    ReplayPolicy::FromTime(replay_time) => {
                        let replay_ts = replay_time.unix_timestamp();
                        match stored_position {
                            Some(pos) if replay_ts > pos.timestamp => {
                                tracing::info!(
                                    replay_from_ts = replay_ts,
                                    stored_ts = pos.timestamp,
                                    "Restoring state (replay starts after stored timestamp)"
                                );
                                true
                            }
                            Some(pos) => {
                                tracing::info!(
                                    replay_from_ts = replay_ts,
                                    stored_ts = pos.timestamp,
                                    "State restore skipped (replay starts at or before stored timestamp, would double-count)"
                                );
                                false
                            }
                            None => {
                                tracing::info!(
                                    "State restore skipped (no stored position to compare against replay)"
                                );
                                false
                            }
                        }
                    }
                }
            }
            #[cfg(not(feature = "daemon-nats"))]
            {
                let _ = stored_position;
                true
            }
        }
    }
}

/// Refresh the `rsigma_tls_certificate_expiry_seconds` gauge to the
/// number of seconds between now and `expiry_unix`. Called at startup
/// and after every SIGHUP-triggered cert reload.
#[cfg(feature = "daemon-tls")]
pub(crate) fn update_tls_metrics(metrics: &Metrics, expiry_unix: i64) {
    let now = chrono::Utc::now().timestamp();
    let delta = (expiry_unix - now) as f64;
    metrics.tls_certificate_expiry_seconds.set(delta);
}

/// Emit a single WARN if the active certificate expires within 30 days.
/// Operators wire this into existing log-based alerting; the Prometheus
/// gauge handles the longer-horizon dashboards.
#[cfg(feature = "daemon-tls")]
pub(crate) fn warn_if_cert_expiring_soon(expiry_unix: i64) {
    const WARN_WINDOW_SECS: i64 = 30 * 24 * 3600;
    let now = chrono::Utc::now().timestamp();
    let remaining = expiry_unix - now;
    if remaining < 0 {
        tracing::warn!(
            expiry_unix,
            "TLS server certificate has already expired; clients will reject the handshake"
        );
    } else if remaining < WARN_WINDOW_SECS {
        let days = remaining / 86400;
        tracing::warn!(
            expiry_unix,
            days_remaining = days,
            "TLS server certificate expires in less than 30 days; rotate it soon"
        );
    }
}

/// Build a `SourcePosition` from the high-water mark atomics.
/// Returns `None` if no NATS messages have been acked yet (sequence == 0).
fn source_position_from_atomics(seq: &AtomicU64, ts: &AtomicI64) -> Option<SourcePosition> {
    let s = seq.load(Ordering::Relaxed);
    if s == 0 {
        return None;
    }
    Some(SourcePosition {
        sequence: s,
        timestamp: ts.load(Ordering::Relaxed),
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn readyz(State(state): State<AppState>) -> Response {
    if state.health.is_ready() {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ready", "rules_loaded": true })),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "not_ready", "rules_loaded": false })),
        )
            .into_response()
    }
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    state
        .metrics
        .uptime_seconds
        .set(state.start_time.elapsed().as_secs_f64());

    if let Some(observer) = state.field_observer.as_ref() {
        let snapshot = observer.snapshot();
        state.metrics.update_field_observer_metrics(&snapshot);
    }

    if let Some(observer) = state.schema_observer.as_ref() {
        let snapshot = observer.snapshot();
        state.metrics.update_schema_observer_metrics(&snapshot);
    }

    state.metrics.update_logsource_metrics(
        state.processor.logsource_pruned_total(),
        state.processor.logsource_absent_total(),
    );
    state
        .metrics
        .update_schema_pruning_metrics(&state.processor.schema_pruning_summary());

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.encode(),
    )
}

async fn list_rules(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.processor.stats();
    Json(serde_json::json!({
        "detection_rules": stats.detection_rules,
        "correlation_rules": stats.correlation_rules,
        "rules_path": state.processor.rules_path().display().to_string(),
    }))
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    detection_rules: usize,
    correlation_rules: usize,
    correlation_state_entries: usize,
    events_processed: u64,
    detection_matches: u64,
    correlation_matches: u64,
    uptime_seconds: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dynamic_sources: Option<DynamicSourcesSummary>,
}

#[derive(Serialize)]
struct DynamicSourcesSummary {
    total: usize,
    resolves_total: u64,
    errors_total: u64,
    cache_hits: u64,
}

/// `GET /api/v1/incidents` — open incidents from the grouping stage.
async fn list_incidents(State(state): State<AppState>) -> impl IntoResponse {
    let include = state
        .alert_pipeline_swap
        .load_full()
        .as_ref()
        .as_ref()
        .and_then(|p| p.incident_include())
        .unwrap_or(IncludeMode::Refs);
    let incidents = {
        let st = state.alert_state.read().unwrap_or_else(|e| e.into_inner());
        st.incidents.snapshot(include)
    };
    let count = incidents.len();
    Json(serde_json::json!({ "incidents": incidents, "count": count }))
}

/// `GET /api/v1/risk` — open entities tracked by the risk accumulator, with
/// their current window score, distinct tactic count, source count, and window
/// bounds. Empty when no risk accumulator is configured.
async fn list_risk_entities(State(state): State<AppState>) -> impl IntoResponse {
    let snapshot = state.risk_swap.load_full();
    let entities = match snapshot.as_ref().as_ref().and_then(|l| l.incident_config()) {
        Some(cfg) => {
            let now = chrono::Utc::now().timestamp();
            let st = state.risk_state.read().unwrap_or_else(|e| e.into_inner());
            st.views(cfg, now)
        }
        None => Vec::new(),
    };
    let count = entities.len();
    Json(serde_json::json!({ "entities": entities, "count": count }))
}

/// `GET /api/v1/correlations` — the compiled correlation list with per-group
/// counts (no window contents). Empty when the engine has no correlation rules.
async fn list_correlations(State(state): State<AppState>) -> impl IntoResponse {
    let correlations = state
        .processor
        .introspect_correlations(None, None)
        .map(|s| s.correlations)
        .unwrap_or_default();
    let count = correlations.len();
    Json(serde_json::json!({ "correlations": correlations, "count": count }))
}

/// Query parameters for `GET /api/v1/correlations/state`.
#[derive(serde::Deserialize)]
struct CorrelationStateQuery {
    /// Keep only the correlation whose id, name, or title equals this value.
    id: Option<String>,
    /// Keep only groups whose rendered key (`field=value, ...`) contains this
    /// substring.
    group: Option<String>,
}

/// `GET /api/v1/correlations/state` — the live per-group window snapshot
/// (current aggregate vs threshold, window entries, last alert, seconds to
/// eviction), optionally filtered by `?id=` and `?group=`. Empty when the
/// engine has no correlation rules.
async fn correlations_state(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<CorrelationStateQuery>,
) -> impl IntoResponse {
    let snapshot = state
        .processor
        .introspect_correlations(query.id.as_deref(), query.group.as_deref());
    match snapshot {
        Some(s) => {
            let count = s.groups.len();
            Json(serde_json::json!({
                "correlations": s.correlations,
                "groups": s.groups,
                "count": count,
            }))
        }
        None => Json(serde_json::json!({ "correlations": [], "groups": [], "count": 0 })),
    }
}

/// Build the `503` body returned by the disposition endpoints when the triage
/// feedback loop is disabled.
fn dispositions_disabled() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "dispositions disabled",
            "hint": "restart the daemon with --enable-dispositions (or daemon.dispositions.enabled: true)"
        })),
    )
        .into_response()
}

/// `POST /api/v1/dispositions` — ingest one or more analyst dispositions (a
/// single object, a JSON array, or NDJSON). Returns the ingest summary.
async fn ingest_dispositions(State(state): State<AppState>, body: String) -> Response {
    let Some(dispositions) = state.disposition_state.as_ref() else {
        return dispositions_disabled();
    };
    match dispositions.ingest(&body, "api") {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// `GET /api/v1/dispositions` — the per-rule false-positive ratio view.
async fn list_dispositions(State(state): State<AppState>) -> Response {
    match state.disposition_state.as_ref() {
        Some(dispositions) => Json(dispositions.view()).into_response(),
        None => dispositions_disabled(),
    }
}

/// `GET /api/v1/silences` — operator silences and their state.
async fn list_silences(State(state): State<AppState>) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    let silences = {
        let st = state.alert_state.read().unwrap_or_else(|e| e.into_inner());
        st.silences.snapshot(now)
    };
    let count = silences.len();
    Json(serde_json::json!({ "silences": silences, "count": count }))
}

/// `POST /api/v1/silences` — create a silence. Returns the assigned id.
async fn create_silence(State(state): State<AppState>, body: String) -> Response {
    let spec: SilenceSpec = match serde_json::from_str(&body) {
        Ok(spec) => spec,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid silence JSON: {e}") })),
            )
                .into_response();
        }
    };
    let max_silences = state
        .alert_pipeline_swap
        .load_full()
        .as_ref()
        .as_ref()
        .map(|p| p.max_dynamic_silences())
        .unwrap_or(rsigma_runtime::DEFAULT_MAX_DYNAMIC_SILENCES);
    match Silence::build(spec, SilenceOrigin::Api) {
        Ok(silence) => {
            let id = silence.id().to_string();
            let added = {
                let mut st = state.alert_state.write().unwrap_or_else(|e| e.into_inner());
                st.silences.try_add(silence, max_silences)
            };
            if added {
                (
                    StatusCode::CREATED,
                    Json(serde_json::json!({ "status": "created", "id": id })),
                )
                    .into_response()
            } else {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({
                        "error": format!(
                            "dynamic silence limit reached ({max_silences}); delete silences or raise max_silences"
                        )
                    })),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// `DELETE /api/v1/silences/{id}` — expire (remove) a silence.
async fn delete_silence(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let removed = {
        let mut st = state.alert_state.write().unwrap_or_else(|e| e.into_inner());
        st.silences.remove(&id)
    };
    if removed {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "deleted", "id": id })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no such silence", "id": id })),
        )
    }
}

async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.processor.stats();

    let dynamic_sources = state.source_resolver.as_ref().map(|_| {
        use prometheus::core::Collector;
        let resolves: u64 = state
            .metrics
            .source_resolves_total
            .collect()
            .first()
            .map(|mf| {
                mf.get_metric()
                    .iter()
                    .map(|m| m.get_counter().get_value() as u64)
                    .sum()
            })
            .unwrap_or(0);
        let errors: u64 = state
            .metrics
            .source_resolve_errors
            .collect()
            .first()
            .map(|mf| {
                mf.get_metric()
                    .iter()
                    .map(|m| m.get_counter().get_value() as u64)
                    .sum()
            })
            .unwrap_or(0);
        let cache_hits = state.metrics.source_cache_hits.get();
        let total = state
            .metrics
            .source_last_resolved
            .collect()
            .first()
            .map(|mf| mf.get_metric().len())
            .unwrap_or(0);

        DynamicSourcesSummary {
            total,
            resolves_total: resolves,
            errors_total: errors,
            cache_hits,
        }
    });

    let resp = StatusResponse {
        status: if state.health.is_ready() {
            "running".to_string()
        } else {
            "loading".to_string()
        },
        detection_rules: stats.detection_rules,
        correlation_rules: stats.correlation_rules,
        correlation_state_entries: stats.state_entries,
        events_processed: state.metrics.events_processed.get(),
        detection_matches: state.metrics.detection_matches.get(),
        correlation_matches: state.metrics.correlation_matches.get(),
        uptime_seconds: state.start_time.elapsed().as_secs_f64(),
        dynamic_sources,
    };
    Json(resp)
}

async fn trigger_reload(State(state): State<AppState>) -> impl IntoResponse {
    match state.reload_tx.try_send(()) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "reload_triggered" })),
        ),
        Err(_) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "status": "reload_already_pending" })),
        ),
    }
}

async fn list_sources(State(state): State<AppState>) -> impl IntoResponse {
    let mut sources_info = Vec::new();
    for entry in state.source_registry.entries() {
        sources_info.push(serde_json::json!({
            "source_id": entry.source.id,
            "origin": entry.origin.to_string(),
            "type": format!("{:?}", entry.source.source_type).split('{').next().unwrap_or("Unknown").trim(),
            "refresh": format!("{:?}", entry.source.refresh),
            "required": entry.source.required,
        }));
    }

    Json(serde_json::json!({ "sources": sources_info }))
}

async fn resolve_sources(State(state): State<AppState>) -> impl IntoResponse {
    use rsigma_runtime::sources::refresh::RefreshTrigger;

    let Some(tx) = &state.sources_trigger_tx else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no dynamic sources configured" })),
        );
    };

    match tx.try_send(RefreshTrigger::All) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "resolve_triggered" })),
        ),
        Err(_) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "status": "resolve_already_pending" })),
        ),
    }
}

async fn resolve_source_by_id(
    State(state): State<AppState>,
    axum::extract::Path(source_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    use rsigma_runtime::sources::refresh::RefreshTrigger;

    let Some(tx) = &state.sources_trigger_tx else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no dynamic sources configured" })),
        );
    };

    match tx.try_send(RefreshTrigger::Single(source_id.clone())) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "resolve_triggered", "source_id": source_id })),
        ),
        Err(_) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "status": "resolve_already_pending" })),
        ),
    }
}

async fn invalidate_source_cache(
    State(state): State<AppState>,
    axum::extract::Path(source_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let Some(resolver) = &state.source_resolver else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no dynamic sources configured" })),
        );
    };

    resolver.cache().invalidate(&source_id);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "invalidated", "source_id": source_id })),
    )
}

// ---------------------------------------------------------------------------
// Field observability handlers
// ---------------------------------------------------------------------------

/// Default `?limit=` value for the paginated `/api/v1/fields/*` endpoints.
const FIELDS_DEFAULT_LIMIT: usize = 100;
/// Hard upper bound on `?limit=` to keep response payloads bounded even
/// when an operator asks for everything.
const FIELDS_MAX_LIMIT: usize = 1000;
/// Maximum number of rule titles surfaced per missing-field entry. The
/// API also reports `truncated: true` when a field carries more.
const MISSING_RULE_TITLES_CAP: usize = 10;

#[derive(serde::Deserialize, Default)]
struct FieldsQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

impl FieldsQuery {
    fn limit(&self) -> usize {
        self.limit
            .unwrap_or(FIELDS_DEFAULT_LIMIT)
            .min(FIELDS_MAX_LIMIT)
    }
    fn offset(&self) -> usize {
        self.offset.unwrap_or(0)
    }
}

/// Parse the `--on-unknown` policy string, exiting on an invalid value.
fn parse_on_unknown_policy(s: &str) -> OnUnknown {
    match s.to_ascii_lowercase().as_str() {
        "warn" => OnUnknown::Warn,
        "drop" => OnUnknown::Drop,
        "passthrough" => OnUnknown::Passthrough,
        "error" => OnUnknown::Error,
        other => {
            eprintln!(
                "Invalid --on-unknown policy '{other}' (expected warn, drop, passthrough, or error)"
            );
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }
}

/// Build a [`RoutingSpec`] from the schema config (signatures + routing
/// bindings) for the daemon's `RuntimeEngine` to (re)build its router from.
fn build_routing_spec(
    schema_config: Option<&Path>,
    on_unknown_override: Option<&str>,
    partition_rules: bool,
) -> RoutingSpec {
    let (signatures, routing) = match schema_config {
        Some(path) => match load_schema_config(path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error loading schema config: {e}");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
        },
        None => (Vec::new(), None),
    };

    let classifier = if signatures.is_empty() {
        SchemaClassifier::builtin()
    } else {
        SchemaClassifier::with_user_signatures(signatures)
    };

    let mut routing = routing.unwrap_or_default();
    if let Some(policy) = on_unknown_override {
        routing.on_unknown = parse_on_unknown_policy(policy);
    }
    if routing.bindings.is_empty() {
        tracing::warn!(
            "schema routing is on but no routing bindings are configured; every event routes to the default pipeline-set"
        );
    }

    let plan = RoutingPlan::from_config(&routing);
    let pipeline_sets: Vec<Vec<Pipeline>> = plan
        .pipeline_sets()
        .iter()
        .map(|names| {
            let paths: Vec<PathBuf> = names.iter().map(PathBuf::from).collect();
            crate::load_pipelines(&paths)
        })
        .collect();

    RoutingSpec {
        classifier,
        plan,
        pipeline_sets,
        partition_rules,
    }
}

fn observation_disabled_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "field observation disabled",
            "hint": "restart the daemon with --observe-fields to enable /api/v1/fields/*",
        })),
    )
        .into_response()
}

/// `GET /api/v1/schemas`: the live per-schema breakdown and unknown rate from
/// the opt-in schema observer. Returns 503 when `--observe-schemas` is off.
async fn schemas_full(State(state): State<AppState>) -> Response {
    let Some(observer) = state.schema_observer.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "schema observation disabled",
                "hint": "restart the daemon with --observe-schemas to enable /api/v1/schemas",
            })),
        )
            .into_response();
    };
    let snapshot = observer.snapshot();
    state.metrics.update_schema_observer_metrics(&snapshot);

    let by_schema: Vec<serde_json::Value> = snapshot
        .by_schema
        .iter()
        .map(|e| serde_json::json!({ "schema": e.schema, "count": e.count }))
        .collect();

    let unknown_shapes: Vec<serde_json::Value> = snapshot
        .unknown_shapes
        .iter()
        .map(|s| serde_json::json!({ "keys": s.keys, "count": s.count }))
        .collect();

    let routing_pruning: Vec<serde_json::Value> = state
        .processor
        .schema_pruning_summary()
        .iter()
        .map(|p| {
            serde_json::json!({
                "schema": p.schema,
                "eligible": p.eligible,
                "pruned": p.pruned,
            })
        })
        .collect();

    let body = serde_json::json!({
        "summary": {
            "events_observed": snapshot.events_observed,
            "classified": snapshot.classified,
            "unknown": snapshot.unknown,
            "ambiguous": snapshot.ambiguous,
            "uptime_seconds": snapshot.uptime_seconds,
        },
        "by_schema": by_schema,
        "unknown_shapes": unknown_shapes,
        "routing_pruning": routing_pruning,
    });

    (StatusCode::OK, Json(body)).into_response()
}

/// `GET /api/v1/schemas/suggestions`: mine the redacted unknown-shape sample
/// into candidate schema signatures for review. The sample is keys-only, so
/// proposals use presence predicates (`source: keys-only`); the offline
/// `engine discover-schemas` command mines a raw corpus for value markers.
/// Returns 503 when `--observe-schemas` is off.
async fn schema_suggestions(State(state): State<AppState>) -> Response {
    let Some(observer) = state.schema_observer.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "schema observation disabled",
                "hint": "restart the daemon with --discover-schemas to enable \
                         /api/v1/schemas/suggestions",
            })),
        )
            .into_response();
    };
    if !observer.discovery_sampling() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "schema discovery sampling disabled",
                "hint": "restart the daemon with --discover-schemas to sample unrecognized \
                         event shapes for /api/v1/schemas/suggestions",
            })),
        )
            .into_response();
    }
    let snapshot = observer.snapshot();
    // Refreshes the per-schema counters and the unknown-cluster gauge.
    state.metrics.update_schema_observer_metrics(&snapshot);

    let report = rsigma_eval::mine_shapes(
        &snapshot.unrecognized_shapes,
        &rsigma_eval::DiscoveryConfig::default(),
    );
    let candidates: Vec<serde_json::Value> = report
        .candidates
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "specificity": c.specificity,
                "source": "keys-only",
                "support": c.support,
                "coverage_of_unknown": c.coverage_of_unknown,
                "predicates": c.predicate_descriptions(),
                "sample_field_sets": c.sample_field_sets,
                "overlap_warnings": c.overlap_warnings,
            })
        })
        .collect();

    let body = serde_json::json!({
        "summary": {
            "events_mined": report.stats.events_mined,
            "shapes": report.stats.shapes,
            "clusters": report.stats.clusters,
            "candidates": report.stats.candidates,
        },
        "candidates": candidates,
        "signatures_yaml": report.to_signatures_yaml(),
    });

    (StatusCode::OK, Json(body)).into_response()
}

/// `DELETE /api/v1/schemas`: reset the schema observer's counters and samples
/// (per-schema counts, unknown shapes, and the discovery sample), so a
/// long-running daemon can refresh a stale discovery sample without a restart.
/// Returns 503 when `--observe-schemas` is off.
async fn schemas_reset(State(state): State<AppState>) -> Response {
    let Some(observer) = state.schema_observer.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "schema observation disabled",
                "hint": "restart the daemon with --observe-schemas to enable /api/v1/schemas",
            })),
        )
            .into_response();
    };
    let (previous_classified, previous_unknown) = observer.reset();
    let snapshot = observer.snapshot();
    state.metrics.update_schema_observer_metrics(&snapshot);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "reset",
            "previous_classified": previous_classified,
            "previous_unknown": previous_unknown,
        })),
    )
        .into_response()
}

fn missing_field_payload(field: &str, origin: &rsigma_eval::FieldOrigin) -> serde_json::Value {
    let mut rule_titles: Vec<&str> = origin.rule_titles.iter().map(String::as_str).collect();
    let total = rule_titles.len();
    let truncated = total > MISSING_RULE_TITLES_CAP;
    rule_titles.truncate(MISSING_RULE_TITLES_CAP);
    let sources: Vec<&str> = origin.sources.iter().map(|s| s.as_str()).collect();
    serde_json::json!({
        "field": field,
        "rule_count": total,
        "sources": sources,
        "rule_titles": rule_titles,
        "truncated": truncated,
    })
}

/// Slice a window out of `items` by moving the page elements out of the
/// source `Vec` rather than cloning. Returns the page, the original
/// total (preserved before the move), and the next offset (if any).
///
/// Consumes `items` because all four field endpoints construct the
/// list fresh from a snapshot and then discard the rest; cloning each
/// `serde_json::Value` just to throw the leftovers away wastes work
/// proportional to `total - limit`.
fn paginate<T>(mut items: Vec<T>, offset: usize, limit: usize) -> (Vec<T>, usize, Option<usize>) {
    let total = items.len();
    if offset >= total {
        return (Vec::new(), total, None);
    }
    let end = offset.saturating_add(limit).min(total);
    items.truncate(end);
    let page: Vec<T> = items.drain(offset..).collect();
    let next_offset = if end < total { Some(end) } else { None };
    (page, total, next_offset)
}

async fn fields_full(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<FieldsQuery>,
) -> Response {
    let Some(observer) = state.field_observer.as_ref() else {
        return observation_disabled_response();
    };
    let snapshot = observer.snapshot();
    state.metrics.update_field_observer_metrics(&snapshot);

    let rule_field_set = state.processor.rule_field_set();
    let coverage = snapshot.coverage(&rule_field_set);

    let unknown_entries: Vec<serde_json::Value> = coverage
        .unknown
        .iter()
        .map(|e| {
            let field: &str = &e.field;
            serde_json::json!({ "field": field, "count": e.count })
        })
        .collect();
    let missing_entries: Vec<serde_json::Value> = coverage
        .missing
        .iter()
        .map(|(name, origin)| missing_field_payload(name, origin))
        .collect();
    let intersection_count = coverage.intersection_count;

    let (unknown_page, unknown_total, unknown_next) =
        paginate(unknown_entries, query.offset(), query.limit());
    let (missing_page, missing_total, missing_next) =
        paginate(missing_entries, query.offset(), query.limit());

    let body = serde_json::json!({
        "summary": {
            "events_observed": snapshot.events_observed,
            "unique_keys_observed": snapshot.unique_keys,
            "rule_fields_loaded": rule_field_set.len(),
            "overflow_dropped": snapshot.overflow_dropped,
            "max_keys": snapshot.max_keys,
            "uptime_seconds": snapshot.uptime_seconds,
            "intersection_count": intersection_count,
            "unknown_count": unknown_total,
            "missing_count": missing_total,
        },
        "unknown": {
            "items": unknown_page,
            "total": unknown_total,
            "offset": query.offset(),
            "limit": query.limit(),
            "next_offset": unknown_next,
        },
        "missing": {
            "items": missing_page,
            "total": missing_total,
            "offset": query.offset(),
            "limit": query.limit(),
            "next_offset": missing_next,
        },
    });

    (StatusCode::OK, Json(body)).into_response()
}

async fn fields_unknown(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<FieldsQuery>,
) -> Response {
    let Some(observer) = state.field_observer.as_ref() else {
        return observation_disabled_response();
    };
    let snapshot = observer.snapshot();
    state.metrics.update_field_observer_metrics(&snapshot);

    let rule_field_set = state.processor.rule_field_set();

    let coverage = snapshot.coverage(&rule_field_set);
    let entries: Vec<serde_json::Value> = coverage
        .unknown
        .iter()
        .map(|e| {
            let field: &str = &e.field;
            serde_json::json!({ "field": field, "count": e.count })
        })
        .collect();
    let (page, total, next_offset) = paginate(entries, query.offset(), query.limit());
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "items": page,
            "total": total,
            "offset": query.offset(),
            "limit": query.limit(),
            "next_offset": next_offset,
        })),
    )
        .into_response()
}

async fn fields_missing(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<FieldsQuery>,
) -> Response {
    let Some(observer) = state.field_observer.as_ref() else {
        return observation_disabled_response();
    };
    let snapshot = observer.snapshot();
    state.metrics.update_field_observer_metrics(&snapshot);

    let rule_field_set = state.processor.rule_field_set();

    let coverage = snapshot.coverage(&rule_field_set);
    let entries: Vec<serde_json::Value> = coverage
        .missing
        .iter()
        .map(|(name, origin)| missing_field_payload(name, origin))
        .collect();
    let (page, total, next_offset) = paginate(entries, query.offset(), query.limit());
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "items": page,
            "total": total,
            "offset": query.offset(),
            "limit": query.limit(),
            "next_offset": next_offset,
        })),
    )
        .into_response()
}

async fn fields_observer_reset(State(state): State<AppState>) -> Response {
    let Some(observer) = state.field_observer.as_ref() else {
        return observation_disabled_response();
    };
    let (previous_keys, previous_events) = observer.reset();
    let snapshot = observer.snapshot();
    state.metrics.update_field_observer_metrics(&snapshot);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "reset",
            "previous_keys": previous_keys,
            "previous_events": previous_events,
        })),
    )
        .into_response()
}

/// Stream a bounded, optionally-redacted window of the live event stream as
/// chunked NDJSON (`GET /api/v1/tap`). The capture ends at `duration` or
/// `limit`, whichever comes first, and a final summary record reports the
/// captured / dropped counts so consumers can detect gaps.
async fn tap_stream(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<super::tap::TapQuery>,
) -> Response {
    let Some(tap) = state.tap.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "event tap disabled",
                "hint": "restart the daemon with --enable-tap (or daemon.tap.enabled: true) to enable GET /api/v1/tap",
            })),
        )
            .into_response();
    };

    let params = match super::tap::parse_params(&query, tap.registry.max_duration()) {
        Ok(params) => params,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": message })),
            )
                .into_response();
        }
    };

    let Some(handle) = tap.registry.register(params.stage) else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "tap session capacity reached",
                "hint": "wait for an active tap to finish, or raise daemon.tap.max_sessions",
            })),
        )
            .into_response();
    };

    super::tap::stream_response(handle, params, tap.metrics.clone())
}

/// Stream live detections as chunked NDJSON (`GET /api/v1/detections/stream`),
/// one result per line, with optional `level` / `rule` filters. Ends at the
/// duration or limit, whichever comes first, and a final summary record
/// reports the streamed / dropped counts.
async fn detections_stream(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<super::tail::TailQuery>,
) -> Response {
    let Some(tail) = state.tail.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "detection tail disabled",
                "hint": "restart the daemon with --enable-tail (or daemon.tail.enabled: true) to enable GET /api/v1/detections/stream",
            })),
        )
            .into_response();
    };

    let params = match super::tail::parse_params(&query) {
        Ok(params) => params,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": message })),
            )
                .into_response();
        }
    };

    match super::tail::stream_response(&tail.registry, params, tail.metrics.clone()) {
        Some(response) => response,
        None => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "tail session capacity reached",
                "hint": "wait for an active tail to finish, or raise daemon.tail.max_sessions",
            })),
        )
            .into_response(),
    }
}

/// Accept events via HTTP POST for processing.
/// Each non-empty line in the request body is parsed using the configured
/// `--input-format` and forwarded to the engine.
async fn ingest_events(State(state): State<AppState>, body: String) -> Response {
    let event_tx = match &state.event_tx {
        Some(tx) => tx,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "event ingestion not enabled (start with --input http)"
                })),
            )
                .into_response();
        }
    };

    const MAX_LINE_BYTES: usize = 1_048_576; // 1 MB

    let mut accepted = 0u64;
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > MAX_LINE_BYTES {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({
                    "error": "line exceeds maximum size",
                    "max_bytes": MAX_LINE_BYTES,
                })),
            )
                .into_response();
        }
        let raw_event = RawEvent {
            payload: line.to_string(),
            ack_token: AckToken::Noop,
        };
        // Mirror `spawn_source`'s accounting so the input-queue-depth and
        // back-pressure metrics are accurate for the HTTP push source too,
        // not just the pull sources (stdin/NATS).
        match event_tx.try_send(raw_event) {
            Ok(()) => state.metrics.on_input_queue_depth_change(1),
            Err(mpsc::error::TrySendError::Full(ev)) => {
                state.metrics.on_back_pressure();
                if event_tx.send(ev).await.is_err() {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(serde_json::json!({
                            "error": "event channel closed",
                            "accepted": accepted,
                        })),
                    )
                        .into_response();
                }
                state.metrics.on_input_queue_depth_change(1);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "event channel closed",
                        "accepted": accepted,
                    })),
                )
                    .into_response();
            }
        }
        accepted += 1;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "accepted": accepted })),
    )
        .into_response()
}

/// Accept OTLP logs via HTTP POST (protobuf or JSON encoding).
///
/// Decodes `ExportLogsServiceRequest` from the request body, flattens each
/// `LogRecord` into a JSON `RawEvent`, and forwards it to the engine pipeline.
/// Always mounted on `/v1/logs` when the `daemon-otlp` feature is compiled in.
///
/// Per the OTLP/HTTP spec, both `application/x-protobuf` and
/// `application/json` content types are supported. When no Content-Type is
/// provided, protobuf is assumed (spec default). Gzip content encoding is
/// supported and transparently decompressed.
#[cfg(feature = "daemon-otlp")]
async fn otlp_http_logs(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/x-protobuf")
        .to_string();

    let is_proto = content_type.starts_with("application/x-protobuf")
        || content_type.starts_with("application/protobuf");
    let is_json = content_type.starts_with("application/json");
    let encoding = if is_proto { "protobuf" } else { "json" };

    let span = tracing::debug_span!("otlp_ingest", transport = "http", encoding);
    async move {
        if !is_proto && !is_json {
            state
                .metrics
                .otlp_errors
                .with_label_values(&["http", "unsupported_content_type"])
                .inc();
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(serde_json::json!({
                    "error": format!(
                        "unsupported content-type: {content_type} \
                         (expected application/x-protobuf or application/json)"
                    )
                })),
            )
                .into_response();
        }

        let body = match otlp_maybe_decompress(&headers, body) {
            Ok(b) => b,
            Err(e) => {
                state
                    .metrics
                    .otlp_errors
                    .with_label_values(&["http", "decompression"])
                    .inc();
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!("decompression error: {e}")
                    })),
                )
                    .into_response();
            }
        };

        let request = if is_proto {
            use prost::Message;
            match rsigma_runtime::ExportLogsServiceRequest::decode(body) {
                Ok(req) => req,
                Err(e) => {
                    state
                        .metrics
                        .otlp_errors
                        .with_label_values(&["http", "decode"])
                        .inc();
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!("protobuf decode error: {e}")
                        })),
                    )
                        .into_response();
                }
            }
        } else {
            match serde_json::from_slice::<rsigma_runtime::ExportLogsServiceRequest>(&body) {
                Ok(req) => req,
                Err(e) => {
                    state
                        .metrics
                        .otlp_errors
                        .with_label_values(&["http", "decode"])
                        .inc();
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!("JSON decode error: {e}")
                        })),
                    )
                        .into_response();
                }
            }
        };

        state
            .metrics
            .otlp_requests
            .with_label_values(&["http", encoding])
            .inc();

        let raw_events = rsigma_runtime::logs_request_to_raw_events(&request);
        let record_count = raw_events.len();
        state.metrics.otlp_log_records.inc_by(record_count as u64);
        tracing::debug!(record_count, "OTLP logs ingested");

        for event in raw_events {
            if state.otlp_event_tx.send(event).await.is_err() {
                state
                    .metrics
                    .otlp_errors
                    .with_label_values(&["http", "channel_closed"])
                    .inc();
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "event channel closed"
                    })),
                )
                    .into_response();
            }
            state.metrics.on_input_queue_depth_change(1);
        }

        (
            StatusCode::OK,
            Json(serde_json::json!({
                "partialSuccess": {
                    "rejectedLogRecords": 0,
                    "errorMessage": ""
                }
            })),
        )
            .into_response()
    }
    .instrument(span)
    .await
}

#[cfg(feature = "daemon-otlp")]
fn otlp_maybe_decompress(
    headers: &axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::body::Bytes, std::io::Error> {
    let content_encoding = headers
        .get(axum::http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_encoding == "gzip" {
        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(&body[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        Ok(axum::body::Bytes::from(decompressed))
    } else {
        Ok(body)
    }
}

#[cfg(feature = "daemon-otlp")]
struct OtlpLogsGrpcService {
    event_tx: mpsc::Sender<RawEvent>,
    metrics: Arc<Metrics>,
    /// API auth table shared with the HTTP layer. The gRPC service is folded
    /// into the router after the axum auth middleware is applied, so it
    /// authenticates its own request metadata and answers with proper gRPC
    /// status codes instead of bare HTTP 401/403.
    auth: Option<super::auth::ApiAuth>,
}

#[cfg(feature = "daemon-otlp")]
#[tonic::async_trait]
impl rsigma_runtime::LogsService for OtlpLogsGrpcService {
    async fn export(
        &self,
        request: tonic::Request<rsigma_runtime::ExportLogsServiceRequest>,
    ) -> Result<tonic::Response<rsigma_runtime::ExportLogsServiceResponse>, tonic::Status> {
        if let Some(auth) = &self.auth {
            let authorization = request
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok());
            match auth.check(authorization, super::auth::EVENTS_INGEST) {
                super::auth::Decision::Allowed(_) => {}
                super::auth::Decision::Unauthorized => {
                    self.metrics
                        .api_auth_failures
                        .with_label_values(&["unauthorized"])
                        .inc();
                    return Err(tonic::Status::unauthenticated(
                        "missing or invalid bearer token",
                    ));
                }
                super::auth::Decision::Forbidden { token } => {
                    self.metrics
                        .api_auth_failures
                        .with_label_values(&["forbidden"])
                        .inc();
                    tracing::warn!(
                        token = %token,
                        "OTLP gRPC auth failure: token lacks events:ingest"
                    );
                    return Err(tonic::Status::permission_denied(
                        "token lacks required permission 'events:ingest'",
                    ));
                }
            }
        }
        let span = tracing::debug_span!("otlp_ingest", transport = "grpc", encoding = "protobuf");
        async move {
            self.metrics
                .otlp_requests
                .with_label_values(&["grpc", "protobuf"])
                .inc();

            let raw_events = rsigma_runtime::logs_request_to_raw_events(&request.into_inner());
            let record_count = raw_events.len();
            self.metrics.otlp_log_records.inc_by(record_count as u64);
            tracing::debug!(record_count, "OTLP logs ingested");

            for event in raw_events {
                self.event_tx.send(event).await.map_err(|_| {
                    self.metrics
                        .otlp_errors
                        .with_label_values(&["grpc", "channel_closed"])
                        .inc();
                    tonic::Status::unavailable("event channel closed")
                })?;
                self.metrics.on_input_queue_depth_change(1);
            }

            Ok(tonic::Response::new(
                rsigma_runtime::ExportLogsServiceResponse::default(),
            ))
        }
        .instrument(span)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "daemon-otlp")]
    mod otlp_grpc_auth {
        use super::super::OtlpLogsGrpcService;
        use super::*;
        use crate::daemon::auth::{ApiAuth, TokenSpec};

        fn auth_table() -> ApiAuth {
            let tokens = [
                TokenSpec {
                    name: "shipper".into(),
                    role: Some("ingest".into()),
                    permissions: None,
                    token_env: "SHIPPER".into(),
                },
                TokenSpec {
                    name: "viewer".into(),
                    role: Some("reader".into()),
                    permissions: None,
                    token_env: "VIEWER".into(),
                },
            ];
            ApiAuth::build(&[], &tokens, &[], |key| match key {
                "SHIPPER" => Some("ship-secret".into()),
                "VIEWER" => Some("view-secret".into()),
                _ => None,
            })
            .unwrap()
        }

        fn service(auth: Option<ApiAuth>) -> (OtlpLogsGrpcService, mpsc::Receiver<RawEvent>) {
            let (event_tx, event_rx) = mpsc::channel(8);
            (
                OtlpLogsGrpcService {
                    event_tx,
                    metrics: Arc::new(Metrics::new()),
                    auth,
                },
                event_rx,
            )
        }

        fn request_with_token(
            token: Option<&str>,
        ) -> tonic::Request<rsigma_runtime::ExportLogsServiceRequest> {
            let mut request =
                tonic::Request::new(rsigma_runtime::ExportLogsServiceRequest::default());
            if let Some(token) = token {
                request
                    .metadata_mut()
                    .insert("authorization", format!("Bearer {token}").parse().unwrap());
            }
            request
        }

        #[tokio::test]
        async fn grpc_export_rejects_missing_token_as_unauthenticated() {
            use rsigma_runtime::LogsService;
            let (svc, _rx) = service(Some(auth_table()));
            let status = svc.export(request_with_token(None)).await.unwrap_err();
            assert_eq!(status.code(), tonic::Code::Unauthenticated);
        }

        #[tokio::test]
        async fn grpc_export_rejects_read_token_as_permission_denied() {
            use rsigma_runtime::LogsService;
            let (svc, _rx) = service(Some(auth_table()));
            let status = svc
                .export(request_with_token(Some("view-secret")))
                .await
                .unwrap_err();
            assert_eq!(status.code(), tonic::Code::PermissionDenied);
        }

        #[tokio::test]
        async fn grpc_export_accepts_ingest_token() {
            use rsigma_runtime::LogsService;
            let (svc, _rx) = service(Some(auth_table()));
            let response = svc.export(request_with_token(Some("ship-secret"))).await;
            assert!(response.is_ok(), "{response:?}");
        }

        #[tokio::test]
        async fn grpc_export_open_without_auth_table() {
            use rsigma_runtime::LogsService;
            let (svc, _rx) = service(None);
            let response = svc.export(request_with_token(None)).await;
            assert!(response.is_ok(), "{response:?}");
        }
    }

    #[test]
    fn force_clear_always_skips() {
        let result = decide_state_restore(
            StateRestoreMode::ForceClear,
            Some(SourcePosition {
                sequence: 100,
                timestamp: 1000,
            }),
            #[cfg(feature = "daemon-nats")]
            &rsigma_runtime::ReplayPolicy::Resume,
        );
        assert!(!result);
    }

    #[test]
    fn force_keep_always_restores() {
        let result = decide_state_restore(
            StateRestoreMode::ForceKeep,
            None,
            #[cfg(feature = "daemon-nats")]
            &rsigma_runtime::ReplayPolicy::Latest,
        );
        assert!(result);
    }

    #[cfg(feature = "daemon-nats")]
    mod nats_auto {
        use super::*;
        use rsigma_runtime::ReplayPolicy;

        #[test]
        fn resume_restores() {
            assert!(decide_state_restore(
                StateRestoreMode::Auto,
                None,
                &ReplayPolicy::Resume,
            ));
        }

        #[test]
        fn latest_skips() {
            assert!(!decide_state_restore(
                StateRestoreMode::Auto,
                Some(SourcePosition {
                    sequence: 100,
                    timestamp: 1000,
                }),
                &ReplayPolicy::Latest,
            ));
        }

        #[test]
        fn forward_sequence_restores() {
            assert!(decide_state_restore(
                StateRestoreMode::Auto,
                Some(SourcePosition {
                    sequence: 100,
                    timestamp: 1000,
                }),
                &ReplayPolicy::FromSequence(101),
            ));
        }

        #[test]
        fn backward_sequence_skips() {
            assert!(!decide_state_restore(
                StateRestoreMode::Auto,
                Some(SourcePosition {
                    sequence: 100,
                    timestamp: 1000,
                }),
                &ReplayPolicy::FromSequence(50),
            ));
        }

        #[test]
        fn equal_sequence_skips() {
            assert!(!decide_state_restore(
                StateRestoreMode::Auto,
                Some(SourcePosition {
                    sequence: 100,
                    timestamp: 1000,
                }),
                &ReplayPolicy::FromSequence(100),
            ));
        }

        #[test]
        fn forward_time_restores() {
            let future = time::OffsetDateTime::from_unix_timestamp(2000).unwrap();
            assert!(decide_state_restore(
                StateRestoreMode::Auto,
                Some(SourcePosition {
                    sequence: 100,
                    timestamp: 1000,
                }),
                &ReplayPolicy::FromTime(future),
            ));
        }

        #[test]
        fn backward_time_skips() {
            let past = time::OffsetDateTime::from_unix_timestamp(500).unwrap();
            assert!(!decide_state_restore(
                StateRestoreMode::Auto,
                Some(SourcePosition {
                    sequence: 100,
                    timestamp: 1000,
                }),
                &ReplayPolicy::FromTime(past),
            ));
        }

        #[test]
        fn no_stored_position_skips_on_replay() {
            assert!(!decide_state_restore(
                StateRestoreMode::Auto,
                None,
                &ReplayPolicy::FromSequence(42),
            ));
        }
    }

    #[cfg(not(feature = "daemon-nats"))]
    #[test]
    fn auto_without_nats_restores() {
        assert!(decide_state_restore(StateRestoreMode::Auto, None));
    }
}
