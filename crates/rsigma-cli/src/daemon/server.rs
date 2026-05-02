use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rsigma_eval::{CorrelationConfig, Pipeline, ProcessResult};
use rsigma_runtime::{
    AckToken, FileSink, InputFormat, LogProcessor, MetricsHook, RawEvent, RuntimeEngine, Sink,
    StdinSource, StdoutSink, spawn_source,
};
use serde::Serialize;
use tokio::sync::mpsc;

/// A dead-letter queue entry for events that fail processing.
#[derive(Serialize)]
struct DlqEntry {
    original_event: String,
    error: String,
    timestamp: String,
}

use super::health::HealthState;
use super::metrics::Metrics;
use super::reload;
use super::store::{SourcePosition, SqliteStateStore};
use crate::EventFilter;

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
    /// Channel for OTLP event ingestion. Always set when daemon-otlp is compiled in.
    #[cfg(feature = "daemon-otlp")]
    otlp_event_tx: mpsc::Sender<RawEvent>,
}

#[derive(Clone)]
pub struct DaemonConfig {
    pub rules_path: PathBuf,
    pub pipelines: Vec<Pipeline>,
    pub corr_config: CorrelationConfig,
    pub include_event: bool,
    pub pretty: bool,
    pub api_addr: SocketAddr,
    pub event_filter: Arc<EventFilter>,
    pub state_db: Option<PathBuf>,
    pub state_save_interval: u64,
    pub input: String,
    pub output: Vec<String>,
    pub buffer_size: usize,
    pub batch_size: usize,
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
}

pub async fn run_daemon(config: DaemonConfig) {
    let metrics = Arc::new(Metrics::new());
    let health = HealthState::new();

    // Open SQLite state store if configured
    let state_store = config.state_db.as_ref().map(|path| {
        let store = SqliteStateStore::open(path).unwrap_or_else(|e| {
            tracing::error!(error = %e, path = %path.display(), "Failed to open state database");
            std::process::exit(1);
        });
        tracing::info!(path = %path.display(), "State database opened");
        Arc::new(store)
    });

    let engine = RuntimeEngine::new(
        config.rules_path.clone(),
        config.pipelines.clone(),
        config.corr_config.clone(),
        config.include_event,
    );
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
            std::process::exit(1);
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
    if let Some(ref store) = state_store {
        match store.load().await {
            Ok(Some((snapshot, stored_position))) => {
                let should_restore = decide_state_restore(
                    config.state_restore_mode,
                    stored_position,
                    #[cfg(feature = "daemon-nats")]
                    &config.replay_policy,
                );
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

    let (reload_tx, mut reload_rx) = mpsc::channel::<()>(4);

    // File watcher for hot-reload
    let _watcher = if config.rules_path.is_dir() {
        reload::spawn_file_watcher(&config.rules_path, reload_tx.clone())
    } else {
        reload::spawn_file_watcher(
            config.rules_path.parent().unwrap_or(&config.rules_path),
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

    let app_state = AppState {
        processor: processor.clone(),
        metrics: metrics.clone(),
        health: health.clone(),
        reload_tx: reload_tx.clone(),
        start_time,
        event_tx: http_event_tx,
        #[cfg(feature = "daemon-otlp")]
        otlp_event_tx,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .route("/api/v1/rules", get(list_rules))
        .route("/api/v1/status", get(status))
        .route("/api/v1/reload", post(trigger_reload))
        .route("/api/v1/events", post(ingest_events));

    #[cfg(feature = "daemon-otlp")]
    let app = app.route("/v1/logs", post(otlp_http_logs));

    let app = app.with_state(app_state);

    let listener = tokio::net::TcpListener::bind(config.api_addr)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(addr = %config.api_addr, error = %e, "Failed to bind API server");
            std::process::exit(1);
        });
    let actual_addr = listener.local_addr().unwrap_or(config.api_addr);

    #[cfg(feature = "daemon-otlp")]
    let otlp_routes = {
        let grpc_service = rsigma_runtime::LogsServiceServer::new(OtlpLogsGrpcService {
            event_tx: event_tx.clone(),
            metrics: metrics.clone(),
        })
        .accept_compressed(tonic::codec::CompressionEncoding::Gzip)
        .send_compressed(tonic::codec::CompressionEncoding::Gzip);
        tonic::service::Routes::from(app).add_service(grpc_service)
    };

    #[cfg(feature = "daemon-otlp")]
    tracing::info!(addr = %actual_addr, "API server listening (HTTP/2 + gRPC)");
    #[cfg(not(feature = "daemon-otlp"))]
    tracing::info!(addr = %actual_addr, "API server listening");

    // Spawn SIGHUP listener
    let sighup_tx = reload_tx.clone();
    tokio::spawn(async move {
        reload::sighup_listener(sighup_tx).await;
    });

    // Spawn reload handler — uses LogProcessor::reload_rules for atomic hot-reload
    let reload_processor = processor.clone();
    let reload_metrics = metrics.clone();
    let reload_health = health.clone();
    tokio::spawn(async move {
        while reload_rx.recv().await.is_some() {
            // Debounce: batch rapid file changes
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            while reload_rx.try_recv().is_ok() {}

            reload_metrics.reloads_total.inc();
            tracing::info!("Reloading rules...");

            match reload_processor.reload_rules() {
                Ok(stats) => {
                    tracing::info!(
                        detection_rules = stats.detection_rules,
                        correlation_rules = stats.correlation_rules,
                        path = %reload_processor.rules_path().display(),
                        "Rules reloaded"
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
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(save_interval_secs));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                if let Some(snapshot) = save_processor.export_state() {
                    let position = source_position_from_atomics(&save_hw_seq, &save_hw_ts);
                    if let Err(e) = save_store.save(&snapshot, position.as_ref()).await {
                        tracing::warn!(error = %e, "Failed to save periodic state snapshot");
                    } else {
                        tracing::debug!("Periodic state snapshot saved");
                    }
                }
            }
        });
    }

    // --- Streaming pipeline: source -> engine -> sink -> ack ---
    let (sink_tx, mut sink_rx) = mpsc::channel::<(ProcessResult, Vec<AckToken>)>(buffer_size);
    let (ack_tx, mut ack_rx) = mpsc::channel::<AckToken>(buffer_size);

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
                    std::process::exit(1);
                }
            }
        }
        other => {
            tracing::error!(
                input = other,
                "Unsupported input source (supported: stdin, http, nats://)"
            );
            std::process::exit(1);
        }
    };

    // Build optional DLQ sink from --dlq flag
    let (dlq_tx, mut dlq_rx) = mpsc::channel::<DlqEntry>(buffer_size);
    let dlq_sink = if let Some(ref dlq_spec) = config.dlq {
        let sink = build_sink(dlq_spec, false, &config).await;
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
    let engine_source_done = source_done_notify;
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
            engine_metrics.observe_batch_size(batch.len() as u64);

            // Pre-parse: route parse failures to DLQ before processing.
            let mut valid_payloads = Vec::with_capacity(batch.len());
            let mut valid_tokens = Vec::with_capacity(batch.len());

            for raw_event in batch {
                if dlq_enabled
                    && !raw_event.payload.trim().is_empty()
                    && rsigma_runtime::parse_line(&raw_event.payload, &input_format).is_none()
                {
                    let _ = engine_dlq_tx
                        .send(DlqEntry {
                            original_event: raw_event.payload,
                            error: "parse error".to_string(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        })
                        .await;
                    if engine_ack_tx.send(raw_event.ack_token).await.is_err() {
                        break;
                    }
                    continue;
                }
                valid_payloads.push(raw_event.payload);
                valid_tokens.push(raw_event.ack_token);
            }

            if valid_payloads.is_empty() {
                engine_metrics.observe_pipeline_latency(pipeline_start.elapsed().as_secs_f64());
                continue;
            }

            let results: Vec<ProcessResult> = engine_processor.process_batch_with_format(
                &valid_payloads,
                &input_format,
                Some(&filter_fn),
            );

            let mut shutdown = false;

            for (result, ack_token) in results.into_iter().zip(valid_tokens) {
                if result.detections.is_empty() && result.correlations.is_empty() {
                    if engine_ack_tx.send(ack_token).await.is_err() {
                        tracing::debug!("Ack channel closed, engine shutting down");
                        shutdown = true;
                        break;
                    }
                    continue;
                }
                engine_metrics.on_output_queue_depth_change(1);
                if sink_tx.send((result, vec![ack_token])).await.is_err() {
                    tracing::debug!("Sink channel closed, engine shutting down");
                    shutdown = true;
                    break;
                }
            }

            engine_metrics.observe_pipeline_latency(pipeline_start.elapsed().as_secs_f64());

            if shutdown {
                break;
            }
        }
        tracing::info!("Event source exhausted, engine shutting down");
    });

    // Build sink(s) from --output flags
    let pretty = config.pretty;
    let output_specs = if config.output.is_empty() {
        vec!["stdout".to_string()]
    } else {
        config.output.clone()
    };
    let mut sinks = Vec::new();
    for spec in &output_specs {
        sinks.push(build_sink(spec, pretty, &config).await);
    }
    let sink = if sinks.len() == 1 {
        sinks.pop().unwrap()
    } else {
        Sink::FanOut(sinks)
    };
    tracing::info!(output = ?output_specs, "Sink started");

    // Sink task: reads (ProcessResult, Vec<AckToken>) from channel, writes via
    // Sink dispatch, then forwards ack tokens to the ack task.
    // On sink failure with DLQ enabled, routes the failed result to the DLQ.
    let sink_metrics = metrics.clone();
    let sink_dlq_tx = dlq_tx;
    let sink_handle = tokio::spawn(async move {
        let mut sink = sink;
        while let Some((result, ack_tokens)) = sink_rx.recv().await {
            sink_metrics.on_output_queue_depth_change(-1);
            if let Err(e) = sink.send(&result).await {
                tracing::warn!(error = %e, "Error writing to sink");
                let serialized = serde_json::to_string(&result).unwrap_or_default();
                let _ = sink_dlq_tx
                    .send(DlqEntry {
                        original_event: serialized,
                        error: format!("sink delivery failure: {e}"),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    })
                    .await;
            }
            for token in ack_tokens {
                if ack_tx.send(token).await.is_err() {
                    tracing::debug!("Ack channel closed");
                    return;
                }
            }
        }
    });

    // DLQ writer task: writes DLQ entries to the configured DLQ sink.
    let dlq_metrics = metrics.clone();
    let dlq_handle = tokio::spawn(async move {
        let mut dlq_sink = dlq_sink;
        while let Some(entry) = dlq_rx.recv().await {
            dlq_metrics.dlq_events.inc();
            if let Some(ref mut sink) = dlq_sink {
                let json = serde_json::to_string(&entry).unwrap_or_default();
                if let Err(e) = sink.send_raw(&json).await {
                    tracing::warn!(error = %e, "Failed to write to DLQ sink");
                }
            }
        }
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

    #[cfg(feature = "daemon-otlp")]
    let mut serve_handle = {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tokio::spawn(async move {
            if let Err(e) = tonic::transport::Server::builder()
                .accept_http1(true)
                .serve_with_incoming_shutdown(otlp_routes, incoming, async {
                    tokio::signal::ctrl_c().await.ok();
                    tracing::info!("Shutdown signal received");
                })
                .await
            {
                tracing::error!(error = %e, "server error");
            }
        })
    };
    #[cfg(not(feature = "daemon-otlp"))]
    let mut serve_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                tokio::signal::ctrl_c().await.ok();
                tracing::info!("Shutdown signal received");
            })
            .await
        {
            tracing::error!(error = %e, "server error");
        }
    });

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
        }

        let drain = async {
            let _ = sink_handle.await;
            let _ = dlq_handle.await;
            let _ = ack_handle.await;
        };
        if tokio::time::timeout(drain_duration, drain).await.is_err() {
            tracing::warn!(
                timeout_secs = config.drain_timeout,
                "Drain timeout exceeded, some events may be lost"
            );
        }
    } else {
        let _ = sink_handle.await;
        let _ = dlq_handle.await;
        let _ = ack_handle.await;
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
}

/// Build a single Sink from an output spec string.
async fn build_sink(
    spec: &str,
    pretty: bool,
    #[cfg_attr(not(feature = "daemon-nats"), allow(unused))] config: &DaemonConfig,
) -> Sink {
    if spec == "stdout" || spec == "stdout://" {
        return Sink::Stdout(StdoutSink::new(pretty));
    }

    if let Some(path) = spec.strip_prefix("file://") {
        let path = std::path::Path::new(path);
        return match FileSink::open(path) {
            Ok(file_sink) => {
                tracing::info!(path = %path.display(), "File sink opened");
                Sink::File(file_sink)
            }
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "Failed to open file sink");
                std::process::exit(1);
            }
        };
    }

    #[cfg(feature = "daemon-nats")]
    if spec.starts_with("nats://") {
        let (url, subject) = parse_nats_url(spec);
        let mut nats_cfg = config.nats_config.clone();
        nats_cfg.url = url.clone();
        return match rsigma_runtime::NatsSink::connect(&nats_cfg, &subject).await {
            Ok(nats_sink) => {
                tracing::info!(url = url, subject = subject, "NATS sink started");
                Sink::Nats(Box::new(nats_sink))
            }
            Err(e) => {
                tracing::error!(error = %e, url = url, "Failed to connect NATS sink");
                std::process::exit(1);
            }
        };
    }

    tracing::error!(
        output = spec,
        "Unsupported output sink (supported: stdout, file://<path>, nats://)"
    );
    std::process::exit(1);
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
}

async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.processor.stats();
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

    let mut accepted = 0u64;
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let raw_event = RawEvent {
            payload: line.to_string(),
            ack_token: AckToken::Noop,
        };
        if event_tx.send(raw_event).await.is_err() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "event channel closed",
                    "accepted": accepted,
                })),
            )
                .into_response();
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
        .unwrap_or("application/x-protobuf");

    let is_proto = content_type.starts_with("application/x-protobuf")
        || content_type.starts_with("application/protobuf");
    let is_json = content_type.starts_with("application/json");
    let encoding = if is_proto { "protobuf" } else { "json" };

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
    state
        .metrics
        .otlp_log_records
        .inc_by(raw_events.len() as u64);

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
}

#[cfg(feature = "daemon-otlp")]
#[tonic::async_trait]
impl rsigma_runtime::LogsService for OtlpLogsGrpcService {
    async fn export(
        &self,
        request: tonic::Request<rsigma_runtime::ExportLogsServiceRequest>,
    ) -> Result<tonic::Response<rsigma_runtime::ExportLogsServiceResponse>, tonic::Status> {
        self.metrics
            .otlp_requests
            .with_label_values(&["grpc", "protobuf"])
            .inc();

        let raw_events = rsigma_runtime::logs_request_to_raw_events(&request.into_inner());
        self.metrics
            .otlp_log_records
            .inc_by(raw_events.len() as u64);

        for event in raw_events {
            self.event_tx.send(event).await.map_err(|_| {
                self.metrics
                    .otlp_errors
                    .with_label_values(&["grpc", "channel_closed"])
                    .inc();
                tonic::Status::unavailable("event channel closed")
            })?;
        }

        Ok(tonic::Response::new(
            rsigma_runtime::ExportLogsServiceResponse::default(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
