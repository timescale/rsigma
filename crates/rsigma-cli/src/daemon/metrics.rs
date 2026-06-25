use prometheus::{
    Gauge, GaugeVec, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Opts, Registry, TextEncoder,
};
use rsigma_runtime::MetricsHook;

#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    pub events_processed: IntCounter,
    pub detection_matches: IntCounter,
    pub correlation_matches: IntCounter,
    pub events_parse_errors: IntCounter,
    pub detection_rules_loaded: IntGauge,
    pub correlation_rules_loaded: IntGauge,
    pub correlation_state_entries: IntGauge,
    pub reloads_total: IntCounter,
    pub reloads_failed: IntCounter,
    pub processing_latency: Histogram,
    pub uptime_seconds: Gauge,
    pub input_queue_depth: IntGauge,
    pub output_queue_depth: IntGauge,
    pub back_pressure_events: IntCounter,
    pub pipeline_latency: Histogram,
    pub batch_size_histogram: Histogram,
    pub dlq_events: IntCounter,
    pub sink_queue_depth: IntGaugeVec,
    pub sink_retries_total: IntCounterVec,
    pub sink_dropped_total: IntCounterVec,
    pub sink_delivery_failures_total: IntCounterVec,
    pub webhook_requests_total: IntCounterVec,
    pub webhook_request_duration_seconds: prometheus::HistogramVec,
    pub detection_matches_by_rule: IntCounterVec,
    pub correlation_matches_by_rule: IntCounterVec,
    pub source_resolves_total: IntCounterVec,
    pub source_resolve_errors: IntCounterVec,
    pub source_resolve_latency: Histogram,
    pub source_cache_hits: IntCounter,
    pub source_last_resolved: GaugeVec,
    pub enrichment_total: IntCounterVec,
    pub enrichment_duration_seconds: prometheus::HistogramVec,
    pub enrichment_queue_depth: IntGauge,
    pub enrichment_http_cache_hits_total: IntCounterVec,
    pub enrichment_http_cache_misses_total: IntCounterVec,
    pub enrichment_http_cache_expirations_total: IntCounterVec,
    #[cfg(feature = "daemon-otlp")]
    pub otlp_requests: IntCounterVec,
    #[cfg(feature = "daemon-otlp")]
    pub otlp_log_records: IntCounter,
    #[cfg(feature = "daemon-otlp")]
    pub otlp_errors: IntCounterVec,
    #[cfg(feature = "daemon-tls")]
    pub tls_certificate_expiry_seconds: Gauge,
    #[cfg(feature = "daemon-tls")]
    pub tls_active_connections: std::sync::Arc<IntGauge>,
    pub fields_observed_total: IntCounter,
    pub fields_observer_unique_keys: IntGauge,
    pub fields_observer_overflow_dropped_total: IntCounter,
    pub events_by_schema: IntCounterVec,
    pub events_unknown_schema: IntCounter,
    pub rules_pruned_by_logsource: IntCounter,
    pub events_without_logsource: IntCounter,
    pub tap_sessions_total: IntCounter,
    pub tap_active_sessions: IntGauge,
    pub tap_events_streamed_total: IntCounter,
    pub tap_events_dropped_total: IntCounter,
    pub tail_active_sessions: IntGauge,
    pub tail_detections_dropped_total: IntCounter,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let events_processed = IntCounter::with_opts(Opts::new(
            "rsigma_events_processed_total",
            "Total events processed",
        ))
        .unwrap();
        let detection_matches = IntCounter::with_opts(Opts::new(
            "rsigma_detection_matches_total",
            "Total detection matches",
        ))
        .unwrap();
        let correlation_matches = IntCounter::with_opts(Opts::new(
            "rsigma_correlation_matches_total",
            "Total correlation matches",
        ))
        .unwrap();
        let events_parse_errors = IntCounter::with_opts(Opts::new(
            "rsigma_events_parse_errors_total",
            "JSON parse errors on input",
        ))
        .unwrap();
        let detection_rules_loaded = IntGauge::with_opts(Opts::new(
            "rsigma_detection_rules_loaded",
            "Number of detection rules loaded",
        ))
        .unwrap();
        let correlation_rules_loaded = IntGauge::with_opts(Opts::new(
            "rsigma_correlation_rules_loaded",
            "Number of correlation rules loaded",
        ))
        .unwrap();
        let correlation_state_entries = IntGauge::with_opts(Opts::new(
            "rsigma_correlation_state_entries",
            "Active correlation state entries",
        ))
        .unwrap();
        let reloads_total = IntCounter::with_opts(Opts::new(
            "rsigma_reloads_total",
            "Total rule reload attempts",
        ))
        .unwrap();
        let reloads_failed = IntCounter::with_opts(Opts::new(
            "rsigma_reloads_failed_total",
            "Failed rule reload attempts",
        ))
        .unwrap();
        let processing_latency = Histogram::with_opts(
            HistogramOpts::new(
                "rsigma_event_processing_seconds",
                "Per-event processing latency",
            )
            .buckets(vec![
                0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1,
            ]),
        )
        .unwrap();
        let uptime_seconds = Gauge::with_opts(Opts::new(
            "rsigma_uptime_seconds",
            "Daemon uptime in seconds",
        ))
        .unwrap();
        let input_queue_depth = IntGauge::with_opts(Opts::new(
            "rsigma_input_queue_depth",
            "Current events buffered in source→engine channel",
        ))
        .unwrap();
        let output_queue_depth = IntGauge::with_opts(Opts::new(
            "rsigma_output_queue_depth",
            "Current results buffered in engine→sink channel",
        ))
        .unwrap();
        let back_pressure_events = IntCounter::with_opts(Opts::new(
            "rsigma_back_pressure_events_total",
            "Times a source was blocked on a full event channel",
        ))
        .unwrap();
        let pipeline_latency = Histogram::with_opts(
            HistogramOpts::new(
                "rsigma_pipeline_latency_seconds",
                "End-to-end latency from event dequeue to sink send",
            )
            .buckets(vec![
                0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5,
            ]),
        )
        .unwrap();
        let batch_size_histogram = Histogram::with_opts(
            HistogramOpts::new("rsigma_batch_size", "Number of events processed per batch")
                .buckets(vec![
                    1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0,
                ]),
        )
        .unwrap();
        let dlq_events = IntCounter::with_opts(Opts::new(
            "rsigma_dlq_events_total",
            "Events routed to dead-letter queue",
        ))
        .unwrap();
        let sink_queue_depth = IntGaugeVec::new(
            Opts::new(
                "rsigma_sink_queue_depth",
                "Results buffered in each sink's delivery queue",
            ),
            &["sink"],
        )
        .unwrap();
        let sink_retries_total = IntCounterVec::new(
            Opts::new(
                "rsigma_sink_retries_total",
                "Sink delivery retries after a retryable failure",
            ),
            &["sink"],
        )
        .unwrap();
        let sink_dropped_total = IntCounterVec::new(
            Opts::new(
                "rsigma_sink_dropped_total",
                "Results dropped because a lossy sink's queue was full",
            ),
            &["sink"],
        )
        .unwrap();
        let sink_delivery_failures_total = IntCounterVec::new(
            Opts::new(
                "rsigma_sink_delivery_failures_total",
                "Sink deliveries that exhausted retries and were routed to the DLQ",
            ),
            &["sink"],
        )
        .unwrap();
        let webhook_requests_total = IntCounterVec::new(
            Opts::new(
                "rsigma_webhook_requests_total",
                "Webhook requests by outcome (success, permanent_failure, rate_limited_wait)",
            ),
            &["webhook_id", "outcome"],
        )
        .unwrap();
        let webhook_request_duration_seconds = prometheus::HistogramVec::new(
            HistogramOpts::new(
                "rsigma_webhook_request_duration_seconds",
                "Per-webhook HTTP request latency",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["webhook_id"],
        )
        .unwrap();
        let detection_matches_by_rule = IntCounterVec::new(
            Opts::new(
                "rsigma_detection_matches_by_rule_total",
                "Detection matches per rule",
            ),
            &["rule_title", "level"],
        )
        .unwrap();
        let correlation_matches_by_rule = IntCounterVec::new(
            Opts::new(
                "rsigma_correlation_matches_by_rule_total",
                "Correlation matches per rule",
            ),
            &["rule_title", "level", "correlation_type"],
        )
        .unwrap();

        registry
            .register(Box::new(events_processed.clone()))
            .unwrap();
        registry
            .register(Box::new(detection_matches.clone()))
            .unwrap();
        registry
            .register(Box::new(correlation_matches.clone()))
            .unwrap();
        registry
            .register(Box::new(events_parse_errors.clone()))
            .unwrap();
        registry
            .register(Box::new(detection_rules_loaded.clone()))
            .unwrap();
        registry
            .register(Box::new(correlation_rules_loaded.clone()))
            .unwrap();
        registry
            .register(Box::new(correlation_state_entries.clone()))
            .unwrap();
        registry.register(Box::new(reloads_total.clone())).unwrap();
        registry.register(Box::new(reloads_failed.clone())).unwrap();
        registry
            .register(Box::new(processing_latency.clone()))
            .unwrap();
        registry.register(Box::new(uptime_seconds.clone())).unwrap();
        registry
            .register(Box::new(input_queue_depth.clone()))
            .unwrap();
        registry
            .register(Box::new(output_queue_depth.clone()))
            .unwrap();
        registry
            .register(Box::new(back_pressure_events.clone()))
            .unwrap();
        registry
            .register(Box::new(pipeline_latency.clone()))
            .unwrap();
        registry
            .register(Box::new(batch_size_histogram.clone()))
            .unwrap();
        registry.register(Box::new(dlq_events.clone())).unwrap();
        registry
            .register(Box::new(sink_queue_depth.clone()))
            .unwrap();
        registry
            .register(Box::new(sink_retries_total.clone()))
            .unwrap();
        registry
            .register(Box::new(sink_dropped_total.clone()))
            .unwrap();
        registry
            .register(Box::new(sink_delivery_failures_total.clone()))
            .unwrap();
        registry
            .register(Box::new(webhook_requests_total.clone()))
            .unwrap();
        registry
            .register(Box::new(webhook_request_duration_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(detection_matches_by_rule.clone()))
            .unwrap();
        registry
            .register(Box::new(correlation_matches_by_rule.clone()))
            .unwrap();

        let source_resolves_total = IntCounterVec::new(
            Opts::new(
                "rsigma_source_resolves_total",
                "Total dynamic source resolution attempts",
            ),
            &["source_id", "source_type"],
        )
        .unwrap();
        let source_resolve_errors = IntCounterVec::new(
            Opts::new(
                "rsigma_source_resolve_errors_total",
                "Failed dynamic source resolutions",
            ),
            &["source_id", "error_kind"],
        )
        .unwrap();
        let source_resolve_latency = Histogram::with_opts(
            HistogramOpts::new(
                "rsigma_source_resolve_seconds",
                "Dynamic source resolution latency",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        )
        .unwrap();
        let source_cache_hits = IntCounter::with_opts(Opts::new(
            "rsigma_source_cache_hits_total",
            "Times cached source data was served on resolution failure",
        ))
        .unwrap();
        let source_last_resolved = GaugeVec::new(
            Opts::new(
                "rsigma_source_last_resolved_timestamp",
                "Unix timestamp of last successful resolution per source",
            ),
            &["source_id"],
        )
        .unwrap();

        registry
            .register(Box::new(source_resolves_total.clone()))
            .unwrap();
        registry
            .register(Box::new(source_resolve_errors.clone()))
            .unwrap();
        registry
            .register(Box::new(source_resolve_latency.clone()))
            .unwrap();
        registry
            .register(Box::new(source_cache_hits.clone()))
            .unwrap();
        registry
            .register(Box::new(source_last_resolved.clone()))
            .unwrap();

        let enrichment_total = IntCounterVec::new(
            Opts::new(
                "rsigma_enrichment_total",
                "Total per-result enrichment calls, labeled by enricher and outcome",
            ),
            &["enricher_id", "kind", "status"],
        )
        .unwrap();
        let enrichment_duration_seconds = prometheus::HistogramVec::new(
            HistogramOpts::new("rsigma_enrichment_duration_seconds", "Per-enricher latency")
                .buckets(vec![
                    0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ]),
            &["enricher_id", "kind"],
        )
        .unwrap();
        let enrichment_queue_depth = IntGauge::with_opts(Opts::new(
            "rsigma_enrichment_queue_depth",
            "Pending enrichment calls (sum across both kinds)",
        ))
        .unwrap();
        let enrichment_http_cache_hits_total = IntCounterVec::new(
            Opts::new(
                "rsigma_enrichment_http_cache_hits_total",
                "HTTP enricher response-cache hits",
            ),
            &["enricher_id"],
        )
        .unwrap();
        let enrichment_http_cache_misses_total = IntCounterVec::new(
            Opts::new(
                "rsigma_enrichment_http_cache_misses_total",
                "HTTP enricher response-cache misses",
            ),
            &["enricher_id"],
        )
        .unwrap();
        let enrichment_http_cache_expirations_total = IntCounterVec::new(
            Opts::new(
                "rsigma_enrichment_http_cache_expirations_total",
                "HTTP enricher response-cache entries evicted on expiry",
            ),
            &["enricher_id"],
        )
        .unwrap();

        registry
            .register(Box::new(enrichment_total.clone()))
            .unwrap();
        registry
            .register(Box::new(enrichment_duration_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(enrichment_queue_depth.clone()))
            .unwrap();
        registry
            .register(Box::new(enrichment_http_cache_hits_total.clone()))
            .unwrap();
        registry
            .register(Box::new(enrichment_http_cache_misses_total.clone()))
            .unwrap();
        registry
            .register(Box::new(enrichment_http_cache_expirations_total.clone()))
            .unwrap();

        #[cfg(feature = "daemon-otlp")]
        let otlp_requests = IntCounterVec::new(
            Opts::new(
                "rsigma_otlp_requests_total",
                "OTLP export requests received",
            ),
            &["transport", "encoding"],
        )
        .unwrap();
        #[cfg(feature = "daemon-otlp")]
        let otlp_log_records = IntCounter::with_opts(Opts::new(
            "rsigma_otlp_log_records_total",
            "Log records ingested via OTLP",
        ))
        .unwrap();
        #[cfg(feature = "daemon-otlp")]
        let otlp_errors = IntCounterVec::new(
            Opts::new("rsigma_otlp_errors_total", "OTLP request errors"),
            &["transport", "reason"],
        )
        .unwrap();

        #[cfg(feature = "daemon-otlp")]
        {
            registry.register(Box::new(otlp_requests.clone())).unwrap();
            registry
                .register(Box::new(otlp_log_records.clone()))
                .unwrap();
            registry.register(Box::new(otlp_errors.clone())).unwrap();
        }

        #[cfg(feature = "daemon-tls")]
        let tls_certificate_expiry_seconds = Gauge::with_opts(Opts::new(
            "rsigma_tls_certificate_expiry_seconds",
            "Seconds until the active TLS server certificate's not_after",
        ))
        .unwrap();
        #[cfg(feature = "daemon-tls")]
        let tls_active_connections = std::sync::Arc::new(
            IntGauge::with_opts(Opts::new(
                "rsigma_tls_active_connections",
                "Currently active TLS-terminated connections on the API listener",
            ))
            .unwrap(),
        );
        #[cfg(feature = "daemon-tls")]
        {
            registry
                .register(Box::new(tls_certificate_expiry_seconds.clone()))
                .unwrap();
            registry
                .register(Box::new(tls_active_connections.as_ref().clone()))
                .unwrap();
        }

        let fields_observed_total = IntCounter::with_opts(Opts::new(
            "rsigma_fields_observed_total",
            "Total events scanned by the opt-in field observer (--observe-fields)",
        ))
        .unwrap();
        let fields_observer_unique_keys = IntGauge::with_opts(Opts::new(
            "rsigma_fields_observer_unique_keys",
            "Distinct field names currently tracked by the field observer",
        ))
        .unwrap();
        let fields_observer_overflow_dropped_total = IntCounter::with_opts(Opts::new(
            "rsigma_fields_observer_overflow_dropped_total",
            "New-key insert attempts dropped because the field observer was at capacity",
        ))
        .unwrap();
        registry
            .register(Box::new(fields_observed_total.clone()))
            .unwrap();
        registry
            .register(Box::new(fields_observer_unique_keys.clone()))
            .unwrap();
        registry
            .register(Box::new(fields_observer_overflow_dropped_total.clone()))
            .unwrap();

        let events_by_schema = IntCounterVec::new(
            Opts::new(
                "rsigma_events_by_schema_total",
                "Events classified per schema by the opt-in schema observer (--observe-schemas)",
            ),
            &["schema"],
        )
        .unwrap();
        let events_unknown_schema = IntCounter::with_opts(Opts::new(
            "rsigma_events_unknown_schema_total",
            "Events that matched no schema signature (--observe-schemas)",
        ))
        .unwrap();
        registry
            .register(Box::new(events_by_schema.clone()))
            .unwrap();
        registry
            .register(Box::new(events_unknown_schema.clone()))
            .unwrap();

        let rules_pruned_by_logsource = IntCounter::with_opts(Opts::new(
            "rsigma_rules_pruned_by_logsource_total",
            "Always-evaluated rules skipped by conflict-based logsource pruning (--logsource-routing)",
        ))
        .unwrap();
        let events_without_logsource = IntCounter::with_opts(Opts::new(
            "rsigma_events_without_logsource_total",
            "Events with no extractable logsource, evaluated against every rule (fail-open)",
        ))
        .unwrap();
        registry
            .register(Box::new(rules_pruned_by_logsource.clone()))
            .unwrap();
        registry
            .register(Box::new(events_without_logsource.clone()))
            .unwrap();

        let tap_sessions_total = IntCounter::with_opts(Opts::new(
            "rsigma_tap_sessions_total",
            "Total live event-tap sessions opened (GET /api/v1/tap)",
        ))
        .unwrap();
        let tap_active_sessions = IntGauge::with_opts(Opts::new(
            "rsigma_tap_active_sessions",
            "Currently active live event-tap sessions",
        ))
        .unwrap();
        let tap_events_streamed_total = IntCounter::with_opts(Opts::new(
            "rsigma_tap_events_streamed_total",
            "Events streamed to live event-tap clients",
        ))
        .unwrap();
        let tap_events_dropped_total = IntCounter::with_opts(Opts::new(
            "rsigma_tap_events_dropped_total",
            "Events dropped from a live event-tap (full session buffer or unparseable redacted raw line)",
        ))
        .unwrap();
        registry
            .register(Box::new(tap_sessions_total.clone()))
            .unwrap();
        registry
            .register(Box::new(tap_active_sessions.clone()))
            .unwrap();
        registry
            .register(Box::new(tap_events_streamed_total.clone()))
            .unwrap();
        registry
            .register(Box::new(tap_events_dropped_total.clone()))
            .unwrap();

        let tail_active_sessions = IntGauge::with_opts(Opts::new(
            "rsigma_tail_active_sessions",
            "Currently active live detection-tail sessions",
        ))
        .unwrap();
        let tail_detections_dropped_total = IntCounter::with_opts(Opts::new(
            "rsigma_tail_detections_dropped_total",
            "Detections dropped from a live tail because a session buffer was full",
        ))
        .unwrap();
        registry
            .register(Box::new(tail_active_sessions.clone()))
            .unwrap();
        registry
            .register(Box::new(tail_detections_dropped_total.clone()))
            .unwrap();

        Metrics {
            registry,
            events_processed,
            detection_matches,
            correlation_matches,
            events_parse_errors,
            detection_rules_loaded,
            correlation_rules_loaded,
            correlation_state_entries,
            reloads_total,
            reloads_failed,
            processing_latency,
            uptime_seconds,
            input_queue_depth,
            output_queue_depth,
            back_pressure_events,
            pipeline_latency,
            batch_size_histogram,
            dlq_events,
            sink_queue_depth,
            sink_retries_total,
            sink_dropped_total,
            sink_delivery_failures_total,
            webhook_requests_total,
            webhook_request_duration_seconds,
            detection_matches_by_rule,
            correlation_matches_by_rule,
            source_resolves_total,
            source_resolve_errors,
            source_resolve_latency,
            source_cache_hits,
            source_last_resolved,
            enrichment_total,
            enrichment_duration_seconds,
            enrichment_queue_depth,
            enrichment_http_cache_hits_total,
            enrichment_http_cache_misses_total,
            enrichment_http_cache_expirations_total,
            #[cfg(feature = "daemon-otlp")]
            otlp_requests,
            #[cfg(feature = "daemon-otlp")]
            otlp_log_records,
            #[cfg(feature = "daemon-otlp")]
            otlp_errors,
            #[cfg(feature = "daemon-tls")]
            tls_certificate_expiry_seconds,
            #[cfg(feature = "daemon-tls")]
            tls_active_connections,
            fields_observed_total,
            fields_observer_unique_keys,
            fields_observer_overflow_dropped_total,
            events_by_schema,
            events_unknown_schema,
            rules_pruned_by_logsource,
            events_without_logsource,
            tap_sessions_total,
            tap_active_sessions,
            tap_events_streamed_total,
            tap_events_dropped_total,
            tail_active_sessions,
            tail_detections_dropped_total,
        }
    }

    /// Refresh the field-observer Prometheus gauges from a snapshot.
    /// Called both by the periodic uptime tick path inside the
    /// `/metrics` handler and by the dedicated `/api/v1/fields*`
    /// endpoints so a scrape immediately after a reset reflects the
    /// new state.
    ///
    /// Prometheus counters must be monotonic, so this bridges from the
    /// observer's *lifetime* totals (which never reset) rather than from
    /// `events_observed` / `overflow_dropped` (which reset on
    /// `DELETE /api/v1/fields/observer`). Without that, a reset between
    /// scrapes silently drops every event observed before the
    /// lifetime-total bridge re-overtook the Prometheus counter's
    /// last-known value.
    pub fn update_field_observer_metrics(&self, snapshot: &rsigma_runtime::FieldObservation) {
        self.fields_observer_unique_keys
            .set(snapshot.unique_keys as i64);
        let observed_now = snapshot.lifetime_events_observed;
        let observed_prev = self.fields_observed_total.get();
        if observed_now > observed_prev {
            self.fields_observed_total
                .inc_by(observed_now - observed_prev);
        }
        let overflow_now = snapshot.lifetime_overflow_dropped;
        let overflow_prev = self.fields_observer_overflow_dropped_total.get();
        if overflow_now > overflow_prev {
            self.fields_observer_overflow_dropped_total
                .inc_by(overflow_now - overflow_prev);
        }
    }

    /// Refresh the schema-observer Prometheus counters from a snapshot.
    /// Counters must be monotonic; the schema observer is not API-resettable,
    /// so the per-schema counts and the lifetime unknown total are monotonic
    /// sources bridged via `inc_by(delta)`.
    pub fn update_schema_observer_metrics(&self, snapshot: &rsigma_runtime::SchemaObservation) {
        for entry in &snapshot.by_schema {
            let counter = self
                .events_by_schema
                .with_label_values(&[entry.schema.as_str()]);
            let prev = counter.get();
            if entry.count > prev {
                counter.inc_by(entry.count - prev);
            }
        }
        let unknown_now = snapshot.lifetime_unknown;
        let unknown_prev = self.events_unknown_schema.get();
        if unknown_now > unknown_prev {
            self.events_unknown_schema
                .inc_by(unknown_now - unknown_prev);
        }
    }

    /// Refresh the logsource-pruning Prometheus counters from the engine's
    /// monotonic totals. Both are monotonic sources bridged via `inc_by(delta)`.
    pub fn update_logsource_metrics(&self, pruned_total: u64, absent_total: u64) {
        let pruned_prev = self.rules_pruned_by_logsource.get();
        if pruned_total > pruned_prev {
            self.rules_pruned_by_logsource
                .inc_by(pruned_total - pruned_prev);
        }
        let absent_prev = self.events_without_logsource.get();
        if absent_total > absent_prev {
            self.events_without_logsource
                .inc_by(absent_total - absent_prev);
        }
    }

    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder
            .encode_to_string(&metric_families)
            .unwrap_or_default()
    }
}

/// Bridge from rsigma-runtime's MetricsHook trait to the Prometheus-backed Metrics struct.
impl MetricsHook for Metrics {
    fn on_parse_error(&self) {
        self.events_parse_errors.inc();
    }

    fn on_events_processed(&self, count: u64) {
        self.events_processed.inc_by(count);
    }

    fn on_detection_matches(&self, count: u64) {
        self.detection_matches.inc_by(count);
    }

    fn on_correlation_matches(&self, count: u64) {
        self.correlation_matches.inc_by(count);
    }

    fn observe_processing_latency(&self, seconds: f64) {
        self.processing_latency.observe(seconds);
    }

    fn on_input_queue_depth_change(&self, delta: i64) {
        if delta > 0 {
            self.input_queue_depth.add(delta);
        } else {
            self.input_queue_depth.sub(-delta);
        }
    }

    fn on_back_pressure(&self) {
        self.back_pressure_events.inc();
    }

    fn observe_batch_size(&self, size: u64) {
        self.batch_size_histogram.observe(size as f64);
    }

    fn on_output_queue_depth_change(&self, delta: i64) {
        if delta > 0 {
            self.output_queue_depth.add(delta);
        } else {
            self.output_queue_depth.sub(-delta);
        }
    }

    fn observe_pipeline_latency(&self, seconds: f64) {
        self.pipeline_latency.observe(seconds);
    }

    fn set_correlation_state_entries(&self, count: u64) {
        self.correlation_state_entries.set(count as i64);
    }

    fn on_detection_match_detail(&self, rule_title: &str, level: &str) {
        self.detection_matches_by_rule
            .with_label_values(&[rule_title, level])
            .inc();
    }

    fn on_correlation_match_detail(&self, rule_title: &str, level: &str, correlation_type: &str) {
        self.correlation_matches_by_rule
            .with_label_values(&[rule_title, level, correlation_type])
            .inc();
    }

    fn on_enrichment_completed(
        &self,
        enricher_id: &str,
        kind: &str,
        status: &str,
        duration_seconds: f64,
    ) {
        self.enrichment_total
            .with_label_values(&[enricher_id, kind, status])
            .inc();
        self.enrichment_duration_seconds
            .with_label_values(&[enricher_id, kind])
            .observe(duration_seconds);
    }

    fn on_enrichment_queue_depth_change(&self, delta: i64) {
        if delta > 0 {
            self.enrichment_queue_depth.add(delta);
        } else {
            self.enrichment_queue_depth.sub(-delta);
        }
    }

    fn on_enrichment_http_cache_hit(&self, enricher_id: &str) {
        self.enrichment_http_cache_hits_total
            .with_label_values(&[enricher_id])
            .inc();
    }

    fn on_enrichment_http_cache_miss(&self, enricher_id: &str) {
        self.enrichment_http_cache_misses_total
            .with_label_values(&[enricher_id])
            .inc();
    }

    fn on_enrichment_http_cache_expiration(&self, enricher_id: &str) {
        self.enrichment_http_cache_expirations_total
            .with_label_values(&[enricher_id])
            .inc();
    }

    fn register_enricher(&self, enricher_id: &str, kind: &str) {
        // Pre-create label sets so `# HELP` / `# TYPE` lines for the
        // per-enricher metrics show up on the first /metrics scrape,
        // even before the enricher has fired. `inc_by(0)` and a
        // bare `with_label_values` both materialise the entry; the
        // former is more explicit about the intent.
        for status in ["success", "skip", "error", "timeout", "drop"] {
            self.enrichment_total
                .with_label_values(&[enricher_id, kind, status])
                .inc_by(0);
        }
        // HistogramVec materialises its buckets in `with_label_values`
        // without observing, so this is side-effect-free: the metric
        // appears with all-zero buckets and `_count == 0` until the
        // first `observe(...)` call.
        let _ = self
            .enrichment_duration_seconds
            .with_label_values(&[enricher_id, kind]);
    }

    fn register_http_enricher_cache(&self, enricher_id: &str) {
        self.enrichment_http_cache_hits_total
            .with_label_values(&[enricher_id])
            .inc_by(0);
        self.enrichment_http_cache_misses_total
            .with_label_values(&[enricher_id])
            .inc_by(0);
        self.enrichment_http_cache_expirations_total
            .with_label_values(&[enricher_id])
            .inc_by(0);
    }

    fn register_sink(&self, sink: &str) {
        self.sink_queue_depth.with_label_values(&[sink]).set(0);
        self.sink_retries_total.with_label_values(&[sink]).inc_by(0);
        self.sink_dropped_total.with_label_values(&[sink]).inc_by(0);
        self.sink_delivery_failures_total
            .with_label_values(&[sink])
            .inc_by(0);
    }

    fn on_sink_queue_depth_change(&self, sink: &str, delta: i64) {
        let gauge = self.sink_queue_depth.with_label_values(&[sink]);
        if delta > 0 {
            gauge.add(delta);
        } else {
            gauge.sub(-delta);
        }
    }

    fn on_sink_retry(&self, sink: &str) {
        self.sink_retries_total.with_label_values(&[sink]).inc();
    }

    fn on_sink_dropped(&self, sink: &str) {
        self.sink_dropped_total.with_label_values(&[sink]).inc();
    }

    fn on_sink_delivery_failed(&self, sink: &str) {
        self.sink_delivery_failures_total
            .with_label_values(&[sink])
            .inc();
    }

    fn register_webhook(&self, webhook_id: &str) {
        for outcome in ["success", "permanent_failure", "rate_limited_wait"] {
            self.webhook_requests_total
                .with_label_values(&[webhook_id, outcome])
                .inc_by(0);
        }
        // Materialise the histogram series so panels render before traffic.
        self.webhook_request_duration_seconds
            .with_label_values(&[webhook_id]);
    }

    fn on_webhook_request(&self, webhook_id: &str, outcome: &'static str, duration_secs: f64) {
        self.webhook_requests_total
            .with_label_values(&[webhook_id, outcome])
            .inc();
        self.webhook_request_duration_seconds
            .with_label_values(&[webhook_id])
            .observe(duration_secs);
    }

    fn on_webhook_rate_limited(&self, webhook_id: &str) {
        self.webhook_requests_total
            .with_label_values(&[webhook_id, "rate_limited_wait"])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_matches_by_rule_labels() {
        let m = Metrics::new();
        m.on_detection_match_detail("Detect Whoami", "medium");
        m.on_detection_match_detail("Detect Whoami", "medium");
        m.on_detection_match_detail("Suspicious Login", "high");

        assert_eq!(
            m.detection_matches_by_rule
                .with_label_values(&["Detect Whoami", "medium"])
                .get(),
            2
        );
        assert_eq!(
            m.detection_matches_by_rule
                .with_label_values(&["Suspicious Login", "high"])
                .get(),
            1
        );
    }

    #[test]
    fn correlation_matches_by_rule_labels() {
        let m = Metrics::new();
        m.on_correlation_match_detail("Brute Force", "high", "event_count");
        m.on_correlation_match_detail("Brute Force", "high", "event_count");
        m.on_correlation_match_detail("Lateral Movement", "critical", "temporal");

        assert_eq!(
            m.correlation_matches_by_rule
                .with_label_values(&["Brute Force", "high", "event_count"])
                .get(),
            2
        );
        assert_eq!(
            m.correlation_matches_by_rule
                .with_label_values(&["Lateral Movement", "critical", "temporal"])
                .get(),
            1
        );
    }

    #[test]
    fn labeled_counters_appear_in_encoded_output() {
        let m = Metrics::new();
        m.on_detection_match_detail("Test Rule", "high");
        m.on_correlation_match_detail("Corr Rule", "medium", "event_count");

        let output = m.encode();
        assert!(output.contains("rsigma_detection_matches_by_rule_total"));
        assert!(output.contains(r#"rule_title="Test Rule""#));
        assert!(output.contains(r#"level="high""#));
        assert!(output.contains("rsigma_correlation_matches_by_rule_total"));
        assert!(output.contains(r#"rule_title="Corr Rule""#));
        assert!(output.contains(r#"correlation_type="event_count""#));
    }
}
