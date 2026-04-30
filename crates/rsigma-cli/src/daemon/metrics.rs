use prometheus::{
    Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry, TextEncoder,
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
}
