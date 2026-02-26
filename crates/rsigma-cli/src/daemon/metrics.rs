use prometheus::{
    Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry, TextEncoder,
};

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
