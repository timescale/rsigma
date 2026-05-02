use prometheus::{
    Gauge, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
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
    pub detection_matches_by_rule: IntCounterVec,
    pub correlation_matches_by_rule: IntCounterVec,
    #[cfg(feature = "daemon-otlp")]
    pub otlp_requests: IntCounterVec,
    #[cfg(feature = "daemon-otlp")]
    pub otlp_log_records: IntCounter,
    #[cfg(feature = "daemon-otlp")]
    pub otlp_errors: IntCounterVec,
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
            .register(Box::new(detection_matches_by_rule.clone()))
            .unwrap();
        registry
            .register(Box::new(correlation_matches_by_rule.clone()))
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
            detection_matches_by_rule,
            correlation_matches_by_rule,
            #[cfg(feature = "daemon-otlp")]
            otlp_requests,
            #[cfg(feature = "daemon-otlp")]
            otlp_log_records,
            #[cfg(feature = "daemon-otlp")]
            otlp_errors,
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
