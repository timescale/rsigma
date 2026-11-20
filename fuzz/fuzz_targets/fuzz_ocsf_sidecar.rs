#![no_main]

use libfuzzer_sys::fuzz_target;
use rsigma_eval::{CorrelationBody, DetectionBody, EvaluationResult, ResultBody, RuleHeader};
use rsigma_parser::CorrelationType;
use rsigma_runtime::ocsf::{
    OcsfOptions, OcsfVersion, dedup_summary_finding_opts, risk_event_finding_opts,
};
use rsigma_runtime::{EnricherKind, RiskEvent, render_webhook_body};
use std::collections::HashMap;
use std::sync::Arc;

// Exercise the OCSF sidecar mappers and the webhook JSON body renderer.
fuzz_target!(|data: &[u8]| {
    let opts = if data.first().copied().unwrap_or(0) % 2 == 0 {
        OcsfOptions::new(OcsfVersion::V1_1_0)
    } else {
        OcsfOptions::new(OcsfVersion::V1_3_0)
    };
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let finding = dedup_summary_finding_opts(&value, opts.clone());
        let _ = serde_json::to_vec(&finding);
        if let Ok(event) = serde_json::from_value::<RiskEvent>(value) {
            let finding = risk_event_finding_opts(&event, opts);
            let _ = serde_json::to_vec(&finding);
        }
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (kind, result) = if text.contains("${correlation.") {
        (EnricherKind::Correlation, correlation_result())
    } else {
        (EnricherKind::Detection, detection_result())
    };
    let _ = render_webhook_body(text, kind, "fuzz", &result, || {
        r#"{"class_uid":2004}"#.to_string()
    });
});

fn detection_result() -> EvaluationResult {
    EvaluationResult {
        header: header(),
        body: ResultBody::Detection(DetectionBody {
            matched_selections: Vec::new(),
            matched_fields: Vec::new(),
            event: None,
        }),
    }
}

fn correlation_result() -> EvaluationResult {
    EvaluationResult {
        header: header(),
        body: ResultBody::Correlation(CorrelationBody {
            correlation_type: CorrelationType::EventCount,
            group_key: Vec::new(),
            aggregated_value: 0.0,
            timespan_secs: 0,
            events: None,
            event_refs: None,
        }),
    }
}

fn header() -> RuleHeader {
    RuleHeader {
        rule_title: "fuzz".to_string(),
        rule_id: None,
        tenant_id: None,
        level: None,
        tags: Vec::new(),
        custom_attributes: Arc::new(HashMap::new()),
        enrichments: None,
        ruleset: None,
    }
}
