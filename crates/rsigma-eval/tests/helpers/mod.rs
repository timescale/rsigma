use rsigma_eval::{CorrelationConfig, CorrelationEngine, Engine, Event, MatchResult, ProcessResult};
use rsigma_parser::parse_sigma_yaml;
use serde_json::Value;

pub fn engine_from_yaml(yaml: &str) -> Engine {
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();
    engine
}

pub fn eval(yaml: &str, event_json: Value) -> Vec<MatchResult> {
    let engine = engine_from_yaml(yaml);
    let event = Event::from_value(&event_json);
    engine.evaluate(&event)
}

pub fn corr_engine(yaml: &str) -> CorrelationEngine {
    corr_engine_with_config(yaml, CorrelationConfig::default())
}

pub fn corr_engine_with_config(yaml: &str, config: CorrelationConfig) -> CorrelationEngine {
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();
    engine
}

pub fn process(engine: &mut CorrelationEngine, event_json: Value, ts: i64) -> ProcessResult {
    let event = Event::from_value(&event_json);
    engine.process_event_at(&event, ts)
}
