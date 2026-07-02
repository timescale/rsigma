//! # rsigma-eval
//!
//! Evaluator for Sigma detection and correlation rules.
//!
//! This crate consumes the AST produced by [`rsigma_parser`] and evaluates it
//! against events in real time using a compile-then-evaluate model.
//!
//! ## Architecture
//!
//! - **Detection rules** (stateless): compiled once into optimized matchers,
//!   each event is matched with zero allocation on the hot path.
//! - **Correlation rules** (stateful): time-windowed aggregation over detection
//!   matches, supporting `event_count`, `value_count`, `temporal`,
//!   `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`,
//!   and `value_median`.
//!
//! ## Quick Start — Detection Only
//!
//! ```rust
//! use rsigma_parser::parse_sigma_yaml;
//! use rsigma_eval::Engine;
//! use rsigma_eval::event::JsonEvent;
//! use serde_json::json;
//!
//! let yaml = r#"
//! title: Detect Whoami
//! logsource:
//!     product: windows
//!     category: process_creation
//! detection:
//!     selection:
//!         CommandLine|contains: 'whoami'
//!     condition: selection
//! level: medium
//! "#;
//!
//! let collection = parse_sigma_yaml(yaml).unwrap();
//! let mut engine = Engine::new();
//! engine.add_collection(&collection).unwrap();
//!
//! let event_val = json!({"CommandLine": "cmd /c whoami"});
//! let event = JsonEvent::borrow(&event_val);
//! let matches = engine.evaluate(&event);
//! assert_eq!(matches.len(), 1);
//! ```
//!
//! ## Quick Start — With Correlations
//!
//! ```rust
//! use rsigma_parser::parse_sigma_yaml;
//! use rsigma_eval::{CorrelationEngine, CorrelationConfig};
//! use rsigma_eval::event::JsonEvent;
//! use serde_json::json;
//!
//! let yaml = r#"
//! title: Login
//! id: login-rule
//! logsource:
//!     category: auth
//! detection:
//!     selection:
//!         EventType: login
//!     condition: selection
//! ---
//! title: Many Logins
//! correlation:
//!     type: event_count
//!     rules:
//!         - login-rule
//!     group-by:
//!         - User
//!     timespan: 60s
//!     condition:
//!         gte: 3
//! level: high
//! "#;
//!
//! let collection = parse_sigma_yaml(yaml).unwrap();
//! let mut engine = CorrelationEngine::new(CorrelationConfig::default());
//! engine.add_collection(&collection).unwrap();
//!
//! for i in 0..3 {
//!     let v = json!({"EventType": "login", "User": "admin"});
//!     let event = JsonEvent::borrow(&v);
//!     let result = engine.process_event_at(&event, 1000 + i);
//!     if i == 2 {
//!         let correlations = result.iter().filter(|r| r.is_correlation()).count();
//!         assert_eq!(correlations, 1);
//!     }
//! }
//! ```

pub mod compiler;
pub mod correlation;
pub mod correlation_engine;
pub mod engine;
pub mod error;
pub mod event;
pub mod explain;
pub mod field_observer;
pub mod fields;
pub mod logsource;
pub mod matcher;
pub mod pipeline;
pub mod result;
pub mod router;
pub mod rule_index;
pub mod schema;

// Re-export the most commonly used types and functions at crate root
pub use compiler::{
    CompiledDetection, CompiledDetectionItem, CompiledRule, compile_rule, evaluate_rule,
};
pub use correlation::{
    CompiledCondition, CompiledCorrelation, EventBuffer, EventRef, EventRefBuffer, GroupByField,
    GroupKey, WindowState,
};
pub use correlation_engine::{
    CorrelationAction, CorrelationConfig, CorrelationEngine, CorrelationEventMode, CorrelationInfo,
    CorrelationSnapshot, CorrelationStateSnapshot, GroupKeyPart, GroupStateInfo, ProcessResult,
    TimestampFallback,
};
pub use engine::Engine;
pub use error::{EvalError, Result};
pub use event::{Event, EventValue, JsonEvent, KvEvent, MapEvent, MappedEvent, PlainEvent};
pub use explain::{
    ConditionTrace, DetectionTrace, ItemTrace, MatchReason, RuleExplanation, SelectionBranch,
    explain_rule,
};
pub use field_observer::{FieldCoverage, FieldObservation, FieldObservationEntry, FieldObserver};
pub use fields::{FieldOrigin, FieldSource, RuleFieldSet};
pub use logsource::LogSourceExtractor;
pub use matcher::{CompiledMatcher, MatchDescriptor};
pub use pipeline::{
    Pipeline, TransformationItem, apply_pipelines, apply_pipelines_with_state,
    builtin::{
        builtin_names as builtin_pipeline_names, resolve_builtin as resolve_builtin_pipeline,
    },
    merge_pipelines, parse_pipeline, parse_pipeline_file, parse_sources_dir, parse_sources_file,
    parse_transformation_items, validate_source_refs,
};
pub use result::{
    CorrelationBody, DetectionBody, EvaluationResult, FieldMatch, MatchDetailLevel, MatcherKind,
    ProcessResultExt, ResultBody, RuleHeader,
};
pub use router::{RouteOutcome, RouteResult, SchemaPruning, SchemaRouter};
pub use schema::{
    FieldValueConfig, OnUnknown, PredicateOutcome, RouteDecision, RoutingConfig, RoutingPlan,
    SchemaBinding, SchemaClassifier, SchemaCountEntry, SchemaError, SchemaExplanation, SchemaMatch,
    SchemaObservation, SchemaObserver, SchemaPredicate, SchemaPredicateConfig, SchemaSignature,
    SchemaSignatureConfig, SchemaSignaturesFile, SignatureExplanation, builtin_schema_names,
    load_schema_config, load_schema_signatures, parse_schema_config, parse_schema_signatures,
    validate_schema_config,
};
