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
//! use rsigma_eval::{Engine, Event};
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
//! let event = Event::from_value(&event_val);
//! let matches = engine.evaluate(&event);
//! assert_eq!(matches.len(), 1);
//! ```
//!
//! ## Quick Start — With Correlations
//!
//! ```rust
//! use rsigma_parser::parse_sigma_yaml;
//! use rsigma_eval::{CorrelationEngine, CorrelationConfig, Event};
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
//!     let event = Event::from_value(&v);
//!     let result = engine.process_event_at(&event, 1000 + i);
//!     if i == 2 {
//!         assert_eq!(result.correlations.len(), 1);
//!     }
//! }
//! ```

pub mod compiler;
pub mod correlation;
pub mod correlation_engine;
pub mod engine;
pub mod error;
pub mod event;
pub mod matcher;
pub mod pipeline;
pub mod result;

// Re-export the most commonly used types and functions at crate root
pub use compiler::{
    CompiledDetection, CompiledDetectionItem, CompiledRule, compile_rule, evaluate_rule,
};
pub use correlation::{
    CompiledCondition, CompiledCorrelation, GroupByField, GroupKey, WindowState,
};
pub use correlation_engine::{
    CorrelationAction, CorrelationConfig, CorrelationEngine, CorrelationResult, ProcessResult,
};
pub use engine::Engine;
pub use error::{EvalError, Result};
pub use event::Event;
pub use matcher::CompiledMatcher;
pub use pipeline::{
    Pipeline, apply_pipelines, merge_pipelines, parse_pipeline, parse_pipeline_file,
};
pub use result::{FieldMatch, MatchResult};
