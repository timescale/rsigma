//! # rsigma-eval
//!
//! Evaluator for Sigma detection rules — matches compiled rules against JSON events.
//!
//! This crate consumes the AST produced by [`rsigma_parser`] and evaluates it
//! against events in real time using a compile-then-evaluate model.
//!
//! ## Architecture
//!
//! 1. **Compile**: Sigma rules are compiled once into optimized in-memory matchers
//! 2. **Evaluate**: Each event is matched against compiled rules with zero allocation
//!    on the hot path
//!
//! ## Quick Start
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

pub mod compiler;
pub mod engine;
pub mod error;
pub mod event;
pub mod matcher;
pub mod result;

// Re-export the most commonly used types and functions at crate root
pub use compiler::{
    CompiledDetection, CompiledDetectionItem, CompiledRule, compile_rule, evaluate_rule,
};
pub use engine::Engine;
pub use error::{EvalError, Result};
pub use event::Event;
pub use matcher::CompiledMatcher;
pub use result::{FieldMatch, MatchResult};
