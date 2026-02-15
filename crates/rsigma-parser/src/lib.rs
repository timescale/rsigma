//! # rsigma-parser
//!
//! A comprehensive parser for Sigma detection rules, correlations, and filters.
//!
//! This crate parses Sigma YAML files into a strongly-typed AST, handling:
//!
//! - **Detection rules**: field matching, wildcards, boolean conditions, field modifiers
//! - **Condition expressions**: `and`, `or`, `not`, `1 of`, `all of`, parenthesized groups
//! - **Correlation rules**: `event_count`, `value_count`, `temporal`, aggregations
//! - **Filter rules**: additional conditions applied to referenced rules
//! - **Rule collections**: multi-document YAML, `action: global/reset/repeat`
//! - **Value types**: strings with wildcards, numbers, booleans, null, regex, CIDR
//! - **All 30+ field modifiers**: `contains`, `endswith`, `startswith`, `re`, `cidr`,
//!   `base64`, `base64offset`, `wide`, `windash`, `all`, `cased`, `exists`, `fieldref`,
//!   comparison operators, regex flags, timestamp parts, and more
//!
//! ## Architecture
//!
//! - **PEG grammar** ([`pest`]) for condition expression parsing with correct operator
//!   precedence (`NOT` > `AND` > `OR`) and Pratt parsing
//! - **serde_yaml** for YAML structure deserialization
//! - **Custom parsing** for field modifiers, wildcard strings, and timespan values
//!
//! ## Quick Start
//!
//! ```rust
//! use rsigma_parser::parse_sigma_yaml;
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
//! assert_eq!(collection.rules.len(), 1);
//! assert_eq!(collection.rules[0].title, "Detect Whoami");
//! ```
//!
//! ## Parsing condition expressions
//!
//! ```rust
//! use rsigma_parser::parse_condition;
//!
//! let expr = parse_condition("selection_main and 1 of selection_dword_* and not 1 of filter_*").unwrap();
//! println!("{expr}");
//! ```

pub mod ast;
pub mod condition;
pub mod error;
pub mod lint;
pub mod parser;
pub mod value;

// Re-export the most commonly used types and functions at crate root
pub use ast::{
    ConditionExpr, ConditionOperator, CorrelationCondition, CorrelationRule, CorrelationType,
    Detection, DetectionItem, Detections, FieldAlias, FieldSpec, FilterRule, Level, LogSource,
    Modifier, Quantifier, Related, RelationType, SelectorPattern, SigmaCollection, SigmaDocument,
    SigmaRule, Status,
};
pub use condition::parse_condition;
pub use error::{Result, SigmaParserError};
pub use lint::{
    FileLintResult, LintRule, LintWarning, Severity, Span, lint_yaml_directory, lint_yaml_file,
    lint_yaml_str, lint_yaml_value,
};
pub use parser::{parse_field_spec, parse_sigma_directory, parse_sigma_file, parse_sigma_yaml};
pub use value::{SigmaString, SigmaValue, SpecialChar, StringPart, Timespan};
