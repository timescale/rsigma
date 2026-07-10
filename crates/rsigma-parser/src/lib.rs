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
//! - **yaml_serde** for YAML structure deserialization
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

pub mod ads;
pub mod ast;
pub mod condition;
pub mod error;
pub mod fieldpath;
pub mod lint;
pub mod parser;
pub mod reference;
pub mod selector;
pub mod value;
pub mod version;

// Re-export the most commonly used types and functions at crate root
pub use ads::{
    AdsCarrier, AdsContent, AdsDocument, AdsScaffoldEntry, AdsSection, AdsSectionInfo,
    AdsSectionStatus, ads_catalogue,
};
pub use ast::{
    ArrayQuantifier, ConditionExpr, ConditionOperator, CorrelationCondition, CorrelationRule,
    CorrelationType, Detection, DetectionItem, Detections, FieldAlias, FieldSpec, FilterRule,
    FilterRuleTarget, Level, LogSource, Modifier, Quantifier, Related, RelationType,
    SelectorPattern, SigmaCollection, SigmaDocument, SigmaRule, Status, WindowMode,
};
pub use condition::parse_condition;
pub use error::{Result, SigmaParserError, SourceLocation};
pub use lint::catalogue::{LintRuleInfo, catalogue};
#[cfg(feature = "fix")]
pub use lint::fix::{SourceFixOutcome, apply_fixes_to_source};
pub use lint::{
    AdsConfig, FileLintResult, Fix, FixDisposition, FixPatch, InlineSuppressions, LintConfig,
    LintRule, LintWarning, Severity, Span, apply_suppressions, lint_yaml_directory,
    lint_yaml_directory_with_config, lint_yaml_file, lint_yaml_file_with_config, lint_yaml_str,
    lint_yaml_str_with_config, lint_yaml_value, parse_inline_suppressions,
};
pub use parser::{parse_field_spec, parse_sigma_directory, parse_sigma_file, parse_sigma_yaml};
pub use selector::detection_name_matches;
pub use value::{SigmaString, SigmaValue, SpecialChar, StringPart, Timespan};
pub use version::{
    SPEC_VERSION_ARRAY_MATCHING, SPEC_VERSION_FLOOR, SPEC_VERSION_SUPPORTED,
    array_matching_enabled, is_unsupported, resolve_major,
};
