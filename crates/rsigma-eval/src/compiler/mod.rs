//! Compile parsed Sigma rules into optimized in-memory representations.
//!
//! The compiler transforms the parser AST (`SigmaRule`, `Detection`,
//! `DetectionItem`) into compiled forms (`CompiledRule`, `CompiledDetection`,
//! `CompiledDetectionItem`) that can be evaluated efficiently against events.
//!
//! Modifier interpretation happens here: the compiler reads the `Vec<Modifier>`
//! from each `FieldSpec` and produces the appropriate `CompiledMatcher` variant.

mod helpers;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use regex::Regex;

use rsigma_parser::value::{SpecialChar, StringPart};
use rsigma_parser::{
    ConditionExpr, Detection, DetectionItem, Level, LogSource, Modifier, Quantifier,
    SelectorPattern, SigmaRule, SigmaString, SigmaValue,
};

use crate::error::{EvalError, Result};
use crate::event::Event;
use crate::matcher::{CompiledMatcher, sigma_string_to_regex};
use crate::result::{FieldMatch, MatchResult};

pub(crate) use helpers::yaml_to_json_map;
use helpers::{
    base64_offset_patterns, build_regex, expand_windash, pattern_matches, sigma_string_to_bytes,
    to_utf16_bom_bytes, to_utf16be_bytes, to_utf16le_bytes, value_to_f64, value_to_plain_string,
};

// =============================================================================
// Compiled types
// =============================================================================

/// A compiled Sigma rule, ready for evaluation.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub title: String,
    pub id: Option<String>,
    pub level: Option<Level>,
    pub tags: Vec<String>,
    pub logsource: LogSource,
    /// Compiled named detections, keyed by detection name.
    pub detections: HashMap<String, CompiledDetection>,
    /// Condition expression trees (usually one, but can be multiple).
    pub conditions: Vec<ConditionExpr>,
    /// Whether to include the full event JSON in the match result.
    /// Controlled by the `rsigma.include_event` custom attribute.
    pub include_event: bool,
    /// Custom attributes from the original Sigma rule (merged view of
    /// arbitrary top-level keys, the explicit `custom_attributes:` block,
    /// and pipeline `SetCustomAttribute` additions). Propagated to match
    /// results. Wrapped in `Arc` so per-match cloning is a pointer bump.
    pub custom_attributes: Arc<HashMap<String, serde_json::Value>>,
}

/// A compiled detection definition.
#[derive(Debug, Clone)]
pub enum CompiledDetection {
    /// AND-linked detection items (from a YAML mapping).
    AllOf(Vec<CompiledDetectionItem>),
    /// OR-linked sub-detections (from a YAML list of mappings).
    AnyOf(Vec<CompiledDetection>),
    /// Keyword detection: match values across all event fields.
    Keywords(CompiledMatcher),
}

/// A compiled detection item: a field + matcher.
#[derive(Debug, Clone)]
pub struct CompiledDetectionItem {
    /// The field name to check (`None` for keyword items).
    pub field: Option<String>,
    /// The compiled matcher combining all values with appropriate logic.
    pub matcher: CompiledMatcher,
    /// If `Some(true)`, field must exist; `Some(false)`, must not exist.
    pub exists: Option<bool>,
}

// =============================================================================
// Modifier context
// =============================================================================

/// Parsed modifier flags for a single field specification.
#[derive(Clone, Copy)]
struct ModCtx {
    contains: bool,
    startswith: bool,
    endswith: bool,
    all: bool,
    base64: bool,
    base64offset: bool,
    wide: bool,
    utf16be: bool,
    utf16: bool,
    windash: bool,
    re: bool,
    cidr: bool,
    cased: bool,
    exists: bool,
    fieldref: bool,
    gt: bool,
    gte: bool,
    lt: bool,
    lte: bool,
    neq: bool,
    ignore_case: bool,
    multiline: bool,
    dotall: bool,
    expand: bool,
    timestamp_part: Option<crate::matcher::TimePart>,
}

impl ModCtx {
    fn from_modifiers(modifiers: &[Modifier]) -> Self {
        let mut ctx = ModCtx {
            contains: false,
            startswith: false,
            endswith: false,
            all: false,
            base64: false,
            base64offset: false,
            wide: false,
            utf16be: false,
            utf16: false,
            windash: false,
            re: false,
            cidr: false,
            cased: false,
            exists: false,
            fieldref: false,
            gt: false,
            gte: false,
            lt: false,
            lte: false,
            neq: false,
            ignore_case: false,
            multiline: false,
            dotall: false,
            expand: false,
            timestamp_part: None,
        };
        for m in modifiers {
            match m {
                Modifier::Contains => ctx.contains = true,
                Modifier::StartsWith => ctx.startswith = true,
                Modifier::EndsWith => ctx.endswith = true,
                Modifier::All => ctx.all = true,
                Modifier::Base64 => ctx.base64 = true,
                Modifier::Base64Offset => ctx.base64offset = true,
                Modifier::Wide => ctx.wide = true,
                Modifier::Utf16be => ctx.utf16be = true,
                Modifier::Utf16 => ctx.utf16 = true,
                Modifier::WindAsh => ctx.windash = true,
                Modifier::Re => ctx.re = true,
                Modifier::Cidr => ctx.cidr = true,
                Modifier::Cased => ctx.cased = true,
                Modifier::Exists => ctx.exists = true,
                Modifier::FieldRef => ctx.fieldref = true,
                Modifier::Gt => ctx.gt = true,
                Modifier::Gte => ctx.gte = true,
                Modifier::Lt => ctx.lt = true,
                Modifier::Lte => ctx.lte = true,
                Modifier::Neq => ctx.neq = true,
                Modifier::IgnoreCase => ctx.ignore_case = true,
                Modifier::Multiline => ctx.multiline = true,
                Modifier::DotAll => ctx.dotall = true,
                Modifier::Expand => ctx.expand = true,
                Modifier::Hour => ctx.timestamp_part = Some(crate::matcher::TimePart::Hour),
                Modifier::Day => ctx.timestamp_part = Some(crate::matcher::TimePart::Day),
                Modifier::Week => ctx.timestamp_part = Some(crate::matcher::TimePart::Week),
                Modifier::Month => ctx.timestamp_part = Some(crate::matcher::TimePart::Month),
                Modifier::Year => ctx.timestamp_part = Some(crate::matcher::TimePart::Year),
                Modifier::Minute => ctx.timestamp_part = Some(crate::matcher::TimePart::Minute),
            }
        }
        ctx
    }

    /// Whether matching should be case-insensitive.
    /// Default is case-insensitive; `|cased` makes it case-sensitive.
    fn is_case_insensitive(&self) -> bool {
        !self.cased
    }

    /// Whether any numeric comparison modifier is present.
    fn has_numeric_comparison(&self) -> bool {
        self.gt || self.gte || self.lt || self.lte
    }

    /// Whether the neq modifier is present.
    fn has_neq(&self) -> bool {
        self.neq
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Compile a parsed `SigmaRule` into a `CompiledRule`.
pub fn compile_rule(rule: &SigmaRule) -> Result<CompiledRule> {
    let mut detections = HashMap::new();
    for (name, detection) in &rule.detection.named {
        detections.insert(name.clone(), compile_detection(detection)?);
    }

    for condition in &rule.detection.conditions {
        validate_condition_refs(condition, &detections)?;
    }

    let include_event = rule
        .custom_attributes
        .get("rsigma.include_event")
        .and_then(|v| v.as_str())
        == Some("true");

    let custom_attributes = Arc::new(yaml_to_json_map(&rule.custom_attributes));

    Ok(CompiledRule {
        title: rule.title.clone(),
        id: rule.id.clone(),
        level: rule.level,
        tags: rule.tags.clone(),
        logsource: rule.logsource.clone(),
        detections,
        conditions: rule.detection.conditions.clone(),
        include_event,
        custom_attributes,
    })
}

/// Validate that all `Identifier` references in a condition expression resolve
/// to an existing detection name. `Selector` patterns are exempt because they
/// match by glob/wildcard and zero matches is semantically valid.
fn validate_condition_refs(
    expr: &ConditionExpr,
    detections: &HashMap<String, CompiledDetection>,
) -> Result<()> {
    match expr {
        ConditionExpr::Identifier(name) => {
            if !detections.contains_key(name) {
                return Err(EvalError::UnknownDetection(name.clone()));
            }
            Ok(())
        }
        ConditionExpr::And(exprs) | ConditionExpr::Or(exprs) => {
            for e in exprs {
                validate_condition_refs(e, detections)?;
            }
            Ok(())
        }
        ConditionExpr::Not(inner) => validate_condition_refs(inner, detections),
        ConditionExpr::Selector { .. } => Ok(()),
    }
}

/// Evaluate a compiled rule against an event, returning a `MatchResult` if it matches.
pub fn evaluate_rule(rule: &CompiledRule, event: &impl Event) -> Option<MatchResult> {
    for condition in &rule.conditions {
        let mut matched_selections = Vec::new();
        if eval_condition(condition, &rule.detections, event, &mut matched_selections) {
            let matched_fields =
                collect_field_matches(&matched_selections, &rule.detections, event);

            let event_data = if rule.include_event {
                Some(event.to_json())
            } else {
                None
            };

            return Some(MatchResult {
                rule_title: rule.title.clone(),
                rule_id: rule.id.clone(),
                level: rule.level,
                tags: rule.tags.clone(),
                matched_selections,
                matched_fields,
                event: event_data,
                custom_attributes: rule.custom_attributes.clone(),
            });
        }
    }
    None
}

// =============================================================================
// Detection compilation
// =============================================================================

/// Compile a parsed detection tree into a [`CompiledDetection`].
///
/// Recursively compiles `AllOf`, `AnyOf`, and `Keywords` variants.
/// Returns an error if the detection tree is empty or contains invalid items.
pub fn compile_detection(detection: &Detection) -> Result<CompiledDetection> {
    match detection {
        Detection::AllOf(items) => {
            if items.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "AllOf detection must not be empty (vacuous truth)".into(),
                ));
            }
            let compiled: Result<Vec<_>> = items.iter().map(compile_detection_item).collect();
            Ok(CompiledDetection::AllOf(compiled?))
        }
        Detection::AnyOf(dets) => {
            if dets.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "AnyOf detection must not be empty (would never match)".into(),
                ));
            }
            let compiled: Result<Vec<_>> = dets.iter().map(compile_detection).collect();
            Ok(CompiledDetection::AnyOf(compiled?))
        }
        Detection::Keywords(values) => {
            let ci = true; // keywords are case-insensitive by default
            let matchers: Vec<CompiledMatcher> = values
                .iter()
                .map(|v| compile_value_default(v, ci))
                .collect::<Result<Vec<_>>>()?;
            let matcher = if matchers.len() == 1 {
                // SAFETY: length checked above
                matchers
                    .into_iter()
                    .next()
                    .unwrap_or(CompiledMatcher::AnyOf(vec![]))
            } else {
                CompiledMatcher::AnyOf(matchers)
            };
            Ok(CompiledDetection::Keywords(matcher))
        }
    }
}

fn compile_detection_item(item: &DetectionItem) -> Result<CompiledDetectionItem> {
    let ctx = ModCtx::from_modifiers(&item.field.modifiers);

    // Handle |exists modifier
    if ctx.exists {
        let expect = match item.values.first() {
            Some(SigmaValue::Bool(b)) => *b,
            Some(SigmaValue::String(s)) => match s.as_plain().as_deref() {
                Some("true") | Some("yes") => true,
                Some("false") | Some("no") => false,
                _ => true,
            },
            _ => true,
        };
        return Ok(CompiledDetectionItem {
            field: item.field.name.clone(),
            matcher: CompiledMatcher::Exists(expect),
            exists: Some(expect),
        });
    }

    // Sigma spec: "Single item values are not allowed to have the all modifier."
    if ctx.all && item.values.len() <= 1 {
        return Err(EvalError::InvalidModifiers(
            "|all modifier requires more than one value".to_string(),
        ));
    }

    // Compile each value into a matcher
    let matchers: Result<Vec<CompiledMatcher>> =
        item.values.iter().map(|v| compile_value(v, &ctx)).collect();
    let matchers = matchers?;

    // Combine multiple values: |all → AND, default → OR
    let combined = if matchers.len() == 1 {
        // SAFETY: length checked above
        matchers
            .into_iter()
            .next()
            .unwrap_or(CompiledMatcher::AnyOf(vec![]))
    } else if ctx.all {
        CompiledMatcher::AllOf(matchers)
    } else {
        CompiledMatcher::AnyOf(matchers)
    };

    Ok(CompiledDetectionItem {
        field: item.field.name.clone(),
        matcher: combined,
        exists: None,
    })
}

// =============================================================================
// Value compilation (modifier interpretation)
// =============================================================================

/// Compile a single `SigmaValue` using the modifier context.
fn compile_value(value: &SigmaValue, ctx: &ModCtx) -> Result<CompiledMatcher> {
    let ci = ctx.is_case_insensitive();

    // Handle special modifiers first

    // |expand — runtime placeholder expansion
    if ctx.expand {
        let plain = value_to_plain_string(value)?;
        let template = crate::matcher::parse_expand_template(&plain);
        return Ok(CompiledMatcher::Expand {
            template,
            case_insensitive: ci,
        });
    }

    // Timestamp part modifiers (|hour, |day, |month, etc.)
    if let Some(part) = ctx.timestamp_part {
        // The value is compared against the extracted time component.
        // Compile the value as a numeric matcher, then wrap in TimestampPart.
        let inner = match value {
            SigmaValue::Integer(n) => CompiledMatcher::NumericEq(*n as f64),
            SigmaValue::Float(n) => CompiledMatcher::NumericEq(*n),
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                let n: f64 = plain.parse().map_err(|_| {
                    EvalError::IncompatibleValue(format!(
                        "timestamp part modifier requires numeric value, got: {plain}"
                    ))
                })?;
                CompiledMatcher::NumericEq(n)
            }
            _ => {
                return Err(EvalError::IncompatibleValue(
                    "timestamp part modifier requires numeric value".into(),
                ));
            }
        };
        return Ok(CompiledMatcher::TimestampPart {
            part,
            inner: Box::new(inner),
        });
    }

    // |fieldref — value is a field name to compare against
    if ctx.fieldref {
        let field_name = value_to_plain_string(value)?;
        return Ok(CompiledMatcher::FieldRef {
            field: field_name,
            case_insensitive: ci,
        });
    }

    // |re — value is a regex pattern
    // Sigma spec: "Regex is matched case-sensitive by default."
    // Only the explicit |i sub-modifier enables case-insensitive matching.
    if ctx.re {
        let pattern = value_to_plain_string(value)?;
        let regex = build_regex(&pattern, ctx.ignore_case, ctx.multiline, ctx.dotall)?;
        return Ok(CompiledMatcher::Regex(regex));
    }

    // |cidr — value is a CIDR notation
    if ctx.cidr {
        let cidr_str = value_to_plain_string(value)?;
        let net: ipnet::IpNet = cidr_str
            .parse()
            .map_err(|e: ipnet::AddrParseError| EvalError::InvalidCidr(e))?;
        return Ok(CompiledMatcher::Cidr(net));
    }

    // |gt, |gte, |lt, |lte — numeric comparison
    if ctx.has_numeric_comparison() {
        let n = value_to_f64(value)?;
        if ctx.gt {
            return Ok(CompiledMatcher::NumericGt(n));
        }
        if ctx.gte {
            return Ok(CompiledMatcher::NumericGte(n));
        }
        if ctx.lt {
            return Ok(CompiledMatcher::NumericLt(n));
        }
        if ctx.lte {
            return Ok(CompiledMatcher::NumericLte(n));
        }
    }

    // |neq — not-equal: negate the normal equality match
    if ctx.has_neq() {
        // Compile the value as a normal matcher, then wrap in Not
        let mut inner_ctx = ModCtx { ..*ctx };
        inner_ctx.neq = false;
        let inner = compile_value(value, &inner_ctx)?;
        return Ok(CompiledMatcher::Not(Box::new(inner)));
    }

    // For non-string values without string modifiers, use simple matchers
    match value {
        SigmaValue::Integer(n) => {
            if ctx.contains || ctx.startswith || ctx.endswith {
                // Treat as string for string modifiers
                return compile_string_value(&n.to_string(), ctx);
            }
            return Ok(CompiledMatcher::NumericEq(*n as f64));
        }
        SigmaValue::Float(n) => {
            if ctx.contains || ctx.startswith || ctx.endswith {
                return compile_string_value(&n.to_string(), ctx);
            }
            return Ok(CompiledMatcher::NumericEq(*n));
        }
        SigmaValue::Bool(b) => return Ok(CompiledMatcher::BoolEq(*b)),
        SigmaValue::Null => return Ok(CompiledMatcher::Null),
        SigmaValue::String(_) => {} // handled below
    }

    // String value — apply encoding/transformation modifiers, then string matching
    let sigma_str = match value {
        SigmaValue::String(s) => s,
        _ => unreachable!(),
    };

    // Apply transformation chain: wide → base64/base64offset → windash → string match
    let mut bytes = sigma_string_to_bytes(sigma_str);

    // |wide / |utf16le — UTF-16LE encoding
    if ctx.wide {
        bytes = to_utf16le_bytes(&bytes);
    }

    // |utf16be — UTF-16 big-endian encoding
    if ctx.utf16be {
        bytes = to_utf16be_bytes(&bytes);
    }

    // |utf16 — UTF-16 with BOM (little-endian)
    if ctx.utf16 {
        bytes = to_utf16_bom_bytes(&bytes);
    }

    // |base64 — base64 encode, then exact/contains match
    if ctx.base64 {
        let encoded = BASE64_STANDARD.encode(&bytes);
        return compile_string_value(&encoded, ctx);
    }

    // |base64offset — generate 3 offset variants
    if ctx.base64offset {
        let patterns = base64_offset_patterns(&bytes);
        let matchers: Vec<CompiledMatcher> = patterns
            .into_iter()
            .map(|p| {
                // base64offset implies contains matching
                CompiledMatcher::Contains {
                    value: if ci { p.to_lowercase() } else { p },
                    case_insensitive: ci,
                }
            })
            .collect();
        return Ok(CompiledMatcher::AnyOf(matchers));
    }

    // |windash — expand `-` to `/` variants
    if ctx.windash {
        let plain = sigma_str
            .as_plain()
            .unwrap_or_else(|| sigma_str.original.clone());
        let variants = expand_windash(&plain)?;
        let matchers: Result<Vec<CompiledMatcher>> = variants
            .into_iter()
            .map(|v| compile_string_value(&v, ctx))
            .collect();
        return Ok(CompiledMatcher::AnyOf(matchers?));
    }

    // Standard string matching (exact / contains / startswith / endswith / wildcard)
    compile_sigma_string(sigma_str, ctx)
}

/// Compile a `SigmaString` (with possible wildcards) using modifiers.
fn compile_sigma_string(sigma_str: &SigmaString, ctx: &ModCtx) -> Result<CompiledMatcher> {
    let ci = ctx.is_case_insensitive();

    // If the string is plain (no wildcards), use optimized matchers
    if sigma_str.is_plain() {
        let plain = sigma_str.as_plain().unwrap_or_default();
        return compile_string_value(&plain, ctx);
    }

    // String has wildcards — need to determine matching semantics
    // Modifiers like |contains, |startswith, |endswith adjust the pattern

    // Build a regex from the sigma string, incorporating modifier semantics
    let mut pattern = String::new();
    if ci {
        pattern.push_str("(?i)");
    }

    if !ctx.contains && !ctx.startswith {
        pattern.push('^');
    }

    for part in &sigma_str.parts {
        match part {
            StringPart::Plain(text) => {
                pattern.push_str(&regex::escape(text));
            }
            StringPart::Special(SpecialChar::WildcardMulti) => {
                pattern.push_str(".*");
            }
            StringPart::Special(SpecialChar::WildcardSingle) => {
                pattern.push('.');
            }
        }
    }

    if !ctx.contains && !ctx.endswith {
        pattern.push('$');
    }

    let regex = Regex::new(&pattern).map_err(EvalError::InvalidRegex)?;
    Ok(CompiledMatcher::Regex(regex))
}

/// Compile a plain string value (no wildcards) using modifier context.
fn compile_string_value(plain: &str, ctx: &ModCtx) -> Result<CompiledMatcher> {
    let ci = ctx.is_case_insensitive();

    if ctx.contains {
        Ok(CompiledMatcher::Contains {
            value: if ci {
                plain.to_lowercase()
            } else {
                plain.to_string()
            },
            case_insensitive: ci,
        })
    } else if ctx.startswith {
        Ok(CompiledMatcher::StartsWith {
            value: if ci {
                plain.to_lowercase()
            } else {
                plain.to_string()
            },
            case_insensitive: ci,
        })
    } else if ctx.endswith {
        Ok(CompiledMatcher::EndsWith {
            value: if ci {
                plain.to_lowercase()
            } else {
                plain.to_string()
            },
            case_insensitive: ci,
        })
    } else {
        Ok(CompiledMatcher::Exact {
            value: if ci {
                plain.to_lowercase()
            } else {
                plain.to_string()
            },
            case_insensitive: ci,
        })
    }
}

/// Compile a value with default settings (no modifiers except case sensitivity).
fn compile_value_default(value: &SigmaValue, case_insensitive: bool) -> Result<CompiledMatcher> {
    match value {
        SigmaValue::String(s) => {
            if s.is_plain() {
                let plain = s.as_plain().unwrap_or_default();
                Ok(CompiledMatcher::Contains {
                    value: if case_insensitive {
                        plain.to_lowercase()
                    } else {
                        plain
                    },
                    case_insensitive,
                })
            } else {
                // Wildcards → regex (keywords use contains semantics)
                let pattern = sigma_string_to_regex(&s.parts, case_insensitive);
                let regex = Regex::new(&pattern).map_err(EvalError::InvalidRegex)?;
                Ok(CompiledMatcher::Regex(regex))
            }
        }
        SigmaValue::Integer(n) => Ok(CompiledMatcher::NumericEq(*n as f64)),
        SigmaValue::Float(n) => Ok(CompiledMatcher::NumericEq(*n)),
        SigmaValue::Bool(b) => Ok(CompiledMatcher::BoolEq(*b)),
        SigmaValue::Null => Ok(CompiledMatcher::Null),
    }
}

// =============================================================================
// Condition evaluation
// =============================================================================

/// Evaluate a condition expression against the event using compiled detections.
///
/// Returns `true` if the condition is satisfied. Populates `matched_selections`
/// with the names of detections that were evaluated and returned true.
pub fn eval_condition(
    expr: &ConditionExpr,
    detections: &HashMap<String, CompiledDetection>,
    event: &impl Event,
    matched_selections: &mut Vec<String>,
) -> bool {
    match expr {
        ConditionExpr::Identifier(name) => {
            if let Some(det) = detections.get(name) {
                let result = eval_detection(det, event);
                if result {
                    matched_selections.push(name.clone());
                }
                result
            } else {
                false
            }
        }

        ConditionExpr::And(exprs) => exprs
            .iter()
            .all(|e| eval_condition(e, detections, event, matched_selections)),

        ConditionExpr::Or(exprs) => exprs
            .iter()
            .any(|e| eval_condition(e, detections, event, matched_selections)),

        ConditionExpr::Not(inner) => !eval_condition(inner, detections, event, matched_selections),

        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let matching_names: Vec<&String> = match pattern {
                SelectorPattern::Them => detections
                    .keys()
                    .filter(|name| !name.starts_with('_'))
                    .collect(),
                SelectorPattern::Pattern(pat) => detections
                    .keys()
                    .filter(|name| pattern_matches(pat, name))
                    .collect(),
            };

            let mut match_count = 0u64;
            for name in &matching_names {
                if let Some(det) = detections.get(*name)
                    && eval_detection(det, event)
                {
                    match_count += 1;
                    matched_selections.push((*name).clone());
                }
            }

            match quantifier {
                Quantifier::Any => match_count >= 1,
                Quantifier::All => match_count == matching_names.len() as u64,
                Quantifier::Count(n) => match_count >= *n,
            }
        }
    }
}

/// Evaluate a compiled detection against an event.
fn eval_detection(detection: &CompiledDetection, event: &impl Event) -> bool {
    match detection {
        CompiledDetection::AllOf(items) => {
            items.iter().all(|item| eval_detection_item(item, event))
        }
        CompiledDetection::AnyOf(dets) => dets.iter().any(|d| eval_detection(d, event)),
        CompiledDetection::Keywords(matcher) => matcher.matches_keyword(event),
    }
}

/// Evaluate a single compiled detection item against an event.
fn eval_detection_item(item: &CompiledDetectionItem, event: &impl Event) -> bool {
    if let Some(expect_exists) = item.exists {
        if let Some(field) = &item.field {
            let exists = event.get_field(field).is_some_and(|v| !v.is_null());
            return exists == expect_exists;
        }
        return !expect_exists;
    }

    match &item.field {
        Some(field_name) => {
            if let Some(value) = event.get_field(field_name) {
                item.matcher.matches(&value, event)
            } else {
                matches!(item.matcher, CompiledMatcher::Null)
            }
        }
        None => item.matcher.matches_keyword(event),
    }
}

/// Collect field matches from matched selections for the MatchResult.
fn collect_field_matches(
    selection_names: &[String],
    detections: &HashMap<String, CompiledDetection>,
    event: &impl Event,
) -> Vec<FieldMatch> {
    let mut matches = Vec::new();
    for name in selection_names {
        if let Some(det) = detections.get(name) {
            collect_detection_fields(det, event, &mut matches);
        }
    }
    matches
}

fn collect_detection_fields(
    detection: &CompiledDetection,
    event: &impl Event,
    out: &mut Vec<FieldMatch>,
) {
    match detection {
        CompiledDetection::AllOf(items) => {
            for item in items {
                if let Some(field_name) = &item.field
                    && let Some(value) = event.get_field(field_name)
                    && item.matcher.matches(&value, event)
                {
                    out.push(FieldMatch {
                        field: field_name.clone(),
                        value: value.to_json(),
                    });
                }
            }
        }
        CompiledDetection::AnyOf(dets) => {
            for d in dets {
                if eval_detection(d, event) {
                    collect_detection_fields(d, event, out);
                }
            }
        }
        CompiledDetection::Keywords(_) => {}
    }
}
