//! Compile parsed Sigma rules into optimized in-memory representations.
//!
//! The compiler transforms the parser AST (`SigmaRule`, `Detection`,
//! `DetectionItem`) into compiled forms (`CompiledRule`, `CompiledDetection`,
//! `CompiledDetectionItem`) that can be evaluated efficiently against events.
//!
//! Modifier interpretation happens here: the compiler reads the `Vec<Modifier>`
//! from each `FieldSpec` and produces the appropriate `CompiledMatcher` variant.

use std::collections::HashMap;

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
        .is_some_and(|v| v == "true");

    Ok(CompiledRule {
        title: rule.title.clone(),
        id: rule.id.clone(),
        level: rule.level,
        tags: rule.tags.clone(),
        logsource: rule.logsource.clone(),
        detections,
        conditions: rule.detection.conditions.clone(),
        include_event,
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
pub fn evaluate_rule(rule: &CompiledRule, event: &Event) -> Option<MatchResult> {
    // Evaluate each condition (usually just one)
    for condition in &rule.conditions {
        let mut matched_selections = Vec::new();
        if eval_condition(condition, &rule.detections, event, &mut matched_selections) {
            // Collect field matches from the matched selections
            let matched_fields =
                collect_field_matches(&matched_selections, &rule.detections, event);

            let event_data = if rule.include_event {
                Some(event.as_value().clone())
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
    event: &Event,
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
fn eval_detection(detection: &CompiledDetection, event: &Event) -> bool {
    match detection {
        CompiledDetection::AllOf(items) => {
            items.iter().all(|item| eval_detection_item(item, event))
        }
        CompiledDetection::AnyOf(dets) => dets.iter().any(|d| eval_detection(d, event)),
        CompiledDetection::Keywords(matcher) => matcher.matches_keyword(event),
    }
}

/// Evaluate a single compiled detection item against an event.
fn eval_detection_item(item: &CompiledDetectionItem, event: &Event) -> bool {
    // Handle exists modifier
    if let Some(expect_exists) = item.exists {
        if let Some(field) = &item.field {
            let exists = event.get_field(field).is_some_and(|v| !v.is_null());
            return exists == expect_exists;
        }
        return !expect_exists; // No field name + exists → field doesn't exist
    }

    match &item.field {
        Some(field_name) => {
            // Field-based detection
            if let Some(value) = event.get_field(field_name) {
                item.matcher.matches(value, event)
            } else {
                // Field not present — check if matcher handles null
                matches!(item.matcher, CompiledMatcher::Null)
            }
        }
        None => {
            // Keyword detection (no field) — search all string values
            item.matcher.matches_keyword(event)
        }
    }
}

/// Collect field matches from matched selections for the MatchResult.
fn collect_field_matches(
    selection_names: &[String],
    detections: &HashMap<String, CompiledDetection>,
    event: &Event,
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
    event: &Event,
    out: &mut Vec<FieldMatch>,
) {
    match detection {
        CompiledDetection::AllOf(items) => {
            for item in items {
                if let Some(field_name) = &item.field
                    && let Some(value) = event.get_field(field_name)
                    && item.matcher.matches(value, event)
                {
                    out.push(FieldMatch {
                        field: field_name.clone(),
                        value: value.clone(),
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
        CompiledDetection::Keywords(_) => {
            // Keyword matches don't have specific field names
        }
    }
}

// =============================================================================
// Pattern matching for selectors
// =============================================================================

/// Check if a detection name matches a selector pattern (supports `*` wildcard).
fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return name.ends_with(suffix);
    }
    pattern == name
}

// =============================================================================
// Value extraction helpers
// =============================================================================

/// Extract a plain string from a SigmaValue.
fn value_to_plain_string(value: &SigmaValue) -> Result<String> {
    match value {
        SigmaValue::String(s) => Ok(s.as_plain().unwrap_or_else(|| s.original.clone())),
        SigmaValue::Integer(n) => Ok(n.to_string()),
        SigmaValue::Float(n) => Ok(n.to_string()),
        SigmaValue::Bool(b) => Ok(b.to_string()),
        SigmaValue::Null => Err(EvalError::IncompatibleValue(
            "null value for string modifier".into(),
        )),
    }
}

/// Extract a numeric f64 from a SigmaValue.
fn value_to_f64(value: &SigmaValue) -> Result<f64> {
    match value {
        SigmaValue::Integer(n) => Ok(*n as f64),
        SigmaValue::Float(n) => Ok(*n),
        SigmaValue::String(s) => {
            let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
            plain
                .parse::<f64>()
                .map_err(|_| EvalError::ExpectedNumeric(plain))
        }
        _ => Err(EvalError::ExpectedNumeric(format!("{value:?}"))),
    }
}

/// Convert a SigmaString into raw bytes (UTF-8).
fn sigma_string_to_bytes(s: &SigmaString) -> Vec<u8> {
    let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
    plain.into_bytes()
}

// =============================================================================
// Encoding helpers
// =============================================================================

/// Convert bytes to UTF-16LE representation (wide string / utf16le).
fn to_utf16le_bytes(bytes: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(bytes);
    let mut wide = Vec::with_capacity(s.len() * 2);
    for c in s.chars() {
        let mut buf = [0u16; 2];
        let encoded = c.encode_utf16(&mut buf);
        for u in encoded {
            wide.extend_from_slice(&u.to_le_bytes());
        }
    }
    wide
}

/// Convert bytes to UTF-16BE representation.
fn to_utf16be_bytes(bytes: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(bytes);
    let mut wide = Vec::with_capacity(s.len() * 2);
    for c in s.chars() {
        let mut buf = [0u16; 2];
        let encoded = c.encode_utf16(&mut buf);
        for u in encoded {
            wide.extend_from_slice(&u.to_be_bytes());
        }
    }
    wide
}

/// Convert bytes to UTF-16 with BOM (little-endian, BOM = FF FE).
fn to_utf16_bom_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![0xFF, 0xFE]; // UTF-16LE BOM
    result.extend_from_slice(&to_utf16le_bytes(bytes));
    result
}

/// Generate base64 offset patterns for a byte sequence.
///
/// Produces up to 3 patterns for byte offsets 0, 1, and 2 within a
/// base64 3-byte alignment group. Each pattern is the stable middle
/// portion of the encoding that doesn't depend on alignment padding.
fn base64_offset_patterns(value: &[u8]) -> Vec<String> {
    let mut patterns = Vec::with_capacity(3);

    for offset in 0..3usize {
        let mut padded = vec![0u8; offset];
        padded.extend_from_slice(value);

        let encoded = BASE64_STANDARD.encode(&padded);

        // Skip leading chars influenced by padding bytes
        let start = (offset * 4).div_ceil(3);
        // Trim trailing '=' padding
        let trimmed = encoded.trim_end_matches('=');
        let end = trimmed.len();

        if start < end {
            patterns.push(trimmed[start..end].to_string());
        }
    }

    patterns
}

/// Build a regex with optional flags.
fn build_regex(
    pattern: &str,
    case_insensitive: bool,
    multiline: bool,
    dotall: bool,
) -> Result<Regex> {
    let mut flags = String::new();
    if case_insensitive {
        flags.push('i');
    }
    if multiline {
        flags.push('m');
    }
    if dotall {
        flags.push('s');
    }

    let full_pattern = if flags.is_empty() {
        pattern.to_string()
    } else {
        format!("(?{flags}){pattern}")
    };

    Regex::new(&full_pattern).map_err(EvalError::InvalidRegex)
}

/// Replacement characters for the `windash` modifier per Sigma spec:
/// `-`, `/`, `–` (en dash U+2013), `—` (em dash U+2014), `―` (horizontal bar U+2015).
const WINDASH_CHARS: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];

/// Maximum number of dashes allowed in windash expansion.
/// 5^8 = 390,625 variants — beyond this the expansion is too large.
const MAX_WINDASH_DASHES: usize = 8;

/// Expand windash variants: for each `-` in the string, generate all
/// permutations by substituting with `-`, `/`, `–`, `—`, and `―`.
fn expand_windash(input: &str) -> Result<Vec<String>> {
    // Find byte positions of '-' characters
    let dash_positions: Vec<usize> = input
        .char_indices()
        .filter(|(_, c)| *c == '-')
        .map(|(i, _)| i)
        .collect();

    if dash_positions.is_empty() {
        return Ok(vec![input.to_string()]);
    }

    let n = dash_positions.len();
    if n > MAX_WINDASH_DASHES {
        return Err(EvalError::InvalidModifiers(format!(
            "windash modifier: value contains {n} dashes, max is {MAX_WINDASH_DASHES} \
             (would generate {} variants)",
            5u64.saturating_pow(n as u32)
        )));
    }

    // Generate all 5^n combinations
    let total = WINDASH_CHARS.len().pow(n as u32);
    let mut variants = Vec::with_capacity(total);

    for combo in 0..total {
        let mut variant = input.to_string();
        let mut idx = combo;
        // Replace from back to front to preserve byte positions
        for &pos in dash_positions.iter().rev() {
            let replacement = WINDASH_CHARS[idx % WINDASH_CHARS.len()];
            variant.replace_range(pos..pos + 1, &replacement.to_string());
            idx /= WINDASH_CHARS.len();
        }
        variants.push(variant);
    }

    Ok(variants)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::FieldSpec;
    use serde_json::json;

    fn make_field_spec(name: &str, modifiers: &[Modifier]) -> FieldSpec {
        FieldSpec::new(Some(name.to_string()), modifiers.to_vec())
    }

    fn make_item(name: &str, modifiers: &[Modifier], values: Vec<SigmaValue>) -> DetectionItem {
        DetectionItem {
            field: make_field_spec(name, modifiers),
            values,
        }
    }

    #[test]
    fn test_compile_exact_match() {
        let item = make_item(
            "CommandLine",
            &[],
            vec![SigmaValue::String(SigmaString::new("whoami"))],
        );
        let compiled = compile_detection_item(&item).unwrap();
        assert_eq!(compiled.field, Some("CommandLine".into()));

        let ev = json!({"CommandLine": "whoami"});
        let event = Event::from_value(&ev);
        assert!(eval_detection_item(&compiled, &event));

        let ev2 = json!({"CommandLine": "WHOAMI"});
        let event2 = Event::from_value(&ev2);
        assert!(eval_detection_item(&compiled, &event2)); // case-insensitive
    }

    #[test]
    fn test_compile_contains() {
        let item = make_item(
            "CommandLine",
            &[Modifier::Contains],
            vec![SigmaValue::String(SigmaString::new("whoami"))],
        );
        let compiled = compile_detection_item(&item).unwrap();

        let ev = json!({"CommandLine": "cmd /c whoami /all"});
        let event = Event::from_value(&ev);
        assert!(eval_detection_item(&compiled, &event));

        let ev2 = json!({"CommandLine": "ipconfig"});
        let event2 = Event::from_value(&ev2);
        assert!(!eval_detection_item(&compiled, &event2));
    }

    #[test]
    fn test_compile_endswith() {
        let item = make_item(
            "Image",
            &[Modifier::EndsWith],
            vec![SigmaValue::String(SigmaString::new(".exe"))],
        );
        let compiled = compile_detection_item(&item).unwrap();

        let ev = json!({"Image": "C:\\Windows\\cmd.exe"});
        let event = Event::from_value(&ev);
        assert!(eval_detection_item(&compiled, &event));

        let ev2 = json!({"Image": "C:\\Windows\\cmd.bat"});
        let event2 = Event::from_value(&ev2);
        assert!(!eval_detection_item(&compiled, &event2));
    }

    #[test]
    fn test_compile_contains_all() {
        let item = make_item(
            "CommandLine",
            &[Modifier::Contains, Modifier::All],
            vec![
                SigmaValue::String(SigmaString::new("net")),
                SigmaValue::String(SigmaString::new("user")),
            ],
        );
        let compiled = compile_detection_item(&item).unwrap();

        let ev = json!({"CommandLine": "net user admin"});
        let event = Event::from_value(&ev);
        assert!(eval_detection_item(&compiled, &event));

        let ev2 = json!({"CommandLine": "net localgroup"});
        let event2 = Event::from_value(&ev2);
        assert!(!eval_detection_item(&compiled, &event2)); // missing "user"
    }

    #[test]
    fn test_all_modifier_single_value_rejected() {
        let item = make_item(
            "CommandLine",
            &[Modifier::Contains, Modifier::All],
            vec![SigmaValue::String(SigmaString::new("net"))],
        );
        let result = compile_detection_item(&item);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("|all modifier requires more than one value"));
    }

    #[test]
    fn test_all_modifier_empty_values_rejected() {
        let item = make_item("CommandLine", &[Modifier::Contains, Modifier::All], vec![]);
        let result = compile_detection_item(&item);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_modifier_multiple_values_accepted() {
        // Two values with |all is valid
        let item = make_item(
            "CommandLine",
            &[Modifier::Contains, Modifier::All],
            vec![
                SigmaValue::String(SigmaString::new("net")),
                SigmaValue::String(SigmaString::new("user")),
            ],
        );
        assert!(compile_detection_item(&item).is_ok());
    }

    #[test]
    fn test_compile_regex() {
        let item = make_item(
            "CommandLine",
            &[Modifier::Re],
            vec![SigmaValue::String(SigmaString::from_raw(r"cmd\.exe.*/c"))],
        );
        let compiled = compile_detection_item(&item).unwrap();

        let ev = json!({"CommandLine": "cmd.exe /c whoami"});
        let event = Event::from_value(&ev);
        assert!(eval_detection_item(&compiled, &event));
    }

    #[test]
    fn test_regex_case_sensitive_by_default() {
        // Sigma spec: "|re" is case-sensitive by default
        let item = make_item(
            "User",
            &[Modifier::Re],
            vec![SigmaValue::String(SigmaString::from_raw("Admin"))],
        );
        let compiled = compile_detection_item(&item).unwrap();

        let ev_match = json!({"User": "Admin"});
        assert!(eval_detection_item(
            &compiled,
            &Event::from_value(&ev_match)
        ));

        let ev_no_match = json!({"User": "admin"});
        assert!(!eval_detection_item(
            &compiled,
            &Event::from_value(&ev_no_match)
        ));
    }

    #[test]
    fn test_regex_case_insensitive_with_i_modifier() {
        // |re|i enables case-insensitive matching
        let item = make_item(
            "User",
            &[Modifier::Re, Modifier::IgnoreCase],
            vec![SigmaValue::String(SigmaString::from_raw("Admin"))],
        );
        let compiled = compile_detection_item(&item).unwrap();

        let ev_exact = json!({"User": "Admin"});
        assert!(eval_detection_item(
            &compiled,
            &Event::from_value(&ev_exact)
        ));

        let ev_lower = json!({"User": "admin"});
        assert!(eval_detection_item(
            &compiled,
            &Event::from_value(&ev_lower)
        ));
    }

    #[test]
    fn test_compile_cidr() {
        let item = make_item(
            "SourceIP",
            &[Modifier::Cidr],
            vec![SigmaValue::String(SigmaString::new("10.0.0.0/8"))],
        );
        let compiled = compile_detection_item(&item).unwrap();

        let ev = json!({"SourceIP": "10.1.2.3"});
        let event = Event::from_value(&ev);
        assert!(eval_detection_item(&compiled, &event));

        let ev2 = json!({"SourceIP": "192.168.1.1"});
        let event2 = Event::from_value(&ev2);
        assert!(!eval_detection_item(&compiled, &event2));
    }

    #[test]
    fn test_compile_exists() {
        let item = make_item(
            "SomeField",
            &[Modifier::Exists],
            vec![SigmaValue::Bool(true)],
        );
        let compiled = compile_detection_item(&item).unwrap();

        let ev = json!({"SomeField": "value"});
        let event = Event::from_value(&ev);
        assert!(eval_detection_item(&compiled, &event));

        let ev2 = json!({"OtherField": "value"});
        let event2 = Event::from_value(&ev2);
        assert!(!eval_detection_item(&compiled, &event2));
    }

    #[test]
    fn test_compile_wildcard() {
        let item = make_item(
            "Image",
            &[],
            vec![SigmaValue::String(SigmaString::new(r"*\cmd.exe"))],
        );
        let compiled = compile_detection_item(&item).unwrap();

        let ev = json!({"Image": "C:\\Windows\\System32\\cmd.exe"});
        let event = Event::from_value(&ev);
        assert!(eval_detection_item(&compiled, &event));

        let ev2 = json!({"Image": "C:\\Windows\\powershell.exe"});
        let event2 = Event::from_value(&ev2);
        assert!(!eval_detection_item(&compiled, &event2));
    }

    #[test]
    fn test_compile_numeric_comparison() {
        let item = make_item("EventID", &[Modifier::Gte], vec![SigmaValue::Integer(4688)]);
        let compiled = compile_detection_item(&item).unwrap();

        let ev = json!({"EventID": 4688});
        let event = Event::from_value(&ev);
        assert!(eval_detection_item(&compiled, &event));

        let ev2 = json!({"EventID": 1000});
        let event2 = Event::from_value(&ev2);
        assert!(!eval_detection_item(&compiled, &event2));
    }

    #[test]
    fn test_windash_expansion() {
        // Two dashes → 5^2 = 25 variants
        let variants = expand_windash("-param -value").unwrap();
        assert_eq!(variants.len(), 25);
        // Original and slash variants
        assert!(variants.contains(&"-param -value".to_string()));
        assert!(variants.contains(&"/param -value".to_string()));
        assert!(variants.contains(&"-param /value".to_string()));
        assert!(variants.contains(&"/param /value".to_string()));
        // En dash (U+2013)
        assert!(variants.contains(&"\u{2013}param \u{2013}value".to_string()));
        // Em dash (U+2014)
        assert!(variants.contains(&"\u{2014}param \u{2014}value".to_string()));
        // Horizontal bar (U+2015)
        assert!(variants.contains(&"\u{2015}param \u{2015}value".to_string()));
        // Mixed: slash + en dash
        assert!(variants.contains(&"/param \u{2013}value".to_string()));
    }

    #[test]
    fn test_windash_no_dash() {
        let variants = expand_windash("nodash").unwrap();
        assert_eq!(variants.len(), 1);
        assert_eq!(variants[0], "nodash");
    }

    #[test]
    fn test_windash_single_dash() {
        // One dash → 5 variants
        let variants = expand_windash("-v").unwrap();
        assert_eq!(variants.len(), 5);
        assert!(variants.contains(&"-v".to_string()));
        assert!(variants.contains(&"/v".to_string()));
        assert!(variants.contains(&"\u{2013}v".to_string()));
        assert!(variants.contains(&"\u{2014}v".to_string()));
        assert!(variants.contains(&"\u{2015}v".to_string()));
    }

    #[test]
    fn test_base64_offset_patterns() {
        let patterns = base64_offset_patterns(b"Test");
        assert!(!patterns.is_empty());
        // The first pattern should be the normal base64 encoding of "Test"
        assert!(
            patterns
                .iter()
                .any(|p| p.contains("VGVzdA") || p.contains("Rlc3"))
        );
    }

    #[test]
    fn test_pattern_matches() {
        assert!(pattern_matches("selection_*", "selection_main"));
        assert!(pattern_matches("selection_*", "selection_"));
        assert!(!pattern_matches("selection_*", "filter_main"));
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("*_filter", "my_filter"));
        assert!(pattern_matches("exact", "exact"));
        assert!(!pattern_matches("exact", "other"));
    }

    #[test]
    fn test_eval_condition_and() {
        let items_sel = vec![make_item(
            "CommandLine",
            &[Modifier::Contains],
            vec![SigmaValue::String(SigmaString::new("whoami"))],
        )];
        let items_filter = vec![make_item(
            "User",
            &[],
            vec![SigmaValue::String(SigmaString::new("SYSTEM"))],
        )];

        let mut detections = HashMap::new();
        detections.insert(
            "selection".into(),
            compile_detection(&Detection::AllOf(items_sel)).unwrap(),
        );
        detections.insert(
            "filter".into(),
            compile_detection(&Detection::AllOf(items_filter)).unwrap(),
        );

        let cond = ConditionExpr::And(vec![
            ConditionExpr::Identifier("selection".into()),
            ConditionExpr::Not(Box::new(ConditionExpr::Identifier("filter".into()))),
        ]);

        let ev = json!({"CommandLine": "whoami", "User": "admin"});
        let event = Event::from_value(&ev);
        let mut matched = Vec::new();
        assert!(eval_condition(&cond, &detections, &event, &mut matched));

        let ev2 = json!({"CommandLine": "whoami", "User": "SYSTEM"});
        let event2 = Event::from_value(&ev2);
        let mut matched2 = Vec::new();
        assert!(!eval_condition(&cond, &detections, &event2, &mut matched2));
    }

    #[test]
    fn test_compile_expand_modifier() {
        let items = vec![make_item(
            "path",
            &[Modifier::Expand],
            vec![SigmaValue::String(SigmaString::new(
                "C:\\Users\\%username%\\Downloads",
            ))],
        )];
        let detection = compile_detection(&Detection::AllOf(items)).unwrap();

        let mut detections = HashMap::new();
        detections.insert("selection".into(), detection);

        let cond = ConditionExpr::Identifier("selection".into());

        // Match: field matches after placeholder resolution
        let ev = json!({
            "path": "C:\\Users\\admin\\Downloads",
            "username": "admin"
        });
        let event = Event::from_value(&ev);
        let mut matched = Vec::new();
        assert!(eval_condition(&cond, &detections, &event, &mut matched));

        // No match: different user
        let ev2 = json!({
            "path": "C:\\Users\\admin\\Downloads",
            "username": "guest"
        });
        let event2 = Event::from_value(&ev2);
        let mut matched2 = Vec::new();
        assert!(!eval_condition(&cond, &detections, &event2, &mut matched2));
    }

    #[test]
    fn test_compile_timestamp_hour_modifier() {
        let items = vec![make_item(
            "timestamp",
            &[Modifier::Hour],
            vec![SigmaValue::Integer(3)],
        )];
        let detection = compile_detection(&Detection::AllOf(items)).unwrap();

        let mut detections = HashMap::new();
        detections.insert("selection".into(), detection);

        let cond = ConditionExpr::Identifier("selection".into());

        // Match: timestamp at 03:xx UTC
        let ev = json!({"timestamp": "2024-07-10T03:30:00Z"});
        let event = Event::from_value(&ev);
        let mut matched = Vec::new();
        assert!(eval_condition(&cond, &detections, &event, &mut matched));

        // No match: timestamp at 12:xx UTC
        let ev2 = json!({"timestamp": "2024-07-10T12:30:00Z"});
        let event2 = Event::from_value(&ev2);
        let mut matched2 = Vec::new();
        assert!(!eval_condition(&cond, &detections, &event2, &mut matched2));
    }

    #[test]
    fn test_compile_timestamp_month_modifier() {
        let items = vec![make_item(
            "created",
            &[Modifier::Month],
            vec![SigmaValue::Integer(12)],
        )];
        let detection = compile_detection(&Detection::AllOf(items)).unwrap();

        let mut detections = HashMap::new();
        detections.insert("selection".into(), detection);

        let cond = ConditionExpr::Identifier("selection".into());

        // Match: December
        let ev = json!({"created": "2024-12-25T10:00:00Z"});
        let event = Event::from_value(&ev);
        let mut matched = Vec::new();
        assert!(eval_condition(&cond, &detections, &event, &mut matched));

        // No match: July
        let ev2 = json!({"created": "2024-07-10T10:00:00Z"});
        let event2 = Event::from_value(&ev2);
        let mut matched2 = Vec::new();
        assert!(!eval_condition(&cond, &detections, &event2, &mut matched2));
    }

    fn make_test_sigma_rule(title: &str, custom_attributes: HashMap<String, String>) -> SigmaRule {
        use rsigma_parser::{Detections, LogSource};
        SigmaRule {
            title: title.to_string(),
            id: Some("test-id".to_string()),
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            level: Some(Level::Medium),
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            tags: vec![],
            scope: vec![],
            logsource: LogSource {
                category: Some("test".to_string()),
                product: None,
                service: None,
                definition: None,
                custom: HashMap::new(),
            },
            detection: Detections {
                named: {
                    let mut m = HashMap::new();
                    m.insert(
                        "selection".to_string(),
                        Detection::AllOf(vec![make_item(
                            "action",
                            &[],
                            vec![SigmaValue::String(SigmaString::new("login"))],
                        )]),
                    );
                    m
                },
                conditions: vec![ConditionExpr::Identifier("selection".to_string())],
                condition_strings: vec!["selection".to_string()],
                timeframe: None,
            },
            fields: vec![],
            falsepositives: vec![],
            custom_attributes,
        }
    }

    #[test]
    fn test_include_event_custom_attribute() {
        let mut attrs = HashMap::new();
        attrs.insert("rsigma.include_event".to_string(), "true".to_string());
        let rule = make_test_sigma_rule("Include Event Test", attrs);

        let compiled = compile_rule(&rule).unwrap();
        assert!(compiled.include_event);

        let ev = json!({"action": "login", "user": "alice"});
        let event = Event::from_value(&ev);
        let result = evaluate_rule(&compiled, &event).unwrap();
        assert!(result.event.is_some());
        assert_eq!(result.event.unwrap(), ev);
    }

    #[test]
    fn test_no_include_event_by_default() {
        let rule = make_test_sigma_rule("No Include Event Test", HashMap::new());

        let compiled = compile_rule(&rule).unwrap();
        assert!(!compiled.include_event);

        let ev = json!({"action": "login", "user": "alice"});
        let event = Event::from_value(&ev);
        let result = evaluate_rule(&compiled, &event).unwrap();
        assert!(result.event.is_none());
    }
}

// =============================================================================
// Property-based tests
// =============================================================================

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // -------------------------------------------------------------------------
    // 1. Windash expansion: count is always 5^n for n dashes
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn windash_count_is_5_pow_n(
            // Generate a string with 0-3 dashes embedded in alphabetic text
            prefix in "[a-z]{0,5}",
            dashes in prop::collection::vec(Just('-'), 0..=3),
            suffix in "[a-z]{0,5}",
        ) {
            let mut input = prefix;
            for d in &dashes {
                input.push(*d);
            }
            input.push_str(&suffix);

            let n = input.chars().filter(|c| *c == '-').count();
            let variants = expand_windash(&input).unwrap();
            let expected = 5usize.pow(n as u32);
            prop_assert_eq!(variants.len(), expected,
                "expand_windash({:?}) should produce {} variants, got {}",
                input, expected, variants.len());
        }
    }

    // -------------------------------------------------------------------------
    // 2. Windash expansion: no duplicates
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn windash_no_duplicates(
            prefix in "[a-z]{0,4}",
            dashes in prop::collection::vec(Just('-'), 0..=2),
            suffix in "[a-z]{0,4}",
        ) {
            let mut input = prefix;
            for d in &dashes {
                input.push(*d);
            }
            input.push_str(&suffix);

            let variants = expand_windash(&input).unwrap();
            let unique: std::collections::HashSet<&String> = variants.iter().collect();
            prop_assert_eq!(variants.len(), unique.len(),
                "expand_windash({:?}) produced duplicates", input);
        }
    }

    // -------------------------------------------------------------------------
    // 3. Windash expansion: original string is always in the output
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn windash_contains_original(
            prefix in "[a-z]{0,5}",
            dashes in prop::collection::vec(Just('-'), 0..=3),
            suffix in "[a-z]{0,5}",
        ) {
            let mut input = prefix;
            for d in &dashes {
                input.push(*d);
            }
            input.push_str(&suffix);

            let variants = expand_windash(&input).unwrap();
            prop_assert!(variants.contains(&input),
                "expand_windash({:?}) should contain the original", input);
        }
    }

    // -------------------------------------------------------------------------
    // 4. Windash expansion: all variants have same length minus multi-byte diffs
    //    (each dash position gets replaced by a char, non-dash parts stay the same)
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn windash_variants_preserve_non_dash_chars(
            prefix in "[a-z]{1,5}",
            suffix in "[a-z]{1,5}",
        ) {
            let input = format!("{prefix}-{suffix}");
            let variants = expand_windash(&input).unwrap();
            for variant in &variants {
                // The prefix and suffix parts should be preserved
                prop_assert!(variant.starts_with(&prefix),
                    "variant {:?} should start with {:?}", variant, prefix);
                prop_assert!(variant.ends_with(&suffix),
                    "variant {:?} should end with {:?}", variant, suffix);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 5. Windash with no dashes: returns single-element vec with original
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn windash_no_dashes_passthrough(text in "[a-zA-Z0-9]{1,20}") {
            prop_assume!(!text.contains('-'));
            let variants = expand_windash(&text).unwrap();
            prop_assert_eq!(variants.len(), 1);
            prop_assert_eq!(&variants[0], &text);
        }
    }
}
