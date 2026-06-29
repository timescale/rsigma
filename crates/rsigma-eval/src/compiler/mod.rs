//! Compile parsed Sigma rules into optimized in-memory representations.
//!
//! The compiler transforms the parser AST (`SigmaRule`, `Detection`,
//! `DetectionItem`) into compiled forms (`CompiledRule`, `CompiledDetection`,
//! `CompiledDetectionItem`) that can be evaluated efficiently against events.
//!
//! Modifier interpretation happens here: the compiler reads the `Vec<Modifier>`
//! from each `FieldSpec` and produces the appropriate `CompiledMatcher` variant.

mod helpers;
#[doc(hidden)]
pub mod optimizer;
#[cfg(test)]
mod tests;

// Re-export so equivalence proptests in other modules and the fuzz target
// can drive the optimizer directly.
#[cfg(test)]
pub(crate) use optimizer::optimize_any_of as optimize_any_of_for_test;

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use regex::Regex;

use rsigma_parser::fieldpath::{first_unescaped, unescape_brackets};
use rsigma_parser::value::{SpecialChar, StringPart};
use rsigma_parser::{
    ArrayQuantifier, ConditionExpr, Detection, DetectionItem, Level, LogSource, Modifier,
    Quantifier, SigmaRule, SigmaString, SigmaValue,
};

use crate::error::{EvalError, Result};
use crate::event::{Event, EventValue};
use crate::matcher::{CompiledMatcher, sigma_string_to_regex};
use crate::result::{
    DetectionBody, EvaluationResult, FieldMatch, MatchDetailLevel, MatcherKind, ResultBody,
    RuleHeader,
};

pub(crate) use helpers::yaml_to_json_map;
use helpers::{
    base64_offset_patterns, build_regex, expand_windash, sigma_string_to_bytes, to_utf16_bom_bytes,
    to_utf16be_bytes, to_utf16le_bytes, value_to_f64, value_to_plain_string,
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
    /// Array object-scope match: evaluate `body` against the members of the
    /// array at `field`, with `any`/`all` quantification. Within `body`, a
    /// detection item with `field == None` matches the array member itself.
    ArrayMatch {
        field: String,
        quantifier: ArrayQuantifier,
        body: Box<CompiledDetection>,
    },
    /// AND of heterogeneous sub-detections (a mapping mixing plain items with
    /// array object-scope blocks).
    And(Vec<CompiledDetection>),
    /// Extended array object-scope body: named element-scoped sub-selections
    /// combined by `condition` (and/or/not), evaluated against a single array
    /// member. Appears only as an [`ArrayMatch`](CompiledDetection::ArrayMatch)
    /// body.
    Conditional {
        named: HashMap<String, CompiledDetection>,
        condition: ConditionExpr,
    },
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
    /// Pre-computed flag set when the matcher is a positive substring
    /// assertion eligible for bloom-filter pre-filtering. Recomputing the
    /// recursive `is_positive_substring_matcher` walk for every event would
    /// dominate the eval cost on rule sets where most items don't qualify.
    pub bloom_eligible: bool,
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

/// Evaluate a compiled rule against an event, returning an
/// [`EvaluationResult`] if it matches.
///
/// This is the public entry point for one-shot rule evaluation. It does no
/// bloom pre-filtering; every detection item is evaluated directly. Engines
/// that maintain a per-field bloom index should call the crate-private
/// `evaluate_rule_with_bloom` variant via the `Engine` API instead.
pub fn evaluate_rule(rule: &CompiledRule, event: &impl Event) -> Option<EvaluationResult> {
    evaluate_rule_with_bloom(
        rule,
        event,
        &crate::engine::bloom_index::NoBloom,
        MatchDetailLevel::Off,
    )
}

/// Evaluate a compiled rule against an event with bloom pre-filtering.
///
/// `bloom` provides per-field verdicts for positive substring matchers.
/// When `bloom.verdict_for_field(field)` returns `DefinitelyNoMatch`, any
/// positive substring item targeting that field is short-circuited to
/// `false` without invoking its matcher. The pre-filter is purely an
/// optimization: it never changes the eval result vs `evaluate_rule`.
pub(crate) fn evaluate_rule_with_bloom<E, B>(
    rule: &CompiledRule,
    event: &E,
    bloom: &B,
    level: MatchDetailLevel,
) -> Option<EvaluationResult>
where
    E: Event,
    B: crate::engine::bloom_index::BloomLookup,
{
    for condition in &rule.conditions {
        let mut matched_selections = Vec::new();
        if eval_condition_with_bloom(
            condition,
            &rule.detections,
            event,
            &mut matched_selections,
            bloom,
        ) {
            let matched_fields =
                collect_field_matches(&matched_selections, &rule.detections, event, level);

            let event_data = if rule.include_event {
                Some(event.to_json())
            } else {
                None
            };

            return Some(EvaluationResult {
                header: RuleHeader {
                    rule_title: rule.title.clone(),
                    rule_id: rule.id.clone(),
                    level: rule.level,
                    tags: rule.tags.clone(),
                    custom_attributes: rule.custom_attributes.clone(),
                    enrichments: None,
                },
                body: ResultBody::Detection(DetectionBody {
                    matched_selections,
                    matched_fields,
                    event: event_data,
                }),
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
        Detection::ArrayMatch {
            field,
            quantifier,
            body,
        } => {
            let compiled_body = compile_detection(body)?;
            Ok(CompiledDetection::ArrayMatch {
                field: field.clone(),
                quantifier: *quantifier,
                body: Box::new(compiled_body),
            })
        }
        Detection::And(dets) => {
            if dets.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "And detection must not be empty".into(),
                ));
            }
            let compiled: Result<Vec<_>> = dets.iter().map(compile_detection).collect();
            Ok(CompiledDetection::And(compiled?))
        }
        Detection::Conditional { named, condition } => {
            if named.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "Conditional detection must have at least one named sub-selection".into(),
                ));
            }
            let compiled: Result<HashMap<String, CompiledDetection>> = named
                .iter()
                .map(|(k, d)| Ok((k.clone(), compile_detection(d)?)))
                .collect();
            Ok(CompiledDetection::Conditional {
                named: compiled?,
                condition: condition.clone(),
            })
        }
        Detection::Keywords(values) => {
            let ci = true; // keywords are case-insensitive by default
            let matchers: Vec<CompiledMatcher> = values
                .iter()
                .map(|v| compile_value_default(v, ci))
                .collect::<Result<Vec<_>>>()?;
            // Keywords are OR-semantics; safe to apply AnyOf optimizer.
            let matcher = optimizer::optimize_any_of(matchers);
            Ok(CompiledDetection::Keywords(matcher))
        }
    }
}

fn compile_detection_item(item: &DetectionItem) -> Result<CompiledDetectionItem> {
    let ctx = ModCtx::from_modifiers(&item.field.modifiers);

    // Reject contradictory modifier combinations at compile time so a
    // misconfigured field does not silently resolve to whichever
    // modifier the dispatch arms below check first. Previously
    // `Field|cidr|contains` produced a CIDR match (the `contains` was
    // ignored), `Field|re|contains` produced a regex match (the
    // `contains` was ignored), `Field|gt|contains` ran numeric `gt`
    // and dropped `contains`, and so on; the rule still compiled but
    // its semantics were not what the author wrote.
    validate_modifiers(&ctx, &item.field.modifiers)?;

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
            bloom_eligible: false,
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

    // Combine multiple values: |all → AND, default → OR.
    //
    // CRITICAL invariant: the optimizer is only applied to the OR (`AnyOf`)
    // branch. `AllOf` MUST keep its `Vec<Contains>` intact: collapsing
    // `AllOf(Contains(...))` into `AhoCorasickSet` would silently flip the
    // semantics from "all patterns must match" to "any matches".
    let combined = if ctx.all {
        if matchers.len() == 1 {
            matchers
                .into_iter()
                .next()
                .unwrap_or(CompiledMatcher::AllOf(vec![]))
        } else {
            CompiledMatcher::AllOf(matchers)
        }
    } else {
        optimizer::optimize_any_of(matchers)
    };

    let bloom_eligible = item.field.name.is_some()
        && crate::engine::bloom_index::is_positive_substring_matcher(&combined);

    Ok(CompiledDetectionItem {
        field: item.field.name.clone(),
        matcher: combined,
        exists: None,
        bloom_eligible,
    })
}

// =============================================================================
// Modifier conflict validation
// =============================================================================

/// Reject contradictory modifier combinations before any value is compiled.
///
/// The compiler dispatch in [`compile_value`] checks modifier flags in a
/// fixed order (`expand` -> timestamp part -> `fieldref` -> `re` ->
/// `cidr` -> numeric comparison -> `neq` -> default string/value
/// matching). Whichever flag the dispatch checks first wins, so a
/// field declared as `Field|cidr|contains` silently produced a CIDR
/// match with the `contains` modifier dropped, and a field declared
/// as `Field|re|contains` silently produced a regex match with the
/// `contains` modifier dropped. Both are bugs in the rule the author
/// could not see; the rule still compiled and still matched
/// *something*. Reject every contradiction up front so the operator
/// has to clean the rule.
///
/// The categories of conflict checked here are:
///
/// 1. At most one *operator* modifier per item: `contains`,
///    `startswith`, `endswith`, `re`, `cidr`, `exists`, `fieldref`,
///    numeric comparison, and the timestamp parts each describe how
///    the comparison works and are mutually exclusive.
/// 2. At most one UTF-16 encoding: `wide`, `utf16`, and `utf16be`
///    describe different UTF-16 dialects and cannot coexist.
/// 3. `base64` and `base64offset` are mutually exclusive (each
///    describes a different base64 encoding strategy).
/// 4. Value-transformation modifiers (`base64`, `base64offset`,
///    `wide`, `utf16`, `utf16be`, `windash`, `expand`) only apply to
///    string operators (default eq plus substring matchers); pairing
///    them with `re`, `cidr`, numeric comparison, `exists`,
///    `fieldref`, or a timestamp part means the transformation has
///    nowhere to land.
/// 5. The regex flag modifiers (`i`, `m`, `s`) require `re`; outside
///    a regex context they are no-ops the parser silently accepted.
fn validate_modifiers(ctx: &ModCtx, modifiers: &[Modifier]) -> Result<()> {
    // 1. Multiple operators on a single item.
    let mut operators: Vec<&'static str> = Vec::new();
    if ctx.contains {
        operators.push("contains");
    }
    if ctx.startswith {
        operators.push("startswith");
    }
    if ctx.endswith {
        operators.push("endswith");
    }
    if ctx.re {
        operators.push("re");
    }
    if ctx.cidr {
        operators.push("cidr");
    }
    if ctx.exists {
        operators.push("exists");
    }
    if ctx.fieldref {
        operators.push("fieldref");
    }
    if ctx.gt {
        operators.push("gt");
    }
    if ctx.gte {
        operators.push("gte");
    }
    if ctx.lt {
        operators.push("lt");
    }
    if ctx.lte {
        operators.push("lte");
    }
    for m in modifiers {
        match m {
            Modifier::Minute => operators.push("minute"),
            Modifier::Hour => operators.push("hour"),
            Modifier::Day => operators.push("day"),
            Modifier::Week => operators.push("week"),
            Modifier::Month => operators.push("month"),
            Modifier::Year => operators.push("year"),
            _ => {}
        }
    }
    if operators.len() > 1 {
        return Err(EvalError::InvalidModifiers(format!(
            "conflicting modifiers: at most one operator may be set per field; \
             got |{}",
            operators.join(", |")
        )));
    }

    // 2. Multiple UTF-16 encodings.
    let mut wide_encodings: Vec<&'static str> = Vec::new();
    if ctx.wide {
        wide_encodings.push("wide");
    }
    if ctx.utf16 {
        wide_encodings.push("utf16");
    }
    if ctx.utf16be {
        wide_encodings.push("utf16be");
    }
    if wide_encodings.len() > 1 {
        return Err(EvalError::InvalidModifiers(format!(
            "conflicting modifiers: |wide, |utf16, and |utf16be are mutually \
             exclusive UTF-16 encodings; got |{}",
            wide_encodings.join(", |")
        )));
    }

    // 3. base64 and base64offset cannot coexist.
    if ctx.base64 && ctx.base64offset {
        return Err(EvalError::InvalidModifiers(
            "conflicting modifiers: |base64 and |base64offset are mutually \
             exclusive base64 strategies; pick one"
                .into(),
        ));
    }

    // 4. Value transformations only apply to string operators (default
    //    eq plus substring matchers). Pairing them with re/cidr/
    //    numeric/exists/fieldref/timestamp means the transformation
    //    has nowhere to land.
    let has_non_string_operator = ctx.re
        || ctx.cidr
        || ctx.exists
        || ctx.fieldref
        || ctx.has_numeric_comparison()
        || ctx.timestamp_part.is_some();
    if has_non_string_operator {
        let mut transforms: Vec<&'static str> = Vec::new();
        if ctx.base64 {
            transforms.push("base64");
        }
        if ctx.base64offset {
            transforms.push("base64offset");
        }
        if ctx.wide {
            transforms.push("wide");
        }
        if ctx.utf16 {
            transforms.push("utf16");
        }
        if ctx.utf16be {
            transforms.push("utf16be");
        }
        if ctx.windash {
            transforms.push("windash");
        }
        if ctx.expand {
            transforms.push("expand");
        }
        if !transforms.is_empty() {
            return Err(EvalError::InvalidModifiers(format!(
                "conflicting modifiers: value transformations |{} only apply \
                 to string match operators (default eq, contains, startswith, \
                 endswith) and cannot be combined with the operator that is \
                 also set on this field",
                transforms.join(", |")
            )));
        }
    }

    // 5. Regex-flag modifiers require |re.
    if !ctx.re {
        let mut regex_flags: Vec<&'static str> = Vec::new();
        if ctx.ignore_case {
            regex_flags.push("i");
        }
        if ctx.multiline {
            regex_flags.push("m");
        }
        if ctx.dotall {
            regex_flags.push("s");
        }
        if !regex_flags.is_empty() {
            return Err(EvalError::InvalidModifiers(format!(
                "regex flag modifiers |{} have no effect without |re; \
                 case sensitivity for substring or equality matching is \
                 controlled by |cased (or its absence, which keeps the \
                 default case-insensitive behavior)",
                regex_flags.join(", |")
            )));
        }
    }

    Ok(())
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
    eval_condition_with_bloom(
        expr,
        detections,
        event,
        matched_selections,
        &crate::engine::bloom_index::NoBloom,
    )
}

/// Bloom-aware version of [`eval_condition`].
///
/// Identical to `eval_condition` except that positive substring leaves are
/// short-circuited to `false` when the bloom proves no pattern can match
/// the event's field value.
pub(crate) fn eval_condition_with_bloom<E, B>(
    expr: &ConditionExpr,
    detections: &HashMap<String, CompiledDetection>,
    event: &E,
    matched_selections: &mut Vec<String>,
    bloom: &B,
) -> bool
where
    E: Event,
    B: crate::engine::bloom_index::BloomLookup,
{
    match expr {
        ConditionExpr::Identifier(name) => {
            if let Some(det) = detections.get(name) {
                let result = eval_detection_with_bloom(det, event, bloom);
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
            .all(|e| eval_condition_with_bloom(e, detections, event, matched_selections, bloom)),

        ConditionExpr::Or(exprs) => exprs
            .iter()
            .any(|e| eval_condition_with_bloom(e, detections, event, matched_selections, bloom)),

        ConditionExpr::Not(inner) => {
            !eval_condition_with_bloom(inner, detections, event, matched_selections, bloom)
        }

        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let matching_names: Vec<&String> = detections
                .keys()
                .filter(|name| pattern.matches_detection_name(name))
                .collect();

            let mut match_count = 0u64;
            for name in &matching_names {
                if let Some(det) = detections.get(*name)
                    && eval_detection_with_bloom(det, event, bloom)
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

/// Evaluate a compiled detection item against an event without bloom
/// pre-filtering. Used only by the in-crate compiler tests; the production
/// paths run through `eval_detection_item_with_bloom` from
/// `evaluate_rule_with_bloom`.
#[cfg(test)]
fn eval_detection_item(item: &CompiledDetectionItem, event: &impl Event) -> bool {
    eval_detection_item_with_bloom(item, event, &crate::engine::bloom_index::NoBloom)
}

/// Evaluate a compiled detection against an event without bloom pre-filtering.
///
/// Used by the [`crate::explain`] recording evaluator to obtain the exact
/// verdict for a detection subtree (including opaque array/conditional bodies)
/// so the explain trace can never disagree with the production engine.
pub(crate) fn eval_detection_no_bloom(detection: &CompiledDetection, event: &impl Event) -> bool {
    eval_detection_with_bloom(detection, event, &crate::engine::bloom_index::NoBloom)
}

/// Evaluate a single compiled detection item against an event without bloom
/// pre-filtering. Used by the [`crate::explain`] recording evaluator so each
/// per-item verdict matches the production engine exactly.
pub(crate) fn eval_detection_item_no_bloom(
    item: &CompiledDetectionItem,
    event: &impl Event,
) -> bool {
    eval_detection_item_with_bloom(item, event, &crate::engine::bloom_index::NoBloom)
}

/// Evaluate a compiled detection against an event with a bloom lookup.
fn eval_detection_with_bloom<E, B>(detection: &CompiledDetection, event: &E, bloom: &B) -> bool
where
    E: Event,
    B: crate::engine::bloom_index::BloomLookup,
{
    match detection {
        CompiledDetection::AllOf(items) => items
            .iter()
            .all(|item| eval_detection_item_with_bloom(item, event, bloom)),
        CompiledDetection::AnyOf(dets) => dets
            .iter()
            .any(|d| eval_detection_with_bloom(d, event, bloom)),
        CompiledDetection::Keywords(matcher) => matcher.matches_keyword(event),
        CompiledDetection::ArrayMatch {
            field,
            quantifier,
            body,
        } => match event.get_field(field) {
            Some(value) => eval_array_quantified(&value, *quantifier, body, event),
            None => array_quantifier_matches_empty(*quantifier),
        },
        CompiledDetection::And(dets) => dets
            .iter()
            .all(|d| eval_detection_with_bloom(d, event, bloom)),
        // Only produced as an `ArrayMatch` body (evaluated via
        // `eval_array_condition`). At the top level it degenerates to a
        // sub-rule over the event, which reuses the condition evaluator.
        CompiledDetection::Conditional { named, condition } => {
            eval_condition_with_bloom(condition, named, event, &mut Vec::new(), bloom)
        }
    }
}

/// Evaluate an array object-scope match against a resolved field value.
///
/// A scalar (non-array, non-null) value is treated as a single-member array,
/// so `any`/`all` both reduce to "the value satisfies the body". `all`
/// requires a non-empty array; a missing/null value never matches.
fn eval_array_quantified<E: Event>(
    value: &EventValue,
    quantifier: ArrayQuantifier,
    body: &CompiledDetection,
    outer: &E,
) -> bool {
    match value {
        EventValue::Array(members) => match quantifier {
            ArrayQuantifier::Any => members.iter().any(|m| eval_array_body(body, m, outer)),
            ArrayQuantifier::All => {
                !members.is_empty() && members.iter().all(|m| eval_array_body(body, m, outer))
            }
            ArrayQuantifier::AllOrEmpty => members.iter().all(|m| eval_array_body(body, m, outer)),
            ArrayQuantifier::None => !members.iter().any(|m| eval_array_body(body, m, outer)),
        },
        // A null or missing array is empty: `none` holds vacuously, the others
        // do not.
        EventValue::Null => array_quantifier_matches_empty(quantifier),
        // A scalar (non-array, non-null) value is a single-member array.
        single => match quantifier {
            ArrayQuantifier::None => !eval_array_body(body, single, outer),
            _ => eval_array_body(body, single, outer),
        },
    }
}

/// Whether a quantifier matches an empty or missing array (zero members).
fn array_quantifier_matches_empty(quantifier: ArrayQuantifier) -> bool {
    matches!(
        quantifier,
        ArrayQuantifier::None | ArrayQuantifier::AllOrEmpty
    )
}

/// Evaluate a compiled detection `body` against a single array member.
///
/// Field references inside `body` resolve relative to the member; a body item
/// with no field name matches the member value itself.
fn eval_array_body<E: Event>(body: &CompiledDetection, member: &EventValue, outer: &E) -> bool {
    match body {
        CompiledDetection::AllOf(items) => items
            .iter()
            .all(|item| eval_array_item(item, member, outer)),
        CompiledDetection::AnyOf(dets) => dets.iter().any(|d| eval_array_body(d, member, outer)),
        CompiledDetection::And(dets) => dets.iter().all(|d| eval_array_body(d, member, outer)),
        CompiledDetection::ArrayMatch {
            field,
            quantifier,
            body: inner,
        } => match element_field(member, field) {
            Some(value) => eval_array_quantified(value, *quantifier, inner, outer),
            None => array_quantifier_matches_empty(*quantifier),
        },
        // Keywords inside an element scope match the member value directly.
        CompiledDetection::Keywords(matcher) => matcher.matches(member, outer),
        // Extended block body: evaluate the condition over named sub-selections
        // against this member (same-element binding under and/or/not).
        CompiledDetection::Conditional { named, condition } => {
            eval_array_condition(condition, named, member, outer)
        }
    }
}

/// Evaluate an extended block-body `condition` against a single array member.
///
/// Each named sub-selection is evaluated against the member (via
/// [`eval_array_body`]), and the boolean structure (`and`/`or`/`not` and
/// selector quantifiers like `1 of x_*`) is applied. This is the element-scoped
/// analogue of [`eval_condition_with_bloom`]; it carries no bloom because array
/// members are not bloom-indexed.
fn eval_array_condition<E: Event>(
    expr: &ConditionExpr,
    named: &HashMap<String, CompiledDetection>,
    member: &EventValue,
    outer: &E,
) -> bool {
    match expr {
        ConditionExpr::Identifier(name) => named
            .get(name)
            .is_some_and(|d| eval_array_body(d, member, outer)),
        ConditionExpr::And(exprs) => exprs
            .iter()
            .all(|e| eval_array_condition(e, named, member, outer)),
        ConditionExpr::Or(exprs) => exprs
            .iter()
            .any(|e| eval_array_condition(e, named, member, outer)),
        ConditionExpr::Not(inner) => !eval_array_condition(inner, named, member, outer),
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let names: Vec<&String> = named
                .keys()
                .filter(|n| pattern.matches_detection_name(n))
                .collect();
            let count = names
                .iter()
                .filter(|n| {
                    named
                        .get(**n)
                        .is_some_and(|d| eval_array_body(d, member, outer))
                })
                .count() as u64;
            match quantifier {
                Quantifier::Any => count >= 1,
                Quantifier::All => count == names.len() as u64,
                Quantifier::Count(n) => count >= *n,
            }
        }
    }
}

/// Evaluate one body item against an array member.
fn eval_array_item<E: Event>(item: &CompiledDetectionItem, member: &EventValue, outer: &E) -> bool {
    if let Some(expect_exists) = item.exists {
        let exists = match &item.field {
            Some(name) => element_field(member, name).is_some_and(|v| !v.is_null()),
            None => !member.is_null(),
        };
        return exists == expect_exists;
    }

    match &item.field {
        Some(name) => match element_field(member, name) {
            Some(value) => item.matcher.matches(value, outer),
            None => matches!(item.matcher, CompiledMatcher::Null),
        },
        // No field name: match the array member value itself.
        None => item.matcher.matches(member, outer),
    }
}

/// Resolve a field path within an array member (an [`EventValue`]).
///
/// Mirrors `JsonEvent::get_field`: a flat key first, then dot-separated
/// traversal that distributes over arrays for object keys and selects a single
/// element for positional `[N]` indices.
fn element_field<'a>(member: &'a EventValue<'a>, path: &str) -> Option<&'a EventValue<'a>> {
    if let EventValue::Map(entries) = member
        && let Some((_, v)) = entries.iter().find(|(k, _)| k.as_ref() == path)
    {
        return Some(v);
    }
    let ops = parse_event_ops(path);
    nav_event_value(member, &ops)
}

enum EventOp<'a> {
    Key(Cow<'a, str>),
    Index(i64),
}

/// Parse a dot path into navigation ops, recognizing positional `name[N]`.
/// Only an unescaped `[...]` is an index; `\[` / `\]` are literal and unescaped
/// into the key.
fn parse_event_ops(path: &str) -> Vec<EventOp<'_>> {
    let mut ops = Vec::new();
    for part in path.split('.') {
        match first_unescaped(part, b'[') {
            Some(bpos) if index_groups(&part[bpos..]).is_some() => {
                let name = &part[..bpos];
                if !name.is_empty() {
                    ops.push(EventOp::Key(unescape_brackets(name)));
                }
                for idx in index_groups(&part[bpos..]).expect("checked") {
                    ops.push(EventOp::Index(idx));
                }
            }
            _ => ops.push(EventOp::Key(unescape_brackets(part))),
        }
    }
    ops
}

/// Parse `[N]` or `[N][M]...` into indices (negative allowed), or `None` if
/// malformed/non-numeric.
fn index_groups(s: &str) -> Option<Vec<i64>> {
    let mut out = Vec::new();
    let mut rem = s;
    while !rem.is_empty() {
        let rest = rem.strip_prefix('[')?;
        let close = rest.find(']')?;
        out.push(rest[..close].parse().ok()?);
        rem = &rest[close + 1..];
    }
    Some(out)
}

fn nav_event_value<'a>(
    current: &'a EventValue<'a>,
    ops: &[EventOp<'_>],
) -> Option<&'a EventValue<'a>> {
    let Some((op, rest)) = ops.split_first() else {
        return Some(current);
    };
    match op {
        EventOp::Key(key) => match current {
            EventValue::Map(entries) => {
                let next = entries
                    .iter()
                    .find(|(k, _)| k.as_ref() == key.as_ref())
                    .map(|(_, v)| v)?;
                nav_event_value(next, rest)
            }
            EventValue::Array(members) => members.iter().find_map(|m| nav_event_value(m, ops)),
            _ => None,
        },
        EventOp::Index(i) => match current {
            EventValue::Array(members) => {
                let idx = crate::event::resolve_array_index(*i, members.len())?;
                nav_event_value(members.get(idx)?, rest)
            }
            _ => None,
        },
    }
}

/// Evaluate a single detection item with bloom pre-filtering.
///
/// When the matcher targets a single field and is a positive substring
/// matcher (not under negation), the bloom verdict is consulted first. A
/// `DefinitelyNoMatch` verdict guarantees the matcher would return `false`,
/// so we return early without invoking it.
fn eval_detection_item_with_bloom<E, B>(item: &CompiledDetectionItem, event: &E, bloom: &B) -> bool
where
    E: Event,
    B: crate::engine::bloom_index::BloomLookup,
{
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
                if item.bloom_eligible
                    && bloom.verdict_for_field(field_name)
                        == crate::engine::bloom_index::BloomVerdict::DefinitelyNoMatch
                {
                    return false;
                }
                item.matcher.matches(&value, event)
            } else {
                matches!(item.matcher, CompiledMatcher::Null)
            }
        }
        None => item.matcher.matches_keyword(event),
    }
}

/// Cap on the number of keyword-match entries recorded per keyword detection
/// at `Summary` / `Full`. A single high-cardinality event (many string
/// leaves) cannot blow up the output line.
const MAX_KEYWORD_MATCHES: usize = 16;

/// Collect field matches from matched selections for the detection result.
///
/// At [`MatchDetailLevel::Off`] this reproduces the historical behavior
/// exactly: one `{ field, value }` entry per field-present `AllOf` item that
/// matched, with keyword and absence matches omitted. At `Summary` / `Full`
/// it attaches the matcher descriptor and reports the previously dropped
/// keyword and `Null`-on-absent matches.
fn collect_field_matches(
    selection_names: &[String],
    detections: &HashMap<String, CompiledDetection>,
    event: &impl Event,
    level: MatchDetailLevel,
) -> Vec<FieldMatch> {
    let mut matches = Vec::new();
    for name in selection_names {
        if let Some(det) = detections.get(name) {
            collect_detection_fields(name, det, event, level, &mut matches);
        }
    }
    matches
}

fn collect_detection_fields(
    selection: &str,
    detection: &CompiledDetection,
    event: &impl Event,
    level: MatchDetailLevel,
    out: &mut Vec<FieldMatch>,
) {
    match detection {
        CompiledDetection::AllOf(items) => {
            for item in items {
                match &item.field {
                    Some(field_name) => {
                        if let Some(value) = event.get_field(field_name) {
                            if item.matcher.matches(&value, event) {
                                out.push(make_field_match(
                                    selection,
                                    field_name,
                                    value.to_json(),
                                    &item.matcher,
                                    level,
                                ));
                            }
                        } else if level != MatchDetailLevel::Off
                            && matches!(item.matcher, CompiledMatcher::Null)
                        {
                            // Field absent and matched by the `Null` matcher.
                            // Never reported at `Off` (preserves wire shape).
                            out.push(make_field_match(
                                selection,
                                field_name,
                                serde_json::Value::Null,
                                &item.matcher,
                                level,
                            ));
                        }
                    }
                    None => {
                        // Keyword item inside an `AllOf`. Only reported above `Off`.
                        if level != MatchDetailLevel::Off {
                            collect_keyword_matches(selection, &item.matcher, event, level, out);
                        }
                    }
                }
            }
        }
        CompiledDetection::AnyOf(dets) => {
            for d in dets {
                if eval_detection_with_bloom(d, event, &crate::engine::bloom_index::NoBloom) {
                    collect_detection_fields(selection, d, event, level, out);
                }
            }
        }
        CompiledDetection::ArrayMatch { field, .. } => {
            // Report the array container field and its value (the member
            // fields are relative to elements and not meaningful as top-level
            // field paths).
            if let Some(value) = event.get_field(field) {
                out.push(FieldMatch::new(field.clone(), value.to_json()));
            }
        }
        CompiledDetection::And(dets) => {
            for d in dets {
                if eval_detection_with_bloom(d, event, &crate::engine::bloom_index::NoBloom) {
                    collect_detection_fields(selection, d, event, level, out);
                }
            }
        }
        // Only appears as an array body, whose member fields are not meaningful
        // top-level field paths (the container is reported by `ArrayMatch`).
        CompiledDetection::Conditional { .. } => {}
        CompiledDetection::Keywords(matcher) => {
            // Keyword detections produced no entries historically; only
            // reported above `Off`.
            if level != MatchDetailLevel::Off {
                collect_keyword_matches(selection, matcher, event, level, out);
            }
        }
    }
}

/// Build a [`FieldMatch`] at the requested detail level. `Off` yields the
/// bare `{ field, value }` shape; `Summary` adds the matcher descriptor;
/// `Full` additionally records the pattern.
fn make_field_match(
    selection: &str,
    field: &str,
    value: serde_json::Value,
    matcher: &CompiledMatcher,
    level: MatchDetailLevel,
) -> FieldMatch {
    match level {
        MatchDetailLevel::Off => FieldMatch::new(field, value),
        MatchDetailLevel::Summary | MatchDetailLevel::Full => {
            let d = matcher.describe();
            FieldMatch {
                field: field.to_string(),
                value,
                selection: Some(selection.to_string()),
                matcher: Some(d.kind),
                pattern: if level == MatchDetailLevel::Full {
                    d.pattern
                } else {
                    None
                },
                case_sensitive: d.case_sensitive,
                negated: d.negated,
            }
        }
    }
}

/// Record the individual event string values that satisfied a keyword
/// matcher, capped at [`MAX_KEYWORD_MATCHES`]. Each entry uses the sentinel
/// field name `"keyword"`.
fn collect_keyword_matches(
    selection: &str,
    matcher: &CompiledMatcher,
    event: &impl Event,
    level: MatchDetailLevel,
    out: &mut Vec<FieldMatch>,
) {
    let descriptor = matcher.describe();
    let mut count = 0;
    for s in event.all_string_values() {
        if count >= MAX_KEYWORD_MATCHES {
            break;
        }
        if matcher.matches_str(&s) {
            count += 1;
            out.push(FieldMatch {
                field: "keyword".to_string(),
                value: serde_json::Value::String(s.into_owned()),
                selection: Some(selection.to_string()),
                matcher: Some(MatcherKind::Keyword),
                pattern: if level == MatchDetailLevel::Full {
                    descriptor.pattern.clone()
                } else {
                    None
                },
                case_sensitive: descriptor.case_sensitive,
                negated: descriptor.negated,
            });
        }
    }
}
