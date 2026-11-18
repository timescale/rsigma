//! Backend-neutral test backend modeled after pySigma's `TextQueryTestBackend`.
//!
//! Exercises most generic text backend features without targeting a specific SIEM.
//! Used to validate the `Backend` trait, `TextQueryConfig`, condition walker,
//! value escaping, modifier handling, and output formats.

use std::collections::HashMap;

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_ir::encoding::expand_encoded_matcher;
use rsigma_ir::{
    IrCondition, IrDetection, IrDetectionItem, IrMatcher, IrNumber, IrPattern, IrPatternPart,
    IrRule, IrStrOp, NumericLiteral,
};
use rsigma_parser::*;

use crate::backend::*;
use crate::condition_ir::{convert_lowered_rule, ir_err};
use crate::error::{ConvertError, Result};
use crate::ir_convert::{
    Operand, default_convert_ir_detection, default_convert_ir_detection_item, join, matcher_op,
    negate, selected_detections,
};
use crate::state::{ConversionState, ConvertResult};

// =============================================================================
// TextQueryTestBackend config
// =============================================================================

pub static TEXT_QUERY_TEST_CONFIG: TextQueryConfig = TextQueryConfig {
    precedence: (TokenType::NOT, TokenType::AND, TokenType::OR),
    group_expression: "({expr})",
    token_separator: " ",

    and_token: "and",
    or_token: "or",
    not_token: "not",
    eq_token: "=",

    not_eq_token: Some("!="),
    eq_expression: None,
    not_eq_expression: None,
    convert_not_as_not_eq: false,

    wildcard_multi: "*",
    wildcard_single: "?",

    str_quote: "\"",
    str_quote_pattern: None,
    str_quote_pattern_negation: false,
    escape_char: "\\",
    add_escaped: &[":"],
    filter_chars: &["&"],

    field_quote: Some("'"),
    field_quote_pattern: Some(r"^\w+$"),
    field_quote_pattern_negation: true,
    field_escape: None,
    field_escape_pattern: None,

    startswith_expression: Some("{field} startswith {value}"),
    not_startswith_expression: None,
    startswith_expression_allow_special: false,
    endswith_expression: Some("{field} endswith {value}"),
    not_endswith_expression: None,
    endswith_expression_allow_special: false,
    contains_expression: Some("{field} contains {value}"),
    not_contains_expression: None,
    contains_expression_allow_special: false,
    wildcard_match_expression: Some("{field} match {value}"),

    case_sensitive_match_expression: Some("{field} casematch {value}"),
    case_sensitive_startswith_expression: Some("{field} startswith_cased {value}"),
    case_sensitive_endswith_expression: Some("{field} endswith_cased {value}"),
    case_sensitive_contains_expression: Some("{field} contains_cased {value}"),

    re_expression: Some("{field}=/{regex}/"),
    not_re_expression: None,
    re_escape_char: Some("\\"),
    re_escape: &["/"],
    re_escape_escape_char: Some("\\"),

    cidr_expression: Some("cidrmatch('{field}', \"{value}\")"),
    not_cidr_expression: None,

    field_null_expression: "{field} is null",
    field_exists_expression: Some("exists({field})"),
    field_not_exists_expression: Some("notexists({field})"),

    compare_op_expression: Some("{field}{op}{value}"),
    compare_ops: &[
        ("lt", "<"),
        ("lte", "<="),
        ("gt", ">"),
        ("gte", ">="),
        ("neq", "!="),
    ],

    convert_or_as_in: true,
    convert_and_as_in: true,
    in_expressions_allow_wildcards: true,
    field_in_list_expression: Some("{field} {op} ({list})"),
    or_in_operator: Some("in"),
    and_in_operator: Some("contains-all"),
    list_separator: ", ",

    unbound_value_str_expression: Some("_={value}"),
    unbound_value_num_expression: Some("_={value}"),
    unbound_value_re_expression: Some("_=/{value}/"),

    field_eq_field_expression: Some("{field1}=fieldref({field2})"),
    field_eq_field_escaping_quoting: true,

    deferred_start: Some(" | "),
    deferred_separator: Some(" | "),
    deferred_only_query: "*",

    bool_true: "1",
    bool_false: "0",
    query_expression: "{query}",
    state_defaults: &[],
};

// =============================================================================
// TextQueryTestBackend
// =============================================================================

pub struct TextQueryTestBackend {
    pub config: &'static TextQueryConfig,
}

impl TextQueryTestBackend {
    pub fn new() -> Self {
        Self {
            config: &TEXT_QUERY_TEST_CONFIG,
        }
    }
}

impl Default for TextQueryTestBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// pySigma's value for a string match: the pattern with the operator's
/// wildcards added, unless it already starts or ends with one.
fn full_value(op: IrStrOp, pattern: &IrPattern) -> Vec<IrPatternPart> {
    let mut parts = pattern.parts.clone();
    let lead = matches!(op, IrStrOp::Contains | IrStrOp::EndsWith);
    let trail = matches!(op, IrStrOp::Contains | IrStrOp::StartsWith);
    if lead && parts.first() != Some(&IrPatternPart::WildcardMulti) {
        parts.insert(0, IrPatternPart::WildcardMulti);
    }
    if trail && parts.last() != Some(&IrPatternPart::WildcardMulti) {
        parts.push(IrPatternPart::WildcardMulti);
    }
    parts
}

fn has_wildcard(parts: &[IrPatternPart]) -> bool {
    parts
        .iter()
        .any(|p| !matches!(p, IrPatternPart::Literal(_)))
}

fn is_char(s: &str, c: char) -> bool {
    let mut chars = s.chars();
    chars.next() == Some(c) && chars.next().is_none()
}

/// Quote a value the way pySigma's `convert_value_str` does: wildcards,
/// the quote, and `add_escaped` are escaped when literal, the escape
/// character itself is not, and `filter_chars` are dropped.
fn quote_value(config: &TextQueryConfig, parts: &[IrPatternPart]) -> String {
    let mut out = String::from(config.str_quote);
    for part in parts {
        match part {
            IrPatternPart::Literal(s) => {
                for c in s.chars() {
                    if config.filter_chars.iter().any(|f| is_char(f, c)) {
                        continue;
                    }
                    if is_char(config.wildcard_multi, c)
                        || is_char(config.wildcard_single, c)
                        || is_char(config.str_quote, c)
                        || config.add_escaped.iter().any(|e| is_char(e, c))
                    {
                        out.push_str(config.escape_char);
                    }
                    out.push(c);
                }
            }
            IrPatternPart::WildcardMulti => out.push_str(config.wildcard_multi),
            IrPatternPart::WildcardSingle => out.push_str(config.wildcard_single),
        }
    }
    out.push_str(config.str_quote);
    out
}

fn has_encoded(matcher: &IrMatcher) -> bool {
    match matcher {
        IrMatcher::Encoded { .. } => true,
        IrMatcher::Not(inner) | IrMatcher::TimestampPart { inner, .. } => has_encoded(inner),
        IrMatcher::AnyOf(ms) | IrMatcher::AllOf(ms) => ms.iter().any(has_encoded),
        _ => false,
    }
}

fn expression(expr: Option<&'static str>, what: &str) -> Result<&'static str> {
    expr.ok_or_else(|| ConvertError::UnsupportedModifier(what.into()))
}

/// The field and value of an item that holds a single value an in-list can
/// carry: a case-insensitive string or a number.
fn list_item(item: &IrDetectionItem) -> Option<(&str, &IrMatcher)> {
    let field = item.field.as_deref()?;
    match &item.matcher {
        m @ (IrMatcher::Str {
            case_insensitive: true,
            ..
        }
        | IrMatcher::NumericEq(IrNumber::Literal(_))) => Some((field, m)),
        _ => None,
    }
}

/// The single list item of a detection with one item.
fn single_list_item(det: &IrDetection) -> Option<&IrDetectionItem> {
    match det {
        IrDetection::AllOf(items) if items.len() == 1 => list_item(&items[0]).map(|_| &items[0]),
        _ => None,
    }
}

/// Rewrite the conditions of `ir` so that an AND or OR whose operands are
/// detections holding one value of the same field each refers to a single
/// detection of those items, which renders as an in-list as in pySigma.
/// Selectors are expanded into explicit operands first.
fn merge_condition_lists(ir: &mut IrRule) {
    let mut merged = Vec::new();
    for cond in &mut ir.conditions {
        expand_selectors(cond, &ir.detections);
        merge_condition(cond, &ir.detections, &mut merged);
    }
    ir.detections.extend(merged);
}

fn expand_selectors(cond: &mut IrCondition, detections: &HashMap<String, IrDetection>) {
    match cond {
        IrCondition::And(exprs) | IrCondition::Or(exprs) => exprs
            .iter_mut()
            .for_each(|e| expand_selectors(e, detections)),
        IrCondition::Not(inner) => expand_selectors(inner, detections),
        IrCondition::Selector {
            quantifier,
            pattern,
        } => {
            let names = selected_detections(detections, pattern);
            if names.is_empty() {
                return;
            }
            let operands = names
                .into_iter()
                .map(|n| IrCondition::Detection(n.clone()))
                .collect();
            match quantifier {
                Quantifier::Any => *cond = IrCondition::Or(operands),
                Quantifier::Count(n) if n.get() == 1 => *cond = IrCondition::Or(operands),
                Quantifier::All => *cond = IrCondition::And(operands),
                Quantifier::Count(_) => {}
            }
        }
        IrCondition::Detection(_) => {}
    }
}

fn merge_condition(
    cond: &mut IrCondition,
    detections: &HashMap<String, IrDetection>,
    merged: &mut Vec<(String, IrDetection)>,
) {
    let all = match cond {
        IrCondition::And(_) => true,
        IrCondition::Or(_) => false,
        IrCondition::Not(inner) => return merge_condition(inner, detections, merged),
        _ => return,
    };
    let (IrCondition::And(exprs) | IrCondition::Or(exprs)) = cond else {
        return;
    };
    exprs
        .iter_mut()
        .for_each(|e| merge_condition(e, detections, merged));
    let Some(items) = exprs
        .iter()
        .map(|e| match e {
            IrCondition::Detection(name) => detections.get(name).and_then(single_list_item),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    if items.len() < 2 || items.iter().any(|i| i.field != items[0].field) {
        return;
    }
    let items = items.into_iter().cloned();
    let det = if all {
        IrDetection::AllOf(items.collect())
    } else {
        IrDetection::AnyOf(items.map(|i| IrDetection::AllOf(vec![i])).collect())
    };
    let name = (merged.len()..)
        .map(|n| format!("_rsigma_in_list_{n}"))
        .find(|n| !detections.contains_key(n))
        .expect("an unused detection name");
    merged.push((name.clone(), det));
    *cond = IrCondition::Detection(name);
}

impl TextQueryTestBackend {
    /// Render values of one field as `in` (OR, `all` false) or
    /// `contains-all` (AND) when there are several and every one is a
    /// case-insensitive string or a number.
    fn in_list<'a>(
        &self,
        field: &str,
        values: impl ExactSizeIterator<Item = &'a IrMatcher>,
        all: bool,
    ) -> Option<String> {
        let c = self.config;
        let (enabled, op) = if all {
            (c.convert_and_as_in, c.and_in_operator)
        } else {
            (c.convert_or_as_in, c.or_in_operator)
        };
        if !enabled || values.len() < 2 {
            return None;
        }
        let list = values
            .map(|m| match m {
                IrMatcher::Str {
                    op,
                    pattern,
                    case_insensitive: true,
                } => Some(quote_value(c, &full_value(*op, pattern))),
                IrMatcher::NumericEq(IrNumber::Literal(n)) => Some(n.to_string()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        Some(
            c.field_in_list_expression?
                .replace("{field}", &text_escape_and_quote_field(c, field))
                .replace("{op}", op?)
                .replace("{list}", &list.join(c.list_separator)),
        )
    }

    /// A value list of one item as an in-list.
    fn matcher_in_list(&self, field: &str, matcher: &IrMatcher) -> Option<String> {
        match matcher {
            IrMatcher::AnyOf(ms) => self.in_list(field, ms.iter(), false),
            IrMatcher::AllOf(ms) => self.in_list(field, ms.iter(), true),
            _ => None,
        }
    }

    /// A detection whose operands are single values of one field as an
    /// in-list: the items of one selection (AND), or a list of selections
    /// with one item each (OR).
    fn detection_in_list(&self, det: &IrDetection) -> Option<String> {
        let (items, all): (Vec<&IrDetectionItem>, bool) = match det {
            IrDetection::AllOf(items) => (items.iter().collect(), true),
            IrDetection::AnyOf(dets) => (
                dets.iter()
                    .map(|d| match d {
                        IrDetection::AllOf(items) if items.len() == 1 => Some(&items[0]),
                        _ => None,
                    })
                    .collect::<Option<_>>()?,
                false,
            ),
            _ => return None,
        };
        let leaves = items
            .into_iter()
            .map(list_item)
            .collect::<Option<Vec<_>>>()?;
        let field = leaves.first()?.0;
        if leaves.iter().any(|(f, _)| *f != field) {
            return None;
        }
        self.in_list(field, leaves.iter().map(|(_, m)| *m), all)
    }

    /// Convert the matcher of a field item, rendering value lists as
    /// in-lists where they qualify and every other matcher as the default
    /// item conversion does.
    fn convert_values(
        &self,
        item: &IrDetectionItem,
        field: &str,
        matcher: &IrMatcher,
        state: &mut ConversionState,
    ) -> Result<String> {
        if let Some(list) = self.matcher_in_list(field, matcher) {
            return Ok(list);
        }
        match matcher {
            IrMatcher::Not(inner) => {
                if let Some(list) = self.matcher_in_list(field, inner) {
                    return negate(self, Operand::new(list, matcher_op(inner)));
                }
            }
            IrMatcher::AnyOf(ms) | IrMatcher::AllOf(ms) => {
                let mut parts = Vec::with_capacity(ms.len());
                for m in ms {
                    let expr = self.convert_values(item, field, m, state)?;
                    if !expr.is_empty() {
                        parts.push(Operand::new(expr, matcher_op(m)));
                    }
                }
                return match parts.len() {
                    0 => Ok(String::new()),
                    1 => Ok(parts.remove(0).expr),
                    _ => join(self, matches!(matcher, IrMatcher::AllOf(_)), parts),
                };
            }
            _ => {}
        }
        let leaf = IrDetectionItem {
            field: item.field.clone(),
            matcher: matcher.clone(),
            exists: item.exists,
        };
        default_convert_ir_detection_item(self, &leaf, state)
    }
}

impl Backend for TextQueryTestBackend {
    fn name(&self) -> &str {
        "test"
    }

    fn formats(&self) -> &[(&str, &str)] {
        &[
            ("default", "plain query list"),
            ("test", "wrapped query [ {query} ]"),
            ("state", "index={state.index} ({query})"),
            ("str", "newline-joined queries"),
        ]
    }

    fn requires_pipeline(&self) -> bool {
        false
    }

    // --- Detection rule conversion ---

    fn convert_rule(
        &self,
        rule: &SigmaRule,
        output_format: &str,
        pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        // Encodings stay unexpanded until an item is converted, so their
        // variants render as an OR rather than an in-list, as in pySigma.
        let mut ir =
            rsigma_ir::lower_rule(rule, &rsigma_ir::LowerOptions::default()).map_err(ir_err)?;
        merge_condition_lists(&mut ir);
        convert_lowered_rule(self, rule, &ir, output_format, pipeline_state)
    }

    fn convert_ir_detection(
        &self,
        det: &IrDetection,
        state: &mut ConversionState,
    ) -> Result<String> {
        match det {
            IrDetection::Keywords(matcher) if has_encoded(matcher) => {
                let mut matcher = matcher.clone();
                expand_encoded_matcher(&mut matcher).map_err(ir_err)?;
                default_convert_ir_detection(self, &IrDetection::Keywords(matcher), state)
            }
            _ => match self.detection_in_list(det) {
                Some(list) => Ok(list),
                None => default_convert_ir_detection(self, det, state),
            },
        }
    }

    fn convert_ir_detection_item(
        &self,
        item: &IrDetectionItem,
        state: &mut ConversionState,
    ) -> Result<String> {
        if has_encoded(&item.matcher) {
            let mut item = item.clone();
            expand_encoded_matcher(&mut item.matcher).map_err(ir_err)?;
            return default_convert_ir_detection_item(self, &item, state);
        }
        match (item.field.as_deref(), &item.matcher) {
            (
                Some(field),
                matcher @ (IrMatcher::AnyOf(_) | IrMatcher::AllOf(_) | IrMatcher::Not(_)),
            ) => self.convert_values(item, field, matcher, state),
            _ => default_convert_ir_detection_item(self, item, state),
        }
    }

    // --- Condition combinators ---

    fn convert_condition_and(&self, exprs: &[String]) -> Result<String> {
        Ok(text_convert_condition_and(self.config, exprs))
    }

    fn convert_condition_or(&self, exprs: &[String]) -> Result<String> {
        Ok(text_convert_condition_or(self.config, exprs))
    }

    fn convert_condition_not(&self, expr: &str) -> Result<String> {
        Ok(text_convert_condition_not(self.config, expr))
    }

    fn convert_condition_group(
        &self,
        expr: &str,
        outer: TokenType,
        inner: TokenType,
    ) -> Result<String> {
        Ok(text_convert_condition_group(
            self.config,
            expr,
            outer,
            inner,
        ))
    }

    // --- Field/value escaping ---

    fn escape_and_quote_field(&self, field: &str) -> String {
        text_escape_and_quote_field(self.config, field)
    }

    // --- Value-type-specific leaves (IR-native) ---

    fn convert_field_str(
        &self,
        field: &str,
        op: IrStrOp,
        pattern: &IrPattern,
        case_insensitive: bool,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        // pySigma picks the expression from the value's shape once the
        // operator's wildcards are added, not from the operator.
        let c = self.config;
        let value = full_value(op, pattern);
        let n = value.len();
        let multi = |p: Option<&IrPatternPart>| p == Some(&IrPatternPart::WildcardMulti);
        let ci = case_insensitive;
        let (expr, value) = if multi(value.last()) && !has_wildcard(&value[..n - 1]) {
            let expr = if ci {
                c.startswith_expression
            } else {
                c.case_sensitive_startswith_expression
            };
            (expression(expr, "startswith")?, &value[..n - 1])
        } else if multi(value.first()) && !has_wildcard(&value[1..]) {
            let expr = if ci {
                c.endswith_expression
            } else {
                c.case_sensitive_endswith_expression
            };
            (expression(expr, "endswith")?, &value[1..])
        } else if n >= 2
            && multi(value.first())
            && multi(value.last())
            && !has_wildcard(&value[1..n - 1])
        {
            let expr = if ci {
                c.contains_expression
            } else {
                c.case_sensitive_contains_expression
            };
            (expression(expr, "contains")?, &value[1..n - 1])
        } else if !ci {
            (
                expression(c.case_sensitive_match_expression, "cased")?,
                &value[..],
            )
        } else if has_wildcard(&value) {
            (
                expression(c.wildcard_match_expression, "wildcard")?,
                &value[..],
            )
        } else {
            ("{field}={value}", &value[..])
        };
        Ok(ConvertResult::Query(
            expr.replace("{field}", &text_escape_and_quote_field(c, field))
                .replace("{value}", &quote_value(c, value)),
        ))
    }

    fn convert_field_eq_num(
        &self,
        field: &str,
        value: NumericLiteral,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        Ok(format!("{f}={value}"))
    }

    fn convert_field_eq_bool(
        &self,
        field: &str,
        value: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        let v = if value {
            self.config.bool_true
        } else {
            self.config.bool_false
        };
        Ok(format!("{f}={v}"))
    }

    fn convert_field_eq_null(&self, field: &str, _state: &mut ConversionState) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        Ok(self.config.field_null_expression.replace("{field}", &f))
    }

    fn convert_field_regex(
        &self,
        field: &str,
        pattern: &str,
        flags: RegexFlags,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        if flags.cased {
            return Err(ConvertError::UnsupportedModifier(
                "cased regex (re|cased); a regex is case-sensitive unless it has |i".into(),
            ));
        }
        let f = text_escape_and_quote_field(self.config, field);
        let re_val = format!(
            "{}{}",
            flags.inline_prefix(),
            text_convert_value_re(self.config, pattern)
        );
        let expr = self
            .config
            .re_expression
            .ok_or_else(|| ConvertError::UnsupportedModifier("regex".into()))?;
        Ok(ConvertResult::Query(
            expr.replace("{field}", &f).replace("{regex}", &re_val),
        ))
    }

    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let expr = self
            .config
            .cidr_expression
            .ok_or_else(|| ConvertError::UnsupportedModifier("cidr".into()))?;
        Ok(ConvertResult::Query(
            expr.replace("{field}", field).replace("{value}", cidr),
        ))
    }

    fn convert_field_compare_op(
        &self,
        field: &str,
        op: CompareOp,
        value: NumericLiteral,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        let op_name = match op {
            CompareOp::Lt => "lt",
            CompareOp::Lte => "lte",
            CompareOp::Gt => "gt",
            CompareOp::Gte => "gte",
        };
        let op_token = self
            .config
            .compare_ops
            .iter()
            .find(|(name, _)| *name == op_name)
            .map(|(_, token)| *token)
            .ok_or_else(|| ConvertError::UnsupportedModifier(op_name.into()))?;

        let expr = self
            .config
            .compare_op_expression
            .ok_or_else(|| ConvertError::UnsupportedModifier("compare".into()))?;

        let val_str = value.to_string();
        Ok(expr
            .replace("{field}", &f)
            .replace("{op}", op_token)
            .replace("{value}", &val_str))
    }

    fn convert_field_exists(
        &self,
        field: &str,
        exists: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        if exists {
            let expr = self
                .config
                .field_exists_expression
                .ok_or_else(|| ConvertError::UnsupportedModifier("exists".into()))?;
            Ok(expr.replace("{field}", &f))
        } else {
            let expr = self
                .config
                .field_not_exists_expression
                .ok_or_else(|| ConvertError::UnsupportedModifier("not exists".into()))?;
            Ok(expr.replace("{field}", &f))
        }
    }

    fn convert_field_eq_query_expr(
        &self,
        field: &str,
        expr: &str,
        _id: &str,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        Ok(format!("{f}={expr}"))
    }

    fn convert_field_ref(
        &self,
        field1: &str,
        field2: &str,
        op: IrStrOp,
        case_insensitive: bool,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        if !case_insensitive {
            return Err(ConvertError::UnsupportedModifier(
                "cased field reference (fieldref|cased)".into(),
            ));
        }
        if !matches!(op, IrStrOp::Exact) {
            let f1 = text_escape_and_quote_field(self.config, field1);
            let f2 = text_escape_and_quote_field(self.config, field2);
            let token = match op {
                IrStrOp::Contains => "contains",
                IrStrOp::StartsWith => "startswith",
                IrStrOp::EndsWith => "endswith",
                IrStrOp::Exact => unreachable!("exact handled below"),
            };
            return Ok(ConvertResult::Query(format!("{f1} {token} {f2}")));
        }
        let expr = self
            .config
            .field_eq_field_expression
            .ok_or_else(|| ConvertError::UnsupportedModifier("fieldref".into()))?;
        let f1 = text_escape_and_quote_field(self.config, field1);
        let f2 = if self.config.field_eq_field_escaping_quoting {
            text_escape_and_quote_field(self.config, field2)
        } else {
            field2.to_string()
        };
        Ok(ConvertResult::Query(
            expr.replace("{field1}", &f1).replace("{field2}", &f2),
        ))
    }

    fn convert_keyword_str(
        &self,
        pattern: &IrPattern,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let v = quote_value(self.config, &pattern.parts);
        let expr = self
            .config
            .unbound_value_str_expression
            .ok_or(ConvertError::UnsupportedKeyword)?;
        Ok(expr.replace("{value}", &v))
    }

    fn convert_keyword_num(
        &self,
        value: NumericLiteral,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let expr = self
            .config
            .unbound_value_num_expression
            .ok_or(ConvertError::UnsupportedKeyword)?;
        let s = value.to_string();
        Ok(expr.replace("{value}", &s))
    }

    // --- Query finalization ---

    fn finish_query(
        &self,
        rule: &SigmaRule,
        query: String,
        state: &ConversionState,
    ) -> Result<String> {
        Ok(text_finish_query(self.config, &query, state, rule))
    }

    fn finalize_query(
        &self,
        _rule: &SigmaRule,
        query: String,
        _index: usize,
        state: &ConversionState,
        output_format: &str,
    ) -> Result<String> {
        match output_format {
            "default" => Ok(query),
            "test" => Ok(format!("[ {query} ]")),
            "state" => {
                let index = state.get_state_str("index").unwrap_or("default_index");
                Ok(format!("index={index} ({query})"))
            }
            "str" => Ok(query),
            other => Err(ConvertError::RuleConversion(format!(
                "unknown output format: {other}"
            ))),
        }
    }

    fn finalize_output(&self, queries: Vec<String>, output_format: &str) -> Result<String> {
        match output_format {
            "str" => Ok(queries.join("\n")),
            _ => Ok(queries.join("\n")),
        }
    }
}

// =============================================================================
// MandatoryPipelineTestBackend
// =============================================================================

/// Variant that requires a pipeline (for testing the pipeline-required error path).
pub struct MandatoryPipelineTestBackend(TextQueryTestBackend);

impl MandatoryPipelineTestBackend {
    pub fn new() -> Self {
        Self(TextQueryTestBackend::new())
    }
}

impl Default for MandatoryPipelineTestBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for MandatoryPipelineTestBackend {
    fn name(&self) -> &str {
        "test_mandatory_pipeline"
    }

    fn formats(&self) -> &[(&str, &str)] {
        self.0.formats()
    }

    fn requires_pipeline(&self) -> bool {
        true
    }

    fn convert_rule(
        &self,
        rule: &SigmaRule,
        output_format: &str,
        pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        self.0.convert_rule(rule, output_format, pipeline_state)
    }

    fn convert_condition_and(&self, exprs: &[String]) -> Result<String> {
        self.0.convert_condition_and(exprs)
    }

    fn convert_condition_or(&self, exprs: &[String]) -> Result<String> {
        self.0.convert_condition_or(exprs)
    }

    fn convert_condition_not(&self, expr: &str) -> Result<String> {
        self.0.convert_condition_not(expr)
    }

    fn convert_condition_group(
        &self,
        expr: &str,
        outer: TokenType,
        inner: TokenType,
    ) -> Result<String> {
        self.0.convert_condition_group(expr, outer, inner)
    }

    fn escape_and_quote_field(&self, field: &str) -> String {
        self.0.escape_and_quote_field(field)
    }

    fn convert_field_str(
        &self,
        field: &str,
        op: IrStrOp,
        pattern: &IrPattern,
        case_insensitive: bool,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        self.0
            .convert_field_str(field, op, pattern, case_insensitive, state)
    }

    fn convert_field_eq_num(
        &self,
        field: &str,
        value: NumericLiteral,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_field_eq_num(field, value, state)
    }

    fn convert_field_eq_bool(
        &self,
        field: &str,
        value: bool,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_field_eq_bool(field, value, state)
    }

    fn convert_field_eq_null(&self, field: &str, state: &mut ConversionState) -> Result<String> {
        self.0.convert_field_eq_null(field, state)
    }

    fn convert_field_regex(
        &self,
        field: &str,
        pattern: &str,
        flags: RegexFlags,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        self.0.convert_field_regex(field, pattern, flags, state)
    }

    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        self.0.convert_field_eq_cidr(field, cidr, state)
    }

    fn convert_field_compare_op(
        &self,
        field: &str,
        op: CompareOp,
        value: NumericLiteral,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_field_compare_op(field, op, value, state)
    }

    fn convert_field_exists(
        &self,
        field: &str,
        exists: bool,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_field_exists(field, exists, state)
    }

    fn convert_field_eq_query_expr(
        &self,
        field: &str,
        expr: &str,
        id: &str,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_field_eq_query_expr(field, expr, id, state)
    }

    fn convert_field_ref(
        &self,
        field1: &str,
        field2: &str,
        op: IrStrOp,
        case_insensitive: bool,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        self.0
            .convert_field_ref(field1, field2, op, case_insensitive, state)
    }

    fn convert_keyword_str(
        &self,
        pattern: &IrPattern,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_keyword_str(pattern, state)
    }

    fn convert_keyword_num(
        &self,
        value: NumericLiteral,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_keyword_num(value, state)
    }

    fn finish_query(
        &self,
        rule: &SigmaRule,
        query: String,
        state: &ConversionState,
    ) -> Result<String> {
        self.0.finish_query(rule, query, state)
    }

    fn finalize_query(
        &self,
        rule: &SigmaRule,
        query: String,
        index: usize,
        state: &ConversionState,
        output_format: &str,
    ) -> Result<String> {
        self.0
            .finalize_query(rule, query, index, state, output_format)
    }

    fn finalize_output(&self, queries: Vec<String>, output_format: &str) -> Result<String> {
        self.0.finalize_output(queries, output_format)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::{Detection, SigmaString, SigmaValue, parse_sigma_yaml};

    fn convert_rule_yaml(yaml: &str) -> Vec<String> {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let backend = TextQueryTestBackend::new();
        let mut results = Vec::new();
        for rule in &collection.rules {
            let queries = backend
                .convert_rule(rule, "default", &PipelineState::default())
                .unwrap();
            results.extend(queries);
        }
        results
    }

    #[test]
    fn test_simple_eq() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine: whoami
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine=\"whoami\""]);
    }

    #[test]
    fn test_placeholder_in_value_stays_literal() {
        let queries = convert_rule_yaml(
            r#"
title: 'x" OR "1'
logsource:
    category: test
detection:
    selection:
        CommandLine: '{rule.title}'
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine=\"{rule.title}\""]);
    }

    #[test]
    fn test_and_condition() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        FieldB: val2
    condition: sel1 and sel2
"#,
        );
        assert_eq!(queries, vec!["FieldA=\"val1\" and FieldB=\"val2\""]);
    }

    #[test]
    fn test_or_condition() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        FieldB: val2
    condition: sel1 or sel2
"#,
        );
        assert_eq!(queries, vec!["FieldA=\"val1\" or FieldB=\"val2\""]);
    }

    #[test]
    fn test_not_condition() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    filter:
        FieldB: val2
    condition: selection and not filter
"#,
        );
        assert_eq!(queries, vec!["FieldA=\"val1\" and not FieldB=\"val2\""]);
    }

    #[test]
    fn test_contains_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine contains \"whoami\""]);
    }

    #[test]
    fn test_startswith_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|startswith: cmd
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine startswith \"cmd\""]);
    }

    #[test]
    fn test_endswith_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|endswith: '.exe'
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine endswith \".exe\""]);
    }

    #[test]
    fn test_wildcard_value() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine: '*whoami*'
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine contains \"whoami\""]);
    }

    #[test]
    fn test_numeric_value() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        EventID: 4688
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["EventID=4688"]);
    }

    #[test]
    fn test_boolean_value() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Enabled: true
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["Enabled=1"]);
    }

    #[test]
    fn test_null_value() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: null
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["FieldA is null"]);
    }

    #[test]
    fn test_exists_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA|exists: true
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["exists(FieldA)"]);
    }

    #[test]
    fn test_not_exists_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA|exists: false
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["notexists(FieldA)"]);
    }

    #[test]
    fn test_re_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|re: '.*whoami.*'
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine=/.*whoami.*/"]);
    }

    #[test]
    fn test_cidr_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        SourceIP|cidr: '10.0.0.0/8'
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["cidrmatch('SourceIP', \"10.0.0.0/8\")"]);
    }

    #[test]
    fn test_gte_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        EventCount|gte: 10
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["EventCount>=10"]);
    }

    #[test]
    fn test_multiple_values_or() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine:
            - whoami
            - ipconfig
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine in (\"whoami\", \"ipconfig\")"]);
    }

    #[test]
    fn test_multiple_values_all() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|all:
            - whoami
            - ipconfig
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec!["CommandLine contains-all (\"whoami\", \"ipconfig\")"]
        );
    }

    #[test]
    fn test_value_list_under_and_is_grouped() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Image:
            - a
            - b
        CommandLine: x
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec!["(Image in (\"a\", \"b\")) and CommandLine=\"x\""]
        );
    }

    #[test]
    fn test_not_groups_compound_operands_only() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Image: a
    filter_1:
        CommandLine: b
    filter_2:
        ParentImage: c
        User: d
    filter_3:
        User: e
    condition: selection and not 1 of filter_* and not filter_3 and not (filter_1 and not filter_3)
"#,
        );
        assert_eq!(
            queries,
            vec![
                "Image=\"a\" and not (CommandLine=\"b\" or ParentImage=\"c\" and User=\"d\" or User=\"e\") \
                 and not User=\"e\" and not (CommandLine=\"b\" and not User=\"e\")"
            ]
        );
    }

    #[test]
    fn test_and_under_or_is_bare() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    sel_1:
        Image: a
        User: b
    sel_2:
        Image: c
    condition: 1 of sel_*
"#,
        );
        assert_eq!(queries, vec!["Image=\"a\" and User=\"b\" or Image=\"c\""]);
    }

    #[test]
    fn test_escape_chars() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: 'value:with&special'
    condition: selection
"#,
        );
        // `:` should be escaped with `\`, `&` should be filtered
        assert_eq!(queries, vec!["FieldA=\"value\\:withspecial\""]);
    }

    #[test]
    fn test_output_format_test() {
        let collection = parse_sigma_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        )
        .unwrap();
        let backend = TextQueryTestBackend::new();
        let queries = backend
            .convert_rule(&collection.rules[0], "test", &PipelineState::default())
            .unwrap();
        assert_eq!(queries, vec!["[ FieldA=\"val1\" ]"]);
    }

    #[test]
    fn test_output_format_state() {
        let collection = parse_sigma_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        )
        .unwrap();
        let backend = TextQueryTestBackend::new();
        let mut ps = PipelineState::default();
        ps.set_state(
            "index".to_string(),
            serde_json::Value::String("my_index".into()),
        );
        let queries = backend
            .convert_rule(&collection.rules[0], "state", &ps)
            .unwrap();
        assert_eq!(queries, vec!["index=my_index (FieldA=\"val1\")"]);
    }

    #[test]
    fn test_mandatory_pipeline_error() {
        let collection = parse_sigma_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        )
        .unwrap();
        let backend = MandatoryPipelineTestBackend::new();
        let result = crate::convert::convert_collection(&backend, &collection, &[], "default");
        assert!(matches!(result, Err(ConvertError::PipelineRequired)));
    }

    #[test]
    fn test_multiple_detection_items_and() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
        FieldB: val2
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["FieldA=\"val1\" and FieldB=\"val2\""]);
    }

    #[test]
    fn test_keywords() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        - whoami
        - ipconfig
    condition: keywords
"#,
        );
        assert_eq!(queries, vec!["_=\"whoami\" or _=\"ipconfig\""]);
    }

    #[test]
    fn test_keywords_all_renders_one_term_per_value() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        '|all':
            - 'bash -c'
            - 4444
    condition: keywords
"#,
        );
        assert_eq!(queries, vec!["_=\"bash -c\" and _=4444"]);
    }

    #[test]
    fn test_negated_field_less_value_renders_a_negated_term() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        '|neq':
            - whoami
            - ipconfig
    condition: keywords
"#,
        );
        assert_eq!(queries, vec!["not (_=\"whoami\" or _=\"ipconfig\")"]);
    }

    #[test]
    fn test_bool_keyword_converts_as_text() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        - true
    condition: keywords
"#,
        );
        assert_eq!(queries, vec!["_=\"true\""]);
    }

    #[test]
    fn test_anchored_field_less_value_is_unsupported() {
        let err = convert_rule_yaml_err(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        '|startswith': whoami
    condition: keywords
"#,
        );
        assert!(matches!(err, ConvertError::UnsupportedKeyword));
    }

    #[test]
    fn test_case_sensitive_contains() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains|cased: Whoami
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine contains_cased \"Whoami\""]);
    }

    #[test]
    fn test_re_with_slash_escaping() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Path|re: 'C:/Windows/.*'
    condition: selection
"#,
        );
        // `:` is in add_escaped for string values, not re_escape, so it stays unescaped.
        // `/` is in re_escape, so both slashes get escaped.
        assert_eq!(queries, vec!["Path=/C:\\/Windows\\/.*/"]);
    }

    /// Convert a rule expected to fail and return the resulting error message.
    fn convert_rule_yaml_err(yaml: &str) -> ConvertError {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let backend = TextQueryTestBackend::new();
        backend
            .convert_rule(&collection.rules[0], "default", &PipelineState::default())
            .expect_err("rule should fail to convert")
    }

    /// Convert a rule whose only detection item is replaced after parsing, as a
    /// pipeline can, so the backend's own checks run on an item the parser never
    /// validated.
    fn convert_item_err(modifiers: &[&str], value: &str) -> ConvertError {
        let mut collection = parse_sigma_yaml(
            "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: x\n    condition: selection\n",
        )
        .unwrap();
        let rule = &mut collection.rules[0];
        let Some(Detection::AllOf(items)) = rule.detection.named.get_mut("selection") else {
            unreachable!("the selection is a single mapping");
        };
        items[0].field.modifiers = modifiers.iter().map(|m| m.parse().unwrap()).collect();
        items[0].values = vec![SigmaValue::String(SigmaString::new(value))];
        TextQueryTestBackend::new()
            .convert_rule(rule, "default", &PipelineState::default())
            .expect_err("rule should fail to convert")
    }

    #[test]
    fn test_neq_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|neq: forbidden
        EventID|neq: 1
        Image|fieldref|neq: ParentImage
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec!["not Field=\"forbidden\" and not EventID=1 and not Image=fieldref(ParentImage)"]
        );
    }

    #[test]
    fn test_encoding_modifiers_expand_to_plain_matches() {
        for (modifier, expected) in [
            ("base64", r#"Field="LXBheWxvYWQ=""#),
            (
                "base64offset|contains",
                r#"Field contains "LXBheWxvYW" or Field contains "1wYXlsb2Fk" or Field contains "tcGF5bG9hZ""#,
            ),
            (
                "wide|base64offset|contains",
                r#"Field contains "LQBwAGEAeQBsAG8AYQBkA" or Field contains "0AcABhAHkAbABvAGEAZA" or Field contains "tAHAAYQB5AGwAbwBhAGQA""#,
            ),
            ("utf16|base64", r#"Field="//4tAHAAYQB5AGwAbwBhAGQA""#),
            ("utf16be|base64", r#"Field="AC0AcABhAHkAbABvAGEAZA==""#),
            (
                "windash|contains",
                r#"Field contains "-payload" or Field contains "/payload" or Field contains "–payload" or Field contains "—payload" or Field contains "―payload""#,
            ),
        ] {
            let yaml = format!(
                r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|{modifier}: '-payload'
    condition: selection
"#
            );
            assert_eq!(convert_rule_yaml(&yaml), vec![expected], "{modifier}");
        }
    }

    #[test]
    fn test_encoding_expansion_keeps_or_grouped() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Image|endswith: '\x.exe'
        CommandLine|windash|contains: ' -f '
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec![
                r#"Image endswith "\x.exe" and (CommandLine contains " -f " or CommandLine contains " /f " or CommandLine contains " –f " or CommandLine contains " —f " or CommandLine contains " ―f ")"#
            ]
        );
    }

    #[test]
    fn test_negated_encoding_expansion_is_grouped() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        A: x
        Field|windash|contains|neq: ' -f '
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec![
                r#"A="x" and not (Field contains " -f " or Field contains " /f " or Field contains " –f " or Field contains " —f " or Field contains " ―f ")"#
            ]
        );
    }

    #[test]
    fn test_encoding_wildcard_with_base64_is_rejected() {
        let err = convert_item_err(&["base64offset", "contains"], "pay*load");
        assert!(
            matches!(&err, ConvertError::UnsupportedValue(_)),
            "got: {err}"
        );
    }

    #[test]
    fn test_values_pysigma_rejects_fail_conversion() {
        for (modifiers, value, expected) in [
            (&["cidr"][..], "10.1.2.3/8", "host bits set"),
            (&["gt"][..], "abc", "abc"),
            (&["fieldref", "cased"][..], "B", "fieldref|cased"),
        ] {
            let err = convert_item_err(modifiers, value);
            assert!(err.to_string().contains(expected), "{modifiers:?}: {err}");
        }
    }

    #[test]
    fn test_unresolved_expand_is_rejected() {
        let err = convert_rule_yaml_err(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|expand: '%admin_users%'
    condition: selection
"#,
        );
        assert!(err.to_string().contains("%admin_users%"), "got: {err}");
    }

    #[test]
    fn test_default_path_rejects_timestamp_part_modifiers() {
        for modifier in ["minute", "hour", "day", "week", "month", "year"] {
            let yaml = format!(
                r#"
title: Test
logsource:
    category: test
detection:
    selection:
        TimeField|{modifier}: 5
    condition: selection
"#
            );
            let err = convert_rule_yaml_err(&yaml);
            assert!(
                matches!(&err, ConvertError::UnsupportedModifier(_)),
                "expected UnsupportedModifier for `{modifier}`, got: {err}",
            );
        }
    }

    #[test]
    fn test_regex_flags_render_inline() {
        for (modifiers, expected) in [
            ("re", "F=/ab.c/"),
            ("re|i", "F=/(?i)ab.c/"),
            ("re|m", "F=/(?m)ab.c/"),
            ("re|s", "F=/(?s)ab.c/"),
            ("re|i|m|s", "F=/(?ims)ab.c/"),
        ] {
            let yaml = format!(
                "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        F|{modifiers}: 'ab.c'\n    condition: selection\n"
            );
            assert_eq!(convert_rule_yaml(&yaml), vec![expected], "{modifiers}");
        }
    }

    #[test]
    fn test_cased_regex_is_rejected_on_a_rewritten_item() {
        let err = convert_item_err(&["re", "cased"], "ab.c");
        assert!(err.to_string().contains("got |re, |cased"), "{err}");
    }

    #[test]
    fn test_default_path_rejects_regex_flag_without_re() {
        // `m` (multiline) and `s` (dotall) only have meaning alongside `re`;
        // outside that branch they would be silently dropped.
        for modifier in ["m", "s"] {
            let err = convert_item_err(&[modifier], "anything");
            assert!(
                matches!(&err, ConvertError::UnsupportedModifier(_)),
                "expected UnsupportedModifier for `{modifier}`, got: {err}",
            );
        }
    }

    #[test]
    fn renders_like_pysigma_text_query_test_backend() {
        let cases = [
            ("A|endswith: 'x?y'", r#"A match "*x?y""#),
            (r"A: 'a\*b'", r#"A="a\*b""#),
            (r#"A|contains: 'a"b:c'"#, r#"A contains "a\"b\:c""#),
            ("A: 'x&y'", r#"A="xy""#),
            ("A: '*'", r#"A startswith """#),
            ("A: ''", r#"A="""#),
            (
                r"A|startswith: 'C:\Windows\'",
                r#"A startswith "C\:\Windows\""#,
            ),
            ("A|startswith: 'net*user'", r#"A match "net*user*""#),
            ("A|neq: ['x', 'y']", r#"not (A in ("x", "y"))"#),
            ("A: [1, 2]", "A in (1, 2)"),
            ("A|contains: ['a*b', 'c']", r#"A in ("*a*b*", "*c*")"#),
            (
                "A|contains|all: ['x', 'y']",
                r#"A contains-all ("*x*", "*y*")"#,
            ),
            ("A|cidr: '10.0.0.0/8'", r#"cidrmatch('A', "10.0.0.0/8")"#),
            (r"A|re: 'a\sb/c'", r"A=/a\\sb\/c/"),
            (
                "A|base64offset|contains: 'abc'",
                r#"A contains "YWJj" or A contains "FiY" or A contains "hYm""#,
            ),
        ];
        for (item, expected) in cases {
            let yaml = format!(
                "title: t\nlogsource:\n    category: test\ndetection:\n    sel:\n        {item}\n    condition: sel\n"
            );
            assert_eq!(convert_rule_yaml(&yaml), vec![expected], "for `{item}`");
        }
    }

    #[test]
    fn same_field_items_of_a_selection_render_as_contains_all() {
        let queries = convert_rule_yaml(
            r#"
title: t
logsource:
    category: test
detection:
    sel:
        A|endswith: x
        A|contains: y
    condition: sel
"#,
        );
        assert_eq!(queries, vec![r#"A contains-all ("*x", "*y*")"#]);
    }

    #[test]
    fn same_field_selections_in_a_condition_render_as_an_in_list() {
        let queries = convert_rule_yaml(
            r#"
title: t
logsource:
    category: test
detection:
    sel1:
        A: x
    sel2:
        A: 'y*'
    list:
        - A: x
        - A: 5
    condition: (sel1 or sel2) and not list
"#,
        );
        assert_eq!(
            queries,
            vec![r#"(A in ("x", "y*")) and not (A in ("x", 5))"#]
        );
    }

    #[test]
    fn selectors_never_match_merged_in_lists() {
        let queries = convert_rule_yaml(
            r#"
title: t
logsource:
    category: test
detection:
    sel1:
        A: x
    sel2:
        A: y
    _hidden:
        B: z
    condition: (sel1 or sel2) and 1 of _*
"#,
        );
        assert_eq!(queries, vec![r#"(A in ("x", "y")) and B="z""#]);
    }

    #[test]
    fn cased_values_stay_out_of_in_lists() {
        let queries = convert_rule_yaml(
            r#"
title: t
logsource:
    category: test
detection:
    sel:
        A|cased: ['Ab', 'c*']
    condition: sel
"#,
        );
        assert_eq!(
            queries,
            vec![r#"A casematch "Ab" or A startswith_cased "c""#]
        );
    }

    #[test]
    fn test_default_path_keeps_safe_modifiers_working() {
        // Sanity check: modifiers that ARE supported by the generic
        // dispatch (`contains`, `startswith`, `endswith`, `cased`, `i`)
        // still produce a query, so the new gate does not over-reject.
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#,
        );
        assert_eq!(queries.len(), 1);
    }
}
