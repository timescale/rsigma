//! LynxDB conversion backend.
//!
//! Generates [LynxDB](https://github.com/lynxbase/lynxdb) SPL2-compatible
//! search queries from Sigma rules. LynxDB is a Go-based log analytics engine
//! whose search syntax is close to Splunk SPL2 but with notable differences:
//!
//! - Boolean precedence: `NOT` > `OR` > `AND` (OR binds tighter than AND).
//! - Only `*` wildcard; no single-character `?` wildcard.
//! - Regex via `=~` / `!~` in `where` clauses (not in `search` predicates).
//! - CIDR via `cidrmatch("cidr", field)` in `where` clauses.
//! - Case-sensitive matching via `CASE(value)` wrapper.
//! - Default matching is case-insensitive.

use std::collections::HashMap;

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_parser::*;

use crate::backend::*;
use crate::condition::convert_condition_expr;
use crate::convert::{default_convert_detection, default_convert_detection_item};
use crate::error::{ConvertError, Result};
use crate::state::{ConversionState, ConvertResult, DeferredTextExpression};

// =============================================================================
// LynxDB config
// =============================================================================

static LYNXDB_CONFIG: TextQueryConfig = TextQueryConfig {
    // LynxDB binds NOT tightest, then OR, then AND loosest.
    precedence: (TokenType::NOT, TokenType::OR, TokenType::AND),
    group_expression: "({expr})",
    token_separator: " ",

    and_token: "AND",
    or_token: "OR",
    not_token: "NOT",
    eq_token: "=",

    not_eq_token: Some("!="),
    eq_expression: None,
    not_eq_expression: None,
    convert_not_as_not_eq: false,

    // LynxDB only supports `*` glob; `?` is a literal character.
    // Sigma's single-char wildcard is mapped to `*` here (lossy fallback);
    // patterns that actually contain `?` are deferred to a regex `where` clause
    // in `convert_field_eq_str`.
    wildcard_multi: "*",
    wildcard_single: "*",

    str_quote: "\"",
    str_quote_pattern: None,
    str_quote_pattern_negation: false,
    escape_char: "\\",
    add_escaped: &[],
    filter_chars: &[],

    // LynxDB field names are bare identifiers; no quoting needed.
    field_quote: None,
    field_quote_pattern: None,
    field_quote_pattern_negation: false,
    field_escape: None,
    field_escape_pattern: None,

    // LynxDB search predicates use glob `*` for contains/startswith/endswith.
    startswith_expression: Some("{field}={value}*"),
    not_startswith_expression: None,
    startswith_expression_allow_special: false,
    endswith_expression: Some("{field}=*{value}"),
    not_endswith_expression: None,
    endswith_expression_allow_special: false,
    contains_expression: Some("{field}=*{value}*"),
    not_contains_expression: None,
    contains_expression_allow_special: false,
    wildcard_match_expression: None,

    case_sensitive_match_expression: Some("{field}=CASE({value})"),
    case_sensitive_startswith_expression: None,
    case_sensitive_endswith_expression: None,
    case_sensitive_contains_expression: None,

    // Regex and CIDR are handled as deferred `where` clauses, not inline.
    re_expression: None,
    not_re_expression: None,
    re_escape_char: Some("\\"),
    re_escape: &[],
    re_escape_escape_char: None,

    cidr_expression: None,
    not_cidr_expression: None,

    field_null_expression: "NOT {field}=*",
    field_exists_expression: Some("{field}=*"),
    field_not_exists_expression: Some("NOT {field}=*"),

    compare_op_expression: Some("{field}{op}{value}"),
    compare_ops: &[("lt", "<"), ("lte", "<="), ("gt", ">"), ("gte", ">=")],

    convert_or_as_in: true,
    convert_and_as_in: false,
    in_expressions_allow_wildcards: false,
    field_in_list_expression: Some("{field} IN ({list})"),
    or_in_operator: Some("IN"),
    and_in_operator: None,
    list_separator: ", ",

    unbound_value_str_expression: Some("{value}"),
    unbound_value_num_expression: Some("{value}"),
    unbound_value_re_expression: None,

    field_eq_field_expression: None,
    field_eq_field_escaping_quoting: false,

    deferred_start: Some(" | where "),
    deferred_separator: Some(" | where "),
    deferred_only_query: "*",

    bool_true: "true",
    bool_false: "false",

    query_expression: "FROM {index} | search {query}",
    state_defaults: &[("index", "main")],
};

// =============================================================================
// LynxDbBackend
// =============================================================================

pub struct LynxDbBackend {
    config: &'static TextQueryConfig,
}

impl LynxDbBackend {
    pub fn new() -> Self {
        Self {
            config: &LYNXDB_CONFIG,
        }
    }
}

impl Default for LynxDbBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for LynxDbBackend {
    fn name(&self) -> &str {
        "lynxdb"
    }

    fn formats(&self) -> &[(&str, &str)] {
        &[
            ("default", "full query: FROM <index> | search ..."),
            ("minimal", "search expression only (no FROM prefix)"),
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
        let mut queries = Vec::new();
        for (idx, cond_expr) in rule.detection.conditions.iter().enumerate() {
            let mut state = ConversionState::new(pipeline_state.state.clone());
            let query = self.convert_condition(cond_expr, &rule.detection.named, &mut state)?;
            let finished = self.finish_query(rule, query, &state)?;
            let finalized = self.finalize_query(rule, finished, idx, &state, output_format)?;
            queries.push(finalized);
        }
        Ok(queries)
    }

    // --- Condition tree dispatch ---

    fn convert_condition(
        &self,
        expr: &ConditionExpr,
        detections: &HashMap<String, Detection>,
        state: &mut ConversionState,
    ) -> Result<String> {
        convert_condition_expr(self, expr, detections, state)
    }

    fn convert_condition_and(&self, exprs: &[String]) -> Result<String> {
        let non_empty: Vec<String> = exprs.iter().filter(|s| !s.is_empty()).cloned().collect();
        if non_empty.is_empty() {
            return Ok(String::new());
        }
        let joined = text_convert_condition_and(self.config, &non_empty);
        // AND binds loosest in LynxDB (unusual: NOT > OR > AND), so we must
        // parenthesize AND groups to preserve Sigma's standard semantics when
        // an AND is nested inside an OR.
        if non_empty.len() > 1 {
            Ok(format!("({joined})"))
        } else {
            Ok(joined)
        }
    }

    fn convert_condition_or(&self, exprs: &[String]) -> Result<String> {
        let non_empty: Vec<String> = exprs.iter().filter(|s| !s.is_empty()).cloned().collect();
        if non_empty.is_empty() {
            return Ok(String::new());
        }
        Ok(text_convert_condition_or(self.config, &non_empty))
    }

    fn convert_condition_not(&self, expr: &str) -> Result<String> {
        Ok(text_convert_condition_not(self.config, expr))
    }

    // --- Detection ---

    fn convert_detection(&self, det: &Detection, state: &mut ConversionState) -> Result<String> {
        default_convert_detection(self, det, state)
    }

    fn convert_detection_item(
        &self,
        item: &DetectionItem,
        state: &mut ConversionState,
    ) -> Result<String> {
        default_convert_detection_item(self, item, state)
    }

    // --- Field/value escaping ---

    fn escape_and_quote_field(&self, field: &str) -> String {
        text_escape_and_quote_field(self.config, field)
    }

    fn convert_value_str(&self, value: &SigmaString, _state: &ConversionState) -> String {
        text_convert_value_str(self.config, value)
    }

    fn convert_value_re(&self, regex: &str, _state: &ConversionState) -> String {
        text_convert_value_re(self.config, regex)
    }

    // --- Value-type-specific methods ---

    fn convert_field_eq_str(
        &self,
        field: &str,
        value: &SigmaString,
        modifiers: &[Modifier],
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        text_convert_field_eq_str(self.config, field, value, modifiers, state)
    }

    fn convert_field_eq_str_case_sensitive(
        &self,
        field: &str,
        value: &SigmaString,
        modifiers: &[Modifier],
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let mut mods = modifiers.to_vec();
        if !mods.contains(&Modifier::Cased) {
            mods.push(Modifier::Cased);
        }
        text_convert_field_eq_str(self.config, field, value, &mods, state)
    }

    fn convert_field_eq_num(
        &self,
        field: &str,
        value: f64,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        if value.fract() == 0.0 {
            Ok(format!("{f}={}", value as i64))
        } else {
            Ok(format!("{f}={value}"))
        }
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

    fn convert_field_eq_re(
        &self,
        field: &str,
        pattern: &str,
        _flags: &[Modifier],
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f = text_escape_and_quote_field(self.config, field);
        let re_val = text_convert_value_re(self.config, pattern);
        Ok(ConvertResult::Deferred(Box::new(DeferredTextExpression {
            template: "{field} {op} \"{value}\"".to_string(),
            field: f,
            value: re_val,
            negated: false,
            operators: ("=~", "!~"),
        })))
    }

    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f = text_escape_and_quote_field(self.config, field);
        Ok(ConvertResult::Deferred(Box::new(DeferredTextExpression {
            template: "{op}cidrmatch(\"{value}\", {field})".to_string(),
            field: f,
            value: cidr.to_string(),
            negated: false,
            operators: ("", "NOT "),
        })))
    }

    fn convert_field_compare(
        &self,
        field: &str,
        op: &Modifier,
        value: f64,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        let op_name = match op {
            Modifier::Lt => "lt",
            Modifier::Lte => "lte",
            Modifier::Gt => "gt",
            Modifier::Gte => "gte",
            _ => {
                return Err(ConvertError::UnsupportedModifier(format!(
                    "compare op {:?}",
                    op
                )));
            }
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

        let val_str = if value.fract() == 0.0 {
            (value as i64).to_string()
        } else {
            value.to_string()
        };
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
        _field1: &str,
        _field2: &str,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        Err(ConvertError::UnsupportedModifier(
            "field-to-field comparison not supported by LynxDB backend".into(),
        ))
    }

    fn convert_keyword(&self, value: &SigmaValue, _state: &mut ConversionState) -> Result<String> {
        match value {
            SigmaValue::String(s) => {
                let v = text_convert_value_str(self.config, s);
                let expr = self
                    .config
                    .unbound_value_str_expression
                    .ok_or(ConvertError::UnsupportedKeyword)?;
                Ok(expr.replace("{value}", &v))
            }
            SigmaValue::Integer(n) => {
                let expr = self
                    .config
                    .unbound_value_num_expression
                    .ok_or(ConvertError::UnsupportedKeyword)?;
                Ok(expr.replace("{value}", &n.to_string()))
            }
            SigmaValue::Float(f) => {
                let expr = self
                    .config
                    .unbound_value_num_expression
                    .ok_or(ConvertError::UnsupportedKeyword)?;
                Ok(expr.replace("{value}", &f.to_string()))
            }
            _ => Err(ConvertError::UnsupportedKeyword),
        }
    }

    fn convert_condition_as_in_expression(
        &self,
        field: &str,
        values: &[&SigmaValue],
        is_or: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        if !is_or {
            return Err(ConvertError::UnsupportedModifier(
                "AND-in not supported by LynxDB backend".into(),
            ));
        }
        let f = text_escape_and_quote_field(self.config, field);
        let expr = self
            .config
            .field_in_list_expression
            .ok_or_else(|| ConvertError::UnsupportedModifier("in-list".into()))?;

        let items: Vec<String> = values
            .iter()
            .map(|v| match v {
                SigmaValue::String(s) => text_convert_value_str(self.config, s),
                SigmaValue::Integer(n) => n.to_string(),
                SigmaValue::Float(f) => f.to_string(),
                _ => String::new(),
            })
            .collect();

        let list = items.join(self.config.list_separator);
        Ok(expr.replace("{field}", &f).replace("{list}", &list))
    }

    // --- Query finalization ---

    fn finish_query(
        &self,
        rule: &SigmaRule,
        query: String,
        state: &ConversionState,
    ) -> Result<String> {
        // Custom finish_query: apply processing state BEFORE defaults so that
        // pipeline-provided values (e.g. `index`) override the default ("main").
        // The generic `text_finish_query` applies defaults first, which prevents
        // state values from overriding them.
        let main_query = if state.has_deferred() && query.is_empty() {
            self.config.deferred_only_query
        } else {
            &query
        };

        let mut result = self.config.query_expression.replace("{query}", main_query);

        // Processing state first (pipeline-provided values take precedence)
        for (key, val) in &state.processing_state {
            if let Some(s) = val.as_str() {
                let placeholder = format!("{{{key}}}");
                result = result.replace(&placeholder, s);
            }
        }
        // Then defaults for anything not yet substituted
        for (key, default) in self.config.state_defaults {
            let placeholder = format!("{{{key}}}");
            result = result.replace(&placeholder, default);
        }

        // Rule metadata
        result = result.replace("{rule.title}", &rule.title);
        if let Some(id) = &rule.id {
            result = result.replace("{rule.id}", id);
        }

        // Append deferred parts
        if state.has_deferred() {
            let deferred_start = self.config.deferred_start.unwrap_or("");
            let deferred_sep = self.config.deferred_separator.unwrap_or("");
            let parts: Vec<String> = state.deferred.iter().map(|d| d.finalize()).collect();
            result = format!("{result}{deferred_start}{}", parts.join(deferred_sep));
        }

        Ok(result)
    }

    fn finalize_query(
        &self,
        _rule: &SigmaRule,
        query: String,
        _index: usize,
        _state: &ConversionState,
        output_format: &str,
    ) -> Result<String> {
        match output_format {
            "default" => Ok(query),
            "minimal" => {
                if let Some(rest) = query.strip_prefix("FROM ")
                    && let Some(pos) = rest.find("| search ")
                {
                    return Ok(rest[pos + "| search ".len()..].to_string());
                }
                Ok(query)
            }
            other => Err(ConvertError::RuleConversion(format!(
                "unknown output format: {other}"
            ))),
        }
    }

    fn finalize_output(&self, queries: Vec<String>, _output_format: &str) -> Result<String> {
        Ok(queries.join("\n"))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::parse_sigma_yaml;

    fn convert(yaml: &str) -> Vec<String> {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let backend = LynxDbBackend::new();
        let mut results = Vec::new();
        for rule in &collection.rules {
            let queries = backend
                .convert_rule(rule, "default", &PipelineState::default())
                .unwrap();
            results.extend(queries);
        }
        results
    }

    fn convert_minimal(yaml: &str) -> Vec<String> {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let backend = LynxDbBackend::new();
        let mut results = Vec::new();
        for rule in &collection.rules {
            let queries = backend
                .convert_rule(rule, "minimal", &PipelineState::default())
                .unwrap();
            results.extend(queries);
        }
        results
    }

    fn convert_with_state(yaml: &str, state: PipelineState) -> Vec<String> {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let backend = LynxDbBackend::new();
        let mut results = Vec::new();
        for rule in &collection.rules {
            let queries = backend.convert_rule(rule, "default", &state).unwrap();
            results.extend(queries);
        }
        results
    }

    // --- Basic field equality ---

    #[test]
    fn field_eq_string() {
        let q = convert(
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
        assert_eq!(q, vec!["FROM main | search CommandLine=\"whoami\""]);
    }

    #[test]
    fn field_eq_numeric() {
        let q = convert(
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
        assert_eq!(q, vec!["FROM main | search EventID=4688"]);
    }

    #[test]
    fn field_eq_boolean() {
        let q = convert(
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
        assert_eq!(q, vec!["FROM main | search Enabled=true"]);
    }

    #[test]
    fn field_eq_null() {
        let q = convert(
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
        assert_eq!(q, vec!["FROM main | search NOT FieldA=*"]);
    }

    // --- Wildcards ---

    #[test]
    fn wildcard_contains() {
        let q = convert(
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
        assert_eq!(q, vec!["FROM main | search CommandLine=*whoami*"]);
    }

    #[test]
    fn wildcard_startswith_modifier() {
        let q = convert(
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
        // startswith generates a trailing wildcard
        assert_eq!(q, vec!["FROM main | search CommandLine=\"cmd\"*"]);
    }

    #[test]
    fn wildcard_endswith_modifier() {
        let q = convert(
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
        assert_eq!(q, vec!["FROM main | search CommandLine=*\".exe\""]);
    }

    #[test]
    fn wildcard_contains_modifier() {
        let q = convert(
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
        assert_eq!(q, vec!["FROM main | search CommandLine=*\"whoami\"*"]);
    }

    // --- Boolean logic ---

    #[test]
    fn condition_and() {
        let q = convert(
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
        assert_eq!(
            q,
            vec!["FROM main | search (FieldA=\"val1\" AND FieldB=\"val2\")"]
        );
    }

    #[test]
    fn condition_or() {
        let q = convert(
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
        assert_eq!(
            q,
            vec!["FROM main | search FieldA=\"val1\" OR FieldB=\"val2\""]
        );
    }

    #[test]
    fn condition_not() {
        let q = convert(
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
        assert_eq!(
            q,
            vec!["FROM main | search (FieldA=\"val1\" AND NOT FieldB=\"val2\")"]
        );
    }

    #[test]
    fn condition_grouping_and_inside_or() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        FieldB: val2
    sel3:
        FieldC: val3
    condition: (sel1 and sel2) or sel3
"#,
        );
        // LynxDB's OR binds tighter than AND, so (sel1 AND sel2) needs parens
        assert_eq!(
            q,
            vec!["FROM main | search (FieldA=\"val1\" AND FieldB=\"val2\") OR FieldC=\"val3\""]
        );
    }

    // --- Multiple values ---

    #[test]
    fn multiple_values_or() {
        let q = convert(
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
        assert_eq!(
            q,
            vec!["FROM main | search CommandLine=\"whoami\" OR CommandLine=\"ipconfig\""]
        );
    }

    #[test]
    fn multiple_values_all() {
        let q = convert(
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
            q,
            vec!["FROM main | search (CommandLine=\"whoami\" AND CommandLine=\"ipconfig\")"]
        );
    }

    #[test]
    fn multiple_fields_in_detection() {
        let q = convert(
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
        assert_eq!(
            q,
            vec!["FROM main | search (FieldA=\"val1\" AND FieldB=\"val2\")"]
        );
    }

    // --- Numeric comparisons ---

    #[test]
    fn compare_gte() {
        let q = convert(
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
        assert_eq!(q, vec!["FROM main | search EventCount>=10"]);
    }

    #[test]
    fn compare_lt() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Duration|lt: 5
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FROM main | search Duration<5"]);
    }

    // --- Regex (deferred where clause) ---

    #[test]
    fn regex_modifier() {
        let q = convert(
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
        assert_eq!(
            q,
            vec!["FROM main | search * | where CommandLine =~ \".*whoami.*\""]
        );
    }

    // --- CIDR (deferred where clause) ---

    #[test]
    fn cidr_modifier() {
        let q = convert(
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
        assert_eq!(
            q,
            vec!["FROM main | search * | where cidrmatch(\"10.0.0.0/8\", SourceIP)"]
        );
    }

    // --- Field existence ---

    #[test]
    fn field_exists() {
        let q = convert(
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
        assert_eq!(q, vec!["FROM main | search FieldA=*"]);
    }

    #[test]
    fn field_not_exists() {
        let q = convert(
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
        assert_eq!(q, vec!["FROM main | search NOT FieldA=*"]);
    }

    // --- Keywords (full-text search) ---

    #[test]
    fn keyword_search() {
        let q = convert(
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
        assert_eq!(q, vec!["FROM main | search \"whoami\" OR \"ipconfig\""]);
    }

    // --- Case-sensitive matching ---

    #[test]
    fn case_sensitive_eq() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|cased: Whoami
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FROM main | search CommandLine=CASE(\"Whoami\")"]);
    }

    // --- Index from pipeline state ---

    #[test]
    fn custom_index_from_state() {
        let mut ps = PipelineState::default();
        ps.set_state(
            "index".to_string(),
            serde_json::Value::String("security_logs".into()),
        );
        let q = convert_with_state(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
            ps,
        );
        assert_eq!(q, vec!["FROM security_logs | search FieldA=\"val1\""]);
    }

    // --- Output formats ---

    #[test]
    fn minimal_format() {
        let q = convert_minimal(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FieldA=\"val1\""]);
    }

    // --- Multiple conditions ---

    #[test]
    fn multiple_conditions() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        FieldB: val2
    condition:
        - sel1
        - sel2
"#,
        );
        assert_eq!(
            q,
            vec![
                "FROM main | search FieldA=\"val1\"",
                "FROM main | search FieldB=\"val2\"",
            ]
        );
    }

    // --- Mixed regex and normal fields ---

    #[test]
    fn regex_with_normal_fields() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        status: 500
        Path|re: '/api/.*'
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | search status=500 | where Path =~ \"/api/.*\""]
        );
    }
}
