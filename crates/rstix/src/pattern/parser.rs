//! Hand-written recursive-descent parser for STIX patterns (STIX Specification §9).

use crate::pattern::ast::{
    Comparison, ComparisonOp, ComparisonTree, Duration, ObjectPath, ObservationExpr, PathStep,
    PatternAst, PatternConstant, PatternScoType, Span, TimeUnit,
};
use crate::pattern::error::PatternError;
use crate::pattern::lexer::{
    MAX_AST_DEPTH, MAX_COMPARISONS_PER_OBSERVATION, MAX_OBSERVATIONS, SpannedToken, Token, lex,
};

/// Parse a full STIX pattern (Levels 1–3 grammar).
pub fn parse(source: &str) -> Result<PatternAst, PatternError> {
    let tokens = lex(source)?;
    let mut parser = Parser::new(&tokens);
    let ast = parser.parse_pattern_expression()?;
    parser.expect_eof()?;
    let count = ast.observation_count();
    if count > MAX_OBSERVATIONS {
        return Err(PatternError::ParseError {
            pos: 0,
            msg: format!("pattern contains {count} observations; maximum is {MAX_OBSERVATIONS}"),
        });
    }
    Ok(ast)
}

/// Parse a Level-1 STIX pattern (single observation expression).
pub fn parse_level1(source: &str) -> Result<PatternAst, PatternError> {
    let tokens = lex(source)?;
    let mut parser = Parser::new(&tokens);
    let obs = parser.parse_bracketed_observation()?;
    parser.expect_eof()?;
    Ok(PatternAst::Observation(obs))
}

struct Parser<'a> {
    tokens: &'a [SpannedToken],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [SpannedToken]) -> Self {
        Self {
            tokens,
            pos: 0,
            depth: 0,
        }
    }

    fn current(&self) -> &SpannedToken {
        &self.tokens[self.pos]
    }

    fn peek(&self) -> &Token {
        &self.current().token
    }

    fn bump(&mut self) {
        if !matches!(self.peek(), Token::Eof) {
            self.pos += 1;
        }
    }

    fn expect_eof(&mut self) -> Result<(), PatternError> {
        if matches!(self.peek(), Token::Eof) {
            Ok(())
        } else {
            Err(parse_error(
                self.current().start,
                format!("expected end of input, found {:?}", self.peek()),
            ))
        }
    }

    fn with_depth<F, T>(&mut self, f: F) -> Result<T, PatternError>
    where
        F: FnOnce(&mut Self) -> Result<T, PatternError>,
    {
        if self.depth >= MAX_AST_DEPTH {
            return Err(PatternError::DepthExceeded {
                pos: self.current().start,
                max: MAX_AST_DEPTH,
            });
        }
        self.depth += 1;
        let result = f(self);
        self.depth -= 1;
        result
    }

    /// Top-level pattern (STIXPattern.g4 `observationExpressions`).
    fn parse_pattern_expression(&mut self) -> Result<PatternAst, PatternError> {
        self.with_depth(|p| p.parse_observation_expressions())
    }

    /// `observationExpressions` — FOLLOWEDBY is the loosest operator.
    fn parse_observation_expressions(&mut self) -> Result<PatternAst, PatternError> {
        let mut left = self.parse_observation_expression_or()?;
        while matches!(self.peek(), Token::FollowedBy) {
            let op_start = self.current().start;
            self.bump();
            let right = self.parse_observation_expression_or()?;
            let span = Span {
                start: op_start,
                end: self.tokens[self.pos.saturating_sub(1)].end,
            };
            left = PatternAst::FollowedBy {
                left: Box::new(left),
                right: Box::new(right),
                span,
            };
        }
        Ok(left)
    }

    /// `observationExpressionOr` — OR binds tighter than FOLLOWEDBY.
    fn parse_observation_expression_or(&mut self) -> Result<PatternAst, PatternError> {
        let mut left = self.parse_observation_expression_and()?;
        while matches!(self.peek(), Token::Or) {
            let op_start = self.current().start;
            self.bump();
            let right = self.parse_observation_expression_and()?;
            let span = Span {
                start: op_start,
                end: self.tokens[self.pos.saturating_sub(1)].end,
            };
            left = PatternAst::Or {
                left: Box::new(left),
                right: Box::new(right),
                span,
            };
        }
        Ok(left)
    }

    /// `observationExpressionAnd` — AND binds tighter than OR.
    fn parse_observation_expression_and(&mut self) -> Result<PatternAst, PatternError> {
        let mut left = self.parse_observation_expression()?;
        while matches!(self.peek(), Token::And) {
            let op_start = self.current().start;
            self.bump();
            let right = self.parse_observation_expression()?;
            let span = Span {
                start: op_start,
                end: self.tokens[self.pos.saturating_sub(1)].end,
            };
            left = PatternAst::And {
                left: Box::new(left),
                right: Box::new(right),
                span,
            };
        }
        Ok(left)
    }

    /// One observation expression with optional postfix qualifiers (WITHIN / REPEATS / START-STOP).
    fn parse_observation_expression(&mut self) -> Result<PatternAst, PatternError> {
        let mut node = self.parse_observation_primary()?;
        loop {
            match self.peek() {
                Token::Within => {
                    let op_start = self.current().start;
                    self.bump();
                    let duration = self.parse_duration()?;
                    let span = Span {
                        start: op_start,
                        end: self.tokens[self.pos.saturating_sub(1)].end,
                    };
                    node = PatternAst::Within {
                        inner: Box::new(node),
                        duration,
                        span,
                    };
                }
                Token::Repeats => {
                    let op_start = self.current().start;
                    self.bump();
                    let count = self.parse_repeat_count()?;
                    self.expect(&Token::Times)?;
                    let span = Span {
                        start: op_start,
                        end: self.tokens[self.pos.saturating_sub(1)].end,
                    };
                    node = PatternAst::Repeats {
                        inner: Box::new(node),
                        count,
                        span,
                    };
                }
                Token::Start => {
                    let op_start = self.current().start;
                    self.bump();
                    let start_ts = self.expect_timestamp()?;
                    self.expect(&Token::Stop)?;
                    let stop_ts = self.expect_timestamp()?;
                    let span = Span {
                        start: op_start,
                        end: self.tokens[self.pos.saturating_sub(1)].end,
                    };
                    node = PatternAst::StartStop {
                        inner: Box::new(node),
                        start: start_ts,
                        stop: stop_ts,
                        span,
                    };
                }
                _ => break,
            }
        }
        Ok(node)
    }

    fn parse_observation_primary(&mut self) -> Result<PatternAst, PatternError> {
        if matches!(self.peek(), Token::LBracket) {
            let obs = self.with_depth(|p| p.parse_bracketed_observation())?;
            return Ok(PatternAst::Observation(obs));
        }
        if matches!(self.peek(), Token::LParen) {
            self.bump();
            let inner = self.with_depth(|p| p.parse_observation_expressions())?;
            self.expect(&Token::RParen)?;
            return Ok(inner);
        }
        Err(parse_error(
            self.current().start,
            "expected observation expression or '('",
        ))
    }

    fn parse_duration(&mut self) -> Result<Duration, PatternError> {
        let value = match self.peek() {
            Token::IntLit(n) => {
                let v = *n as f64;
                self.bump();
                v
            }
            Token::FloatLit(f) => {
                let v = *f;
                self.bump();
                v
            }
            other => {
                return Err(parse_error(
                    self.current().start,
                    format!("expected duration number, found {other:?}"),
                ));
            }
        };
        let unit = match self.peek() {
            Token::Seconds => TimeUnit::Seconds,
            Token::Minutes => TimeUnit::Minutes,
            Token::Hours => TimeUnit::Hours,
            Token::Days => TimeUnit::Days,
            Token::Months => TimeUnit::Months,
            Token::Years => TimeUnit::Years,
            other => {
                return Err(parse_error(
                    self.current().start,
                    format!("expected time unit, found {other:?}"),
                ));
            }
        };
        self.bump();
        Ok(Duration { value, unit })
    }

    fn parse_repeat_count(&mut self) -> Result<u32, PatternError> {
        match self.peek() {
            Token::IntLit(n) if *n >= 0 => {
                let count = *n as u32;
                self.bump();
                Ok(count)
            }
            other => Err(parse_error(
                self.current().start,
                format!("expected repeat count, found {other:?}"),
            )),
        }
    }

    fn expect_timestamp(&mut self) -> Result<crate::core::StixTimestamp, PatternError> {
        match self.peek() {
            Token::TimestampLit(ts) => {
                let ts = ts.clone();
                self.bump();
                Ok(ts)
            }
            other => Err(parse_error(
                self.current().start,
                format!("expected timestamp literal, found {other:?}"),
            )),
        }
    }

    fn parse_bracketed_observation(&mut self) -> Result<ObservationExpr, PatternError> {
        let start = self.current().start;
        self.expect(&Token::LBracket)?;
        let root = self.with_depth(|p| p.parse_prop_test_or())?;
        let count = root.comparison_count();
        if count > MAX_COMPARISONS_PER_OBSERVATION {
            return Err(PatternError::ComparisonLimitExceeded {
                pos: start,
                max: MAX_COMPARISONS_PER_OBSERVATION,
            });
        }
        let end = self.current().start;
        self.expect(&Token::RBracket)?;
        let object_type = root
            .primary_object_type()
            .ok_or_else(|| parse_error(start, "observation expression contains no comparisons"))?;
        Ok(ObservationExpr {
            object_type,
            root,
            span: Span { start, end },
        })
    }

    fn parse_prop_test_or(&mut self) -> Result<ComparisonTree, PatternError> {
        let mut left = self.parse_prop_test_and()?;
        while matches!(self.peek(), Token::Or) {
            let op_start = self.current().start;
            self.bump();
            let right = self.parse_prop_test_and()?;
            let span = Span {
                start: op_start,
                end: self.tokens[self.pos.saturating_sub(1)].end,
            };
            left = ComparisonTree::Or {
                left: Box::new(left),
                right: Box::new(right),
                span,
            };
        }
        Ok(left)
    }

    fn parse_prop_test_and(&mut self) -> Result<ComparisonTree, PatternError> {
        let mut left = self.parse_prop_test_unary()?;
        while matches!(self.peek(), Token::And) {
            let op_start = self.current().start;
            self.bump();
            let right = self.parse_prop_test_unary()?;
            let span = Span {
                start: op_start,
                end: self.tokens[self.pos.saturating_sub(1)].end,
            };
            left = ComparisonTree::And {
                left: Box::new(left),
                right: Box::new(right),
                span,
            };
        }
        Ok(left)
    }

    fn parse_prop_test_unary(&mut self) -> Result<ComparisonTree, PatternError> {
        if matches!(self.peek(), Token::Not) {
            let start = self.current().start;
            self.bump();
            if matches!(
                self.peek(),
                Token::Like
                    | Token::Matches
                    | Token::In
                    | Token::IsSubset
                    | Token::IsSuperset
                    | Token::Exists
                    | Token::Eq
                    | Token::NotEq
                    | Token::Gt
                    | Token::Lt
                    | Token::Gte
                    | Token::Lte
            ) {
                return self.parse_comparison(true);
            }
            let inner = self.with_depth(|p| p.parse_prop_test_unary())?;
            let end = self.tokens[self.pos.saturating_sub(1)].end;
            return Ok(ComparisonTree::Not {
                inner: Box::new(inner),
                span: Span { start, end },
            });
        }
        self.parse_prop_test_primary()
    }

    fn parse_prop_test_primary(&mut self) -> Result<ComparisonTree, PatternError> {
        if matches!(self.peek(), Token::LParen) {
            self.bump();
            let inner = self.parse_prop_test_or()?;
            self.expect(&Token::RParen)?;
            return Ok(inner);
        }
        self.parse_comparison(false)
    }

    fn parse_comparison(&mut self, not_modifier: bool) -> Result<ComparisonTree, PatternError> {
        let start = self.current().start;
        if matches!(self.peek(), Token::Exists) {
            self.bump();
            let path = self.parse_object_path()?;
            let end = self.tokens[self.pos.saturating_sub(1)].end;
            return Ok(ComparisonTree::Cmp(Comparison {
                path,
                op: ComparisonOp::Exists,
                negated: not_modifier,
                value: None,
                span: Span { start, end },
            }));
        }
        let path = self.parse_object_path()?;
        let negated = if not_modifier {
            true
        } else if matches!(self.peek(), Token::Not) {
            self.bump();
            true
        } else {
            false
        };
        let op = self.parse_comparison_op()?;
        let value = if matches!(op, ComparisonOp::Exists) {
            None
        } else {
            Some(self.parse_constant()?)
        };
        let end = self.tokens[self.pos.saturating_sub(1)].end;
        Ok(ComparisonTree::Cmp(Comparison {
            path,
            op,
            negated,
            value,
            span: Span { start, end },
        }))
    }

    fn parse_comparison_op(&mut self) -> Result<ComparisonOp, PatternError> {
        let op = match self.peek() {
            Token::Eq => ComparisonOp::Eq,
            Token::NotEq => ComparisonOp::NotEq,
            Token::Gt => ComparisonOp::Gt,
            Token::Lt => ComparisonOp::Lt,
            Token::Gte => ComparisonOp::Gte,
            Token::Lte => ComparisonOp::Lte,
            Token::In => ComparisonOp::In,
            Token::Like => ComparisonOp::Like,
            Token::Matches => ComparisonOp::Matches,
            Token::IsSubset => ComparisonOp::IsSubset,
            Token::IsSuperset => ComparisonOp::IsSuperset,
            Token::Exists => ComparisonOp::Exists,
            other => {
                return Err(parse_error(
                    self.current().start,
                    format!("expected comparison operator, found {other:?}"),
                ));
            }
        };
        self.bump();
        Ok(op)
    }

    fn parse_constant(&mut self) -> Result<PatternConstant, PatternError> {
        if matches!(self.peek(), Token::LParen) {
            return self.parse_list_constant();
        }
        let token = self.current().clone();
        self.bump();
        match token.token {
            Token::StringLit(s) => Ok(PatternConstant::String(s)),
            Token::IntLit(n) => Ok(PatternConstant::Int(n)),
            Token::FloatLit(f) => Ok(PatternConstant::Float(f)),
            Token::BoolLit(b) => Ok(PatternConstant::Bool(b)),
            Token::TimestampLit(ts) => Ok(PatternConstant::Timestamp(ts)),
            Token::HexLit(bytes) => Ok(PatternConstant::Hex(bytes)),
            Token::BinaryLit(bytes) => Ok(PatternConstant::Binary(bytes)),
            other => Err(parse_error(
                token.start,
                format!("expected constant, found {other:?}"),
            )),
        }
    }

    fn parse_list_constant(&mut self) -> Result<PatternConstant, PatternError> {
        let start = self.current().start;
        self.expect(&Token::LParen)?;
        let mut items = Vec::new();
        if !matches!(self.peek(), Token::RParen) {
            loop {
                items.push(self.parse_constant()?);
                if matches!(self.peek(), Token::Comma) {
                    self.bump();
                } else {
                    break;
                }
            }
        }
        self.expect(&Token::RParen)?;
        if items.is_empty() {
            return Err(parse_error(start, "IN list must not be empty"));
        }
        Ok(PatternConstant::List(items))
    }

    fn parse_object_path(&mut self) -> Result<ObjectPath, PatternError> {
        let start = self.current().start;
        let type_name = self.expect_identifier()?;
        let object_type = PatternScoType::parse(&type_name);
        self.expect(&Token::Colon)?;
        let first = self.parse_property_name()?;
        let mut steps = vec![PathStep::Property(first.clone())];
        let mut expect_dict_key = is_dict_container_property(&first);
        self.after_property_step(&mut steps, &first);
        self.parse_path_suffixes(&mut steps, &mut expect_dict_key)?;
        let end = self.tokens[self.pos.saturating_sub(1)].end;
        Ok(ObjectPath {
            object_type,
            steps,
            span: Span { start, end },
        })
    }

    fn parse_path_suffixes(
        &mut self,
        steps: &mut Vec<PathStep>,
        expect_dict_key: &mut bool,
    ) -> Result<(), PatternError> {
        loop {
            match self.peek() {
                Token::Dot => {
                    self.bump();
                    match self.peek() {
                        Token::StringLit(key) => {
                            let key = key.clone();
                            self.bump();
                            steps.push(PathStep::DictKey(key));
                            *expect_dict_key = false;
                        }
                        Token::Identifier(name) if *expect_dict_key => {
                            let name = name.clone();
                            self.bump();
                            steps.push(PathStep::DictKey(name));
                            *expect_dict_key = false;
                        }
                        Token::Identifier(name) => {
                            let name = name.clone();
                            self.bump();
                            steps.push(PathStep::Property(name.clone()));
                            *expect_dict_key = is_dict_container_property(&name);
                            self.after_property_step(steps, &name);
                        }
                        other => {
                            return Err(parse_error(
                                self.current().start,
                                format!("expected property name after '.', found {other:?}"),
                            ));
                        }
                    }
                }
                Token::LBracket => {
                    self.bump();
                    let index_step = match self.peek() {
                        Token::Star => {
                            self.bump();
                            PathStep::AnyIndex
                        }
                        Token::IntLit(n) if *n >= 0 => {
                            let idx = *n as usize;
                            self.bump();
                            PathStep::Index(idx)
                        }
                        other => {
                            return Err(parse_error(
                                self.current().start,
                                format!("expected list index or '*', found {other:?}"),
                            ));
                        }
                    };
                    self.expect(&Token::RBracket)?;
                    steps.push(index_step);
                    self.after_ref_list_index(steps);
                    *expect_dict_key = false;
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn after_property_step(&mut self, steps: &mut Vec<PathStep>, name: &str) {
        if is_ref_property(name) && matches!(self.peek(), Token::Dot) {
            steps.push(PathStep::Reference);
        }
    }

    fn after_ref_list_index(&mut self, steps: &mut Vec<PathStep>) {
        let prop = steps.iter().rev().skip(1).find_map(|step| {
            if let PathStep::Property(name) = step {
                Some(name.as_str())
            } else {
                None
            }
        });
        if prop.is_some_and(is_ref_property) && matches!(self.peek(), Token::Dot) {
            steps.push(PathStep::Reference);
        }
    }

    fn parse_property_name(&mut self) -> Result<String, PatternError> {
        match self.peek() {
            Token::Identifier(name) => {
                let name = name.clone();
                self.bump();
                Ok(name)
            }
            Token::StringLit(name) => {
                let name = name.clone();
                self.bump();
                Ok(name)
            }
            other => Err(parse_error(
                self.current().start,
                format!("expected property name, found {other:?}"),
            )),
        }
    }

    fn expect_identifier(&mut self) -> Result<String, PatternError> {
        match self.peek() {
            Token::Identifier(name) => {
                let name = name.clone();
                self.bump();
                Ok(name)
            }
            other => Err(parse_error(
                self.current().start,
                format!("expected identifier, found {other:?}"),
            )),
        }
    }

    fn expect(&mut self, expected: &Token) -> Result<(), PatternError> {
        if self.token_matches(expected) {
            self.bump();
            Ok(())
        } else {
            Err(parse_error(
                self.current().start,
                format!("expected {expected:?}, found {:?}", self.peek()),
            ))
        }
    }

    fn token_matches(&self, expected: &Token) -> bool {
        match (self.peek(), expected) {
            (Token::Identifier(a), Token::Identifier(_)) => !matches!(
                a.as_str(),
                "true"
                    | "false"
                    | "AND"
                    | "OR"
                    | "NOT"
                    | "FOLLOWEDBY"
                    | "WITHIN"
                    | "REPEATS"
                    | "START"
                    | "STOP"
                    | "TIMES"
                    | "SECONDS"
                    | "MINUTES"
                    | "HOURS"
                    | "DAYS"
                    | "MONTHS"
                    | "YEARS"
                    | "IN"
                    | "LIKE"
                    | "MATCHES"
                    | "ISSUBSET"
                    | "ISSUPERSET"
                    | "EXISTS"
            ),
            (a, b) => std::mem::discriminant(a) == std::mem::discriminant(b),
        }
    }
}

impl ComparisonTree {
    fn primary_object_type(&self) -> Option<PatternScoType> {
        match self {
            ComparisonTree::Cmp(c) => Some(c.path.object_type.clone()),
            ComparisonTree::And { left, .. } | ComparisonTree::Or { left, .. } => {
                left.primary_object_type()
            }
            ComparisonTree::Not { inner, .. } => inner.primary_object_type(),
        }
    }
}

fn is_dict_container_property(name: &str) -> bool {
    matches!(
        name,
        "hashes"
            | "extensions"
            | "ipfix"
            | "environment_variables"
            | "additional_header_fields"
            | "file_header_hashes"
    )
}

fn is_ref_property(name: &str) -> bool {
    name.ends_with("_ref") || name.ends_with("_refs")
}

fn parse_error(pos: usize, msg: impl Into<String>) -> PatternError {
    PatternError::ParseError {
        pos,
        msg: msg.into(),
    }
}

#[cfg(test)]
mod level1 {
    use super::*;
    use crate::core::ScoKind;
    use crate::pattern::ast::{ComparisonOp, PatternScoType};

    fn parse_obs(source: &str) -> ObservationExpr {
        match parse_level1(source).unwrap() {
            PatternAst::Observation(obs) => obs,
            _ => panic!("expected observation"),
        }
    }

    #[test]
    fn ipv4_equality() {
        let obs = parse_obs("[ipv4-addr:value = '203.0.113.4']");
        assert_eq!(obs.object_type, PatternScoType::Known(ScoKind::Ipv4Addr));
        assert_eq!(obs.root.comparison_count(), 1);
    }

    #[test]
    fn file_hash_quoted_key() {
        let obs = parse_obs(
            "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']",
        );
        assert_eq!(obs.object_type, PatternScoType::Known(ScoKind::File));
    }

    #[test]
    fn file_hash_dot_dict_key() {
        let obs = parse_obs("[file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4']");
        assert!(
            obs.root.comparison_count() == 1
                && matches!(
                    parse_level1("[file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4']").unwrap(),
                    PatternAst::Observation(_)
                )
        );
        let ComparisonTree::Cmp(cmp) = &obs.root else {
            panic!("expected comparison");
        };
        assert!(
            cmp.path
                .steps
                .iter()
                .any(|s| matches!(s, PathStep::DictKey(k) if k == "MD5"))
        );
    }

    #[test]
    fn custom_sco_type() {
        let obs = parse_obs("[x-usb-device:usbdrive.serial_number = '575833314133343231313937']");
        assert_eq!(
            obs.object_type,
            PatternScoType::Custom("x-usb-device".into())
        );
    }

    #[test]
    fn and_precedence_over_or() {
        let obs = parse_obs("[file:name = 'a.exe' OR file:name = 'b.exe' AND file:size > 100]");
        assert!(matches!(obs.root, ComparisonTree::Or { .. }));
    }

    #[test]
    fn exists() {
        let obs = parse_obs("[EXISTS windows-registry-key:values]");
        let ComparisonTree::Cmp(cmp) = &obs.root else {
            panic!("expected comparison");
        };
        assert_eq!(cmp.op, ComparisonOp::Exists);
        assert!(cmp.value.is_none());
    }

    #[test]
    fn in_list() {
        let obs = parse_obs("[process:name IN ('a', 'b')]");
        let ComparisonTree::Cmp(cmp) = &obs.root else {
            panic!("expected comparison");
        };
        assert_eq!(cmp.op, ComparisonOp::In);
        assert!(matches!(cmp.value, Some(PatternConstant::List(_))));
    }

    #[test]
    fn ref_path() {
        let obs = parse_obs("[network-traffic:src_ref.value = '10.0.0.1']");
        let ComparisonTree::Cmp(cmp) = &obs.root else {
            panic!("expected comparison");
        };
        assert!(
            cmp.path
                .steps
                .iter()
                .any(|s| matches!(s, PathStep::Reference))
        );
    }

    #[test]
    fn rejects_top_level_observation_operator() {
        let err = parse_level1("[a:x = '1'] AND [b:y = '2']").unwrap_err();
        assert!(matches!(err, PatternError::ParseError { .. }));
    }
}

#[cfg(test)]
mod not {
    use super::*;
    use crate::pattern::ast::ComparisonOp;

    fn parse_obs(source: &str) -> ObservationExpr {
        match parse_level1(source).unwrap() {
            PatternAst::Observation(obs) => obs,
            _ => panic!("expected observation"),
        }
    }

    #[test]
    fn not_like_modifier() {
        let obs = parse_obs("[file:name NOT LIKE '%.exe']");
        let ComparisonTree::Cmp(cmp) = &obs.root else {
            panic!("expected comparison");
        };
        assert!(cmp.negated);
        assert_eq!(cmp.op, ComparisonOp::Like);
    }
}

#[cfg(test)]
mod level23 {
    use super::*;
    use crate::pattern::ast::PatternAst;

    #[test]
    fn and_two_observations() {
        let ast =
            parse("[ipv4-addr:value = '1.2.3.4'] AND [domain-name:value = 'example.com']").unwrap();
        assert!(matches!(ast, PatternAst::And { .. }));
        assert_eq!(ast.observation_count(), 2);
    }

    #[test]
    fn followedby_within_parenthesized() {
        let pattern = "([file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4'] FOLLOWEDBY [windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\foo\\\\bar']) WITHIN 300 SECONDS";
        let ast = parse(pattern).unwrap();
        assert!(
            matches!(ast, PatternAst::Within { inner, .. } if matches!(inner.as_ref(), PatternAst::FollowedBy { .. })),
            "expected (A FOLLOWEDBY B) WITHIN to bind WITHIN to the parenthesized group"
        );
    }

    #[test]
    fn followedby_within_binds_to_last_observation() {
        let pattern = "[ipv4-addr:value = '1.1.1.1'] FOLLOWEDBY [ipv4-addr:value = '2.2.2.2'] WITHIN 300 SECONDS";
        let ast = parse(pattern).unwrap();
        assert!(
            matches!(ast, PatternAst::FollowedBy { left, right, .. }
                if matches!(left.as_ref(), PatternAst::Observation(_))
                && matches!(right.as_ref(), PatternAst::Within { .. })),
            "expected WITHIN to qualify the right operand, not the whole FOLLOWEDBY chain"
        );
    }

    #[test]
    fn followedby_looser_than_and() {
        let pattern = "[ipv4-addr:value = '1.1.1.1'] FOLLOWEDBY [ipv4-addr:value = '2.2.2.2'] AND [ipv4-addr:value = '3.3.3.3']";
        let ast = parse(pattern).unwrap();
        assert!(
            matches!(ast, PatternAst::FollowedBy { left, right, .. }
                if matches!(left.as_ref(), PatternAst::Observation(_))
                && matches!(right.as_ref(), PatternAst::And { .. })),
            "expected [a] FOLLOWEDBY ([b] AND [c]) per STIXPattern.g4 precedence"
        );
    }

    #[test]
    fn within_qualifier() {
        let ast = parse("[ipv4-addr:value = '1.2.3.4'] WITHIN 5 MINUTES").unwrap();
        assert!(matches!(ast, PatternAst::Within { .. }));
    }

    #[test]
    fn repeats_qualifier() {
        let ast = parse("[ipv4-addr:value = '1.2.3.4'] REPEATS 3 TIMES").unwrap();
        assert!(matches!(ast, PatternAst::Repeats { .. }));
    }

    #[test]
    fn start_stop_postfix() {
        let ast = parse(
            "[ipv4-addr:value = '198.51.100.1/32'] START t'2014-06-01T00:00:00Z' STOP t'2014-07-01T00:00:00Z'",
        )
        .unwrap();
        assert!(
            matches!(ast, PatternAst::StartStop { inner, .. }
                if matches!(inner.as_ref(), PatternAst::Observation(_))),
            "expected START/STOP as postfix qualifiers on an observation"
        );
    }

    #[test]
    fn rejects_prefix_start_stop() {
        let err = parse(
            "START t'2016-05-12T08:17:27.000Z' STOP t'2016-05-13T08:17:27.000Z' [ipv4-addr:value = '1.2.3.4']",
        )
        .unwrap_err();
        assert!(matches!(err, PatternError::ParseError { .. }));
    }
}
