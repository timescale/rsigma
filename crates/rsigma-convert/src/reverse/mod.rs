//! Reverse conversion: SIEM query strings → Sigma YAML.
//!
//! This is the mirror image of the forward [`Backend`](crate::Backend) engine.
//! Where a backend lowers a rule's HIR into a query string, a [`Frontend`]
//! parses a query string into the shared HIR ([`IrRule`]), which is then raised
//! to a [`SigmaRule`] and emitted as Sigma YAML.
//!
//! ```text
//! query -> Frontend::parse_query() -> IrRule -> raise_rule() -> SigmaRule -> emit_rule_yaml()
//! ```
//!
//! The framework owns everything that is dialect-independent: a
//! [`QueryDialect`]-driven tokenizer, a precedence-climbing boolean parser
//! (`NOT` > `AND` > `OR`), and the assembly of a boolean tree of leaves into
//! named Sigma selections plus a condition. A target dialect (e.g.
//! [`lucene`]) supplies a [`QueryDialect`] and a single
//! [`Frontend::parse_atom`] that interprets one leaf predicate; everything else
//! is shared, so a new target is a dialect table plus a leaf parser.
//!
//! Reverse conversion is best-effort: a query carries no rule metadata, so the
//! [`ReverseCtx`] supplies the title, id, logsource, level, and status, and
//! constructs a query cannot express are rejected with a structured
//! [`ConvertError`] rather than emitted as silently-wrong Sigma.

pub mod lucene;

use std::collections::HashMap;

use rsigma_ir::{
    IrCondition, IrDetection, IrDetectionItem, IrMatcher, IrPattern, IrPatternPart, IrRule,
    IrRuleMetadata, IrStrOp, LowerOptions, RaiseOptions, lower_rule, raise_rule,
};
use rsigma_parser::{Level, LogSource, SigmaRule, SigmaString, Status, StringPart};

use crate::error::{ConvertError, Result};

pub use lucene::{LUCENE_DIALECT, LuceneFrontend};

/// Longest query, in bytes, that [`reverse_collection`] converts.
pub const MAX_REVERSE_QUERY_LEN: usize = 64 * 1024;

/// Deepest nesting the boolean parser accepts. Each parenthesis and each
/// `NOT`, `!`, or `-` prefix adds a level, and a `field:(...)` value group
/// counts as one level for the parser that reads its values.
pub const MAX_REVERSE_QUERY_DEPTH: usize = 64;

// =============================================================================
// Dialect
// =============================================================================

/// Boolean-syntax configuration for a query dialect. The reverse analogue of
/// the boolean-operator half of [`TextQueryConfig`](crate::TextQueryConfig): a
/// pure data table that drives the shared tokenizer and boolean parser.
///
/// Leaf syntax (field predicates, ranges, quoting, wildcards) is dialect
/// specific and handled by [`Frontend::parse_atom`], not here.
#[derive(Debug, Clone, Copy)]
pub struct QueryDialect {
    /// Human-readable dialect name (`"lucene"`).
    pub name: &'static str,
    /// Tokens that mean logical AND (e.g. `["AND", "&&"]`).
    pub and_tokens: &'static [&'static str],
    /// Tokens that mean logical OR (e.g. `["OR", "||"]`).
    pub or_tokens: &'static [&'static str],
    /// Tokens (and prefixes) that mean logical NOT (e.g. `["NOT", "!"]`).
    pub not_tokens: &'static [&'static str],
    /// Whether adjacent terms with no explicit operator are ANDed (`true`) or
    /// ORed (`false`).
    pub implicit_and: bool,
}

// =============================================================================
// Boolean expression tree
// =============================================================================

/// A boolean expression tree over leaves of type `L`.
///
/// The tokenizer/parser produce `QueryExpr<String>` (leaves are raw atom
/// strings); [`Frontend::parse_atom`] expands each atom into a
/// `QueryExpr<QueryLeaf>` sub-tree (a range atom becomes an `And` of two
/// bounds, a value group becomes an `Or`, and so on).
#[derive(Debug, Clone, PartialEq)]
pub enum QueryExpr<L> {
    And(Vec<QueryExpr<L>>),
    Or(Vec<QueryExpr<L>>),
    Not(Box<QueryExpr<L>>),
    Leaf(L),
}

impl<L> QueryExpr<L> {
    /// Replace every leaf with a sub-tree, splicing the results in place.
    fn expand<T, F>(self, f: &mut F) -> Result<QueryExpr<T>>
    where
        F: FnMut(L) -> Result<QueryExpr<T>>,
    {
        match self {
            QueryExpr::And(items) => Ok(QueryExpr::And(
                items
                    .into_iter()
                    .map(|e| e.expand(f))
                    .collect::<Result<_>>()?,
            )),
            QueryExpr::Or(items) => Ok(QueryExpr::Or(
                items
                    .into_iter()
                    .map(|e| e.expand(f))
                    .collect::<Result<_>>()?,
            )),
            QueryExpr::Not(inner) => Ok(QueryExpr::Not(Box::new(inner.expand(f)?))),
            QueryExpr::Leaf(leaf) => f(leaf),
        }
    }
}

/// One resolved leaf predicate.
#[derive(Debug, Clone, PartialEq)]
pub enum QueryLeaf {
    /// A field-bound match (`field: matcher`).
    Field { field: String, matcher: IrMatcher },
    /// A field-less keyword / free-text match.
    Keyword(IrMatcher),
}

// =============================================================================
// Context and output
// =============================================================================

/// Metadata and options the query string cannot supply. Owns the
/// selection-naming scheme through [`assemble_rule`].
#[derive(Debug, Clone, Default)]
pub struct ReverseCtx {
    pub title: Option<String>,
    pub id: Option<String>,
    pub status: Option<Status>,
    pub level: Option<Level>,
    pub product: Option<String>,
    pub category: Option<String>,
    pub service: Option<String>,
    /// Reserved for strict mode (reject best-effort fallbacks). Currently the
    /// framework already rejects inexpressible constructs unconditionally.
    pub strict: bool,
}

impl ReverseCtx {
    fn metadata(&self) -> IrRuleMetadata {
        IrRuleMetadata {
            title: self
                .title
                .clone()
                .unwrap_or_else(|| "Converted query".to_string()),
            id: self.id.clone(),
            level: self.level,
            status: self.status,
            ..Default::default()
        }
    }

    fn logsource(&self) -> LogSource {
        LogSource {
            category: self.category.clone(),
            product: self.product.clone(),
            service: self.service.clone(),
            definition: None,
            custom: HashMap::new(),
        }
    }
}

/// One successful reverse conversion.
#[derive(Debug, Clone)]
pub struct ReverseResult {
    /// The source query.
    pub query: String,
    /// The raised Sigma rule.
    pub rule: SigmaRule,
    /// The emitted Sigma YAML.
    pub yaml: String,
}

/// The result of converting a batch of queries: successes plus per-query errors
/// (the batch never aborts on a single failure), mirroring
/// [`convert_collection`](crate::convert_collection).
#[derive(Debug, Default)]
pub struct ReverseOutput {
    pub rules: Vec<ReverseResult>,
    pub errors: Vec<(String, ConvertError)>,
}

// =============================================================================
// Frontend trait
// =============================================================================

/// A reverse-conversion target: parses one query dialect into the HIR.
///
/// The inverse of [`Backend`](crate::Backend). Implementors provide a
/// [`QueryDialect`] and a leaf parser; the default [`Frontend::parse_query`]
/// tokenizes, builds the boolean tree, expands each atom via
/// [`Frontend::parse_atom`], and assembles the [`IrRule`].
pub trait Frontend {
    /// The dialect name (`"lucene"`).
    fn name(&self) -> &str;

    /// The boolean-syntax configuration.
    fn dialect(&self) -> &QueryDialect;

    /// Parse a single leaf atom (a `field:value`, range, value group, or bare
    /// term) into a boolean sub-tree of resolved leaves.
    fn parse_atom(&self, atom: &str, ctx: &ReverseCtx) -> Result<QueryExpr<QueryLeaf>>;

    /// Parse a full query into an [`IrRule`].
    fn parse_query(&self, query: &str, ctx: &ReverseCtx) -> Result<IrRule> {
        let dialect = self.dialect();
        let tokens = tokenize(dialect, query)?;
        let tree = parse_boolean(dialect, tokens, 0)?;
        let mut expand = |atom: String| self.parse_atom(&atom, ctx);
        let resolved = tree.expand(&mut expand)?;
        assemble_rule(resolved, ctx)
    }
}

/// Convert a batch of queries, collecting per-query errors instead of aborting.
pub fn reverse_collection(
    frontend: &dyn Frontend,
    queries: &[String],
    ctx: &ReverseCtx,
) -> ReverseOutput {
    let mut output = ReverseOutput::default();
    for query in queries {
        match convert_one(frontend, query, ctx) {
            Ok(result) => output.rules.push(result),
            Err(e) => output.errors.push((query.clone(), e)),
        }
    }
    output
}

fn convert_one(frontend: &dyn Frontend, query: &str, ctx: &ReverseCtx) -> Result<ReverseResult> {
    if query.len() > MAX_REVERSE_QUERY_LEN {
        return Err(ConvertError::QueryParse(format!(
            "query is {} bytes; maximum is {MAX_REVERSE_QUERY_LEN}",
            query.len()
        )));
    }
    if [&ctx.category, &ctx.product, &ctx.service]
        .into_iter()
        .all(|value| value.as_deref().is_none_or(str::is_empty))
    {
        return Err(ConvertError::RuleConversion(
            "a Sigma rule needs a logsource; set a product, category, or service".into(),
        ));
    }
    let ir = frontend.parse_query(query, ctx)?;
    let rule = raise_rule(&ir, &RaiseOptions::default())
        .map_err(|e| ConvertError::RuleConversion(e.to_string()))?;
    let yaml = rsigma_parser::emit_rule_yaml(&rule);
    verify_emitted_rule(&rule, &yaml).map_err(|reason| {
        ConvertError::RuleConversion(format!(
            "the raised rule cannot be written as Sigma YAML that reads back the same: {reason}"
        ))
    })?;
    Ok(ReverseResult {
        query: query.to_string(),
        rule,
        yaml,
    })
}

/// Check that `yaml`, emitted from `rule`, parses back as exactly one rule
/// that lowers to the same HIR: a field name holding `|`, for example, would
/// read back as a field plus modifiers.
fn verify_emitted_rule(rule: &SigmaRule, yaml: &str) -> std::result::Result<(), String> {
    let documents = yaml_serde::Deserializer::from_str(yaml).count();
    if documents != 1 {
        return Err(format!("expected one YAML document, found {documents}"));
    }
    let collection = rsigma_parser::parse_sigma_yaml(yaml).map_err(|e| e.to_string())?;
    if let Some(error) = collection.errors().next() {
        return Err(error.to_string());
    }
    let [reparsed] = collection.rules.as_slice() else {
        return Err("expected exactly one detection rule".to_string());
    };
    if !collection.correlations.is_empty() || !collection.filters.is_empty() {
        return Err("expected exactly one detection rule".to_string());
    }
    let options = LowerOptions::default();
    let expected = lower_rule(rule, &options).map_err(|e| e.to_string())?;
    let actual = lower_rule(reparsed, &options).map_err(|e| e.to_string())?;
    if expected != actual {
        return Err("the emitted rule matches differently".to_string());
    }
    Ok(())
}

// =============================================================================
// Tokenizer
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
enum Token {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Atom(String),
}

/// Split a query into boolean tokens. Quoted strings, `/regex/`, `[range]`,
/// `{range}`, and `field:(value group)` spans are kept atomic (including their
/// internal whitespace); `+`/`-` term prefixes become required/NOT.
fn tokenize(dialect: &QueryDialect, query: &str) -> Result<Vec<Token>> {
    let chars: Vec<char> = query.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    // True at the start of a term slot (start of input, after `(`, or after an
    // operator), where `+`/`-` act as prefixes.
    let mut at_term_start = true;

    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        match chars[i] {
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
                at_term_start = true;
                continue;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
                at_term_start = false;
                continue;
            }
            _ => {}
        }

        if let Some((token, consumed)) = match_operator(dialect, &chars, i) {
            tokens.push(token);
            i += consumed;
            at_term_start = true;
            continue;
        }

        if at_term_start && (chars[i] == '+' || chars[i] == '-') {
            if chars[i] == '-' {
                tokens.push(Token::Not);
            }
            i += 1;
            continue;
        }

        let (atom, consumed) = read_atom(&chars, i)?;
        if consumed == 0 {
            return Err(ConvertError::QueryParse(format!(
                "unexpected character '{}' at position {i}",
                chars[i]
            )));
        }
        tokens.push(Token::Atom(atom));
        i += consumed;
        at_term_start = false;
    }

    if tokens.is_empty() {
        return Err(ConvertError::QueryParse("empty query".into()));
    }
    Ok(tokens)
}

fn match_operator(dialect: &QueryDialect, chars: &[char], i: usize) -> Option<(Token, usize)> {
    for (token, list) in [
        (Token::And, dialect.and_tokens),
        (Token::Or, dialect.or_tokens),
        (Token::Not, dialect.not_tokens),
    ] {
        for &candidate in list {
            if token_matches(chars, i, candidate) {
                return Some((token.clone(), candidate.chars().count()));
            }
        }
    }
    None
}

/// Match a literal operator token at `i`. Alphabetic operators (`AND`) require a
/// trailing word boundary so `ANDROID` is not read as `AND`.
fn token_matches(chars: &[char], i: usize, token: &str) -> bool {
    let token_chars: Vec<char> = token.chars().collect();
    if i + token_chars.len() > chars.len() {
        return false;
    }
    if chars[i..i + token_chars.len()] != token_chars[..] {
        return false;
    }
    if token_chars.iter().all(|c| c.is_ascii_alphabetic()) {
        match chars.get(i + token_chars.len()) {
            None => true,
            Some(c) => c.is_whitespace() || *c == '(' || *c == ')',
        }
    } else {
        true
    }
}

/// Read one atom, keeping quotes/regex/ranges/value-groups (and their internal
/// whitespace) together.
fn read_atom(chars: &[char], start: usize) -> Result<(String, usize)> {
    let mut out = String::new();
    let mut i = start;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() || c == ')' {
            break;
        }
        match c {
            '(' if out.ends_with(':') => {
                let (group, consumed) = read_balanced(chars, i, '(', ')')?;
                out.push_str(&group);
                i += consumed;
            }
            '(' => break,
            '"' | '\'' => {
                let (quoted, consumed) = read_quoted(chars, i, c)?;
                out.push_str(&quoted);
                i += consumed;
            }
            '/' if out.ends_with(':') => {
                let (regex, consumed) = read_quoted(chars, i, '/')?;
                out.push_str(&regex);
                i += consumed;
            }
            '[' => {
                let (range, consumed) = read_balanced(chars, i, '[', ']')?;
                out.push_str(&range);
                i += consumed;
            }
            '{' => {
                let (range, consumed) = read_balanced(chars, i, '{', '}')?;
                out.push_str(&range);
                i += consumed;
            }
            '\\' => {
                out.push('\\');
                i += 1;
                if i < chars.len() {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    Ok((out, i - start))
}

/// Read a `delim ... delim` span (quotes or regex), preserving escapes.
fn read_quoted(chars: &[char], start: usize, delim: char) -> Result<(String, usize)> {
    let mut out = String::new();
    out.push(chars[start]);
    let mut i = start + 1;
    while i < chars.len() {
        let c = chars[i];
        out.push(c);
        i += 1;
        if c == '\\' && i < chars.len() {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        if c == delim {
            return Ok((out, i - start));
        }
    }
    Err(ConvertError::QueryParse(format!(
        "unterminated {delim}-delimited value"
    )))
}

/// Read a balanced `open ... close` span (ranges, value groups).
fn read_balanced(chars: &[char], start: usize, open: char, close: char) -> Result<(String, usize)> {
    let mut out = String::new();
    let mut depth = 0usize;
    let mut i = start;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let (quoted, consumed) = read_quoted(chars, i, c)?;
            out.push_str(&quoted);
            i += consumed;
            continue;
        }
        out.push(c);
        i += 1;
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Ok((out, i - start));
            }
        }
    }
    Err(ConvertError::QueryParse(format!(
        "unbalanced '{open}{close}' group"
    )))
}

// =============================================================================
// Boolean parser (precedence: NOT > AND > OR)
// =============================================================================

struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    dialect: &'a QueryDialect,
    depth: usize,
}

/// Parse `tokens` into a boolean tree. `depth` is the nesting level the
/// tokens start at.
fn parse_boolean(
    dialect: &QueryDialect,
    tokens: Vec<Token>,
    depth: usize,
) -> Result<QueryExpr<String>> {
    let mut parser = Parser {
        tokens,
        pos: 0,
        dialect,
        depth,
    };
    let expr = parser.parse_or()?;
    if parser.pos != parser.tokens.len() {
        return Err(ConvertError::QueryParse(
            "unexpected trailing tokens (check parentheses)".into(),
        ));
    }
    Ok(expr)
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn starts_term(&self) -> bool {
        matches!(
            self.peek(),
            Some(Token::Atom(_)) | Some(Token::LParen) | Some(Token::Not)
        )
    }

    fn parse_or(&mut self) -> Result<QueryExpr<String>> {
        let mut nodes = vec![self.parse_and()?];
        loop {
            if matches!(self.peek(), Some(Token::Or)) {
                self.pos += 1;
                nodes.push(self.parse_and()?);
            } else if !self.dialect.implicit_and && self.starts_term() {
                nodes.push(self.parse_and()?);
            } else {
                break;
            }
        }
        Ok(collapse(QueryExpr::Or, nodes))
    }

    fn parse_and(&mut self) -> Result<QueryExpr<String>> {
        let mut nodes = vec![self.parse_not()?];
        loop {
            if matches!(self.peek(), Some(Token::And)) {
                self.pos += 1;
                nodes.push(self.parse_not()?);
            } else if self.dialect.implicit_and && self.starts_term() {
                nodes.push(self.parse_not()?);
            } else {
                break;
            }
        }
        Ok(collapse(QueryExpr::And, nodes))
    }

    fn nested<T>(&mut self, parse: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        if self.depth >= MAX_REVERSE_QUERY_DEPTH {
            return Err(ConvertError::QueryParse(format!(
                "query nesting exceeds maximum depth ({MAX_REVERSE_QUERY_DEPTH})"
            )));
        }
        self.depth += 1;
        let result = parse(self);
        self.depth -= 1;
        result
    }

    fn parse_not(&mut self) -> Result<QueryExpr<String>> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.pos += 1;
            let inner = self.nested(Self::parse_not)?;
            Ok(QueryExpr::Not(Box::new(inner)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<QueryExpr<String>> {
        match self.peek() {
            Some(Token::LParen) => {
                self.pos += 1;
                let inner = self.nested(Self::parse_or)?;
                match self.peek() {
                    Some(Token::RParen) => {
                        self.pos += 1;
                        Ok(inner)
                    }
                    _ => Err(ConvertError::QueryParse("missing closing ')'".into())),
                }
            }
            Some(Token::Atom(_)) => {
                let Some(Token::Atom(atom)) = self.tokens.get(self.pos).cloned() else {
                    unreachable!()
                };
                self.pos += 1;
                Ok(QueryExpr::Leaf(atom))
            }
            Some(other) => Err(ConvertError::QueryParse(format!(
                "unexpected token: {other:?}"
            ))),
            None => Err(ConvertError::QueryParse("unexpected end of query".into())),
        }
    }
}

fn collapse<L>(
    ctor: fn(Vec<QueryExpr<L>>) -> QueryExpr<L>,
    mut nodes: Vec<QueryExpr<L>>,
) -> QueryExpr<L> {
    if nodes.len() == 1 {
        nodes.pop().unwrap()
    } else {
        ctor(nodes)
    }
}

// =============================================================================
// Assembly: boolean tree of leaves -> IrRule
// =============================================================================

/// Turn a resolved boolean tree into an [`IrRule`] with named selections and a
/// condition. Positive field leaves that share an AND are merged into one
/// selection; same-field OR leaves collapse into a value list; negated branches
/// become `filter` selections.
pub fn assemble_rule(expr: QueryExpr<QueryLeaf>, ctx: &ReverseCtx) -> Result<IrRule> {
    let mut asm = Assembler::default();
    let condition = asm.build(expr, "selection");
    Ok(IrRule {
        metadata: ctx.metadata(),
        logsource: ctx.logsource(),
        sigma_version: None,
        detections: asm.detections,
        conditions: vec![condition],
    })
}

#[derive(Default)]
struct Assembler {
    detections: HashMap<String, IrDetection>,
    counters: HashMap<&'static str, usize>,
}

impl Assembler {
    fn name(&mut self, prefix: &'static str) -> String {
        let counter = self.counters.entry(prefix).or_insert(0);
        let name = if *counter == 0 {
            prefix.to_string()
        } else {
            format!("{prefix}_{counter}")
        };
        *counter += 1;
        name
    }

    fn add(&mut self, prefix: &'static str, detection: IrDetection) -> IrCondition {
        let name = self.name(prefix);
        self.detections.insert(name.clone(), detection);
        IrCondition::Detection(name)
    }

    fn build(&mut self, expr: QueryExpr<QueryLeaf>, prefix: &'static str) -> IrCondition {
        match expr {
            QueryExpr::Leaf(QueryLeaf::Field { field, matcher }) => {
                self.add(prefix, IrDetection::AllOf(vec![field_item(field, matcher)]))
            }
            QueryExpr::Leaf(QueryLeaf::Keyword(matcher)) => {
                self.add("keywords", IrDetection::Keywords(matcher))
            }
            QueryExpr::And(children) => self.build_and(children, prefix),
            QueryExpr::Or(children) => self.build_or(children, prefix),
            QueryExpr::Not(inner) => IrCondition::Not(Box::new(self.build(*inner, "filter"))),
        }
    }

    fn build_and(
        &mut self,
        children: Vec<QueryExpr<QueryLeaf>>,
        prefix: &'static str,
    ) -> IrCondition {
        let mut field_items = Vec::new();
        let mut others = Vec::new();
        for child in children {
            match child {
                QueryExpr::Leaf(QueryLeaf::Field { field, matcher }) => {
                    field_items.push(field_item(field, matcher));
                }
                other => others.push(other),
            }
        }

        let mut conditions = Vec::new();
        if !field_items.is_empty() {
            conditions.push(self.add(prefix, IrDetection::AllOf(field_items)));
        }
        for other in others {
            conditions.push(self.build(other, prefix));
        }
        collapse_cond(IrCondition::And, conditions)
    }

    fn build_or(
        &mut self,
        children: Vec<QueryExpr<QueryLeaf>>,
        prefix: &'static str,
    ) -> IrCondition {
        if let Some(item) = same_field_value_list(&children) {
            return self.add(prefix, IrDetection::AllOf(vec![item]));
        }
        let conditions = children
            .into_iter()
            .map(|c| self.build(c, prefix))
            .collect();
        collapse_cond(IrCondition::Or, conditions)
    }
}

fn field_item(field: String, matcher: IrMatcher) -> IrDetectionItem {
    let exists = match &matcher {
        IrMatcher::Exists(b) => Some(*b),
        _ => None,
    };
    IrDetectionItem {
        field: Some(field),
        matcher,
        exists,
    }
}

fn collapse_cond(
    ctor: fn(Vec<IrCondition>) -> IrCondition,
    mut nodes: Vec<IrCondition>,
) -> IrCondition {
    match nodes.len() {
        0 => IrCondition::And(Vec::new()),
        1 => nodes.pop().unwrap(),
        _ => ctor(nodes),
    }
}

/// If every OR child is a field leaf on the same field with the same string
/// operator and case sensitivity, collapse them into one value-list item.
fn same_field_value_list(children: &[QueryExpr<QueryLeaf>]) -> Option<IrDetectionItem> {
    let mut field_name: Option<&str> = None;
    let mut op_ci: Option<(IrStrOp, bool)> = None;
    let mut matchers = Vec::with_capacity(children.len());

    for child in children {
        let QueryExpr::Leaf(QueryLeaf::Field { field, matcher }) = child else {
            return None;
        };
        let IrMatcher::Str {
            op,
            case_insensitive,
            ..
        } = matcher
        else {
            return None;
        };
        match field_name {
            None => field_name = Some(field),
            Some(prev) if prev == field => {}
            Some(_) => return None,
        }
        match op_ci {
            None => op_ci = Some((*op, *case_insensitive)),
            Some(prev) if prev == (*op, *case_insensitive) => {}
            Some(_) => return None,
        }
        matchers.push(matcher.clone());
    }

    let field = field_name?.to_string();
    Some(IrDetectionItem {
        field: Some(field),
        matcher: IrMatcher::AnyOf(matchers),
        exists: None,
    })
}

// =============================================================================
// Shared leaf helpers (used by frontends)
// =============================================================================

/// Build an [`IrPattern`] from a raw value, interpreting `*`/`?` as wildcards
/// and `\` as an escape (matching Sigma value semantics).
pub fn parse_pattern(raw: &str) -> IrPattern {
    let sigma = SigmaString::new(raw);
    IrPattern {
        parts: sigma
            .parts
            .iter()
            .map(|p| match p {
                StringPart::Plain(t) => IrPatternPart::Literal(t.clone()),
                StringPart::Special(rsigma_parser::SpecialChar::WildcardMulti) => {
                    IrPatternPart::WildcardMulti
                }
                StringPart::Special(rsigma_parser::SpecialChar::WildcardSingle) => {
                    IrPatternPart::WildcardSingle
                }
            })
            .collect(),
    }
}

/// Infer an idiomatic string matcher from a raw value: surrounding `*`
/// wildcards select `contains`/`startswith`/`endswith`; anything else stays an
/// exact match (with inner wildcards preserved inline).
pub fn infer_str_matcher(raw: &str, case_insensitive: bool) -> IrMatcher {
    let pattern = parse_pattern(raw);
    let parts = &pattern.parts;
    let lead = matches!(parts.first(), Some(IrPatternPart::WildcardMulti));
    let trail = parts.len() > 1 && matches!(parts.last(), Some(IrPatternPart::WildcardMulti));

    let inner = &parts[lead as usize..parts.len() - trail as usize];
    let inner_has_wildcard = inner.iter().any(|p| {
        matches!(
            p,
            IrPatternPart::WildcardMulti | IrPatternPart::WildcardSingle
        )
    });

    if !inner.is_empty() && !inner_has_wildcard {
        let pattern = IrPattern {
            parts: inner.to_vec(),
        };
        let op = match (lead, trail) {
            (true, true) => Some(IrStrOp::Contains),
            (false, true) => Some(IrStrOp::StartsWith),
            (true, false) => Some(IrStrOp::EndsWith),
            (false, false) => None,
        };
        if let Some(op) = op {
            return IrMatcher::Str {
                op,
                pattern,
                case_insensitive,
            };
        }
    }

    IrMatcher::Str {
        op: IrStrOp::Exact,
        pattern,
        case_insensitive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ReverseCtx {
        ReverseCtx {
            title: Some("T".into()),
            product: Some("windows".into()),
            ..Default::default()
        }
    }

    fn yaml(query: &str) -> String {
        let frontend = LuceneFrontend;
        convert_one(&frontend, query, &ctx())
            .expect("converts")
            .yaml
    }

    #[test]
    fn requires_a_logsource() {
        for ctx in [
            ReverseCtx {
                title: Some("T".into()),
                ..Default::default()
            },
            ReverseCtx {
                title: Some("T".into()),
                product: Some(String::new()),
                ..Default::default()
            },
        ] {
            let err = convert_one(&LuceneFrontend, "EventID:1", &ctx).unwrap_err();
            assert!(err.to_string().contains("needs a logsource"), "{err}");
        }
    }

    #[test]
    fn infers_string_operators_from_wildcards() {
        assert!(matches!(
            infer_str_matcher("*foo*", true),
            IrMatcher::Str {
                op: IrStrOp::Contains,
                ..
            }
        ));
        assert!(matches!(
            infer_str_matcher("foo*", true),
            IrMatcher::Str {
                op: IrStrOp::StartsWith,
                ..
            }
        ));
        assert!(matches!(
            infer_str_matcher("*foo", true),
            IrMatcher::Str {
                op: IrStrOp::EndsWith,
                ..
            }
        ));
        assert!(matches!(
            infer_str_matcher("foo", true),
            IrMatcher::Str {
                op: IrStrOp::Exact,
                ..
            }
        ));
    }

    #[test]
    fn and_of_fields_merges_into_one_selection() {
        let out = yaml("Image:*\\\\cmd.exe AND CommandLine:*whoami*");
        assert!(out.contains("selection:"), "{out}");
        assert!(out.contains("Image|endswith:"), "{out}");
        assert!(out.contains("CommandLine|contains:"), "{out}");
        assert!(out.contains("condition: selection"), "{out}");
    }

    #[test]
    fn not_becomes_filter_selection() {
        let out = yaml("EventID:1 AND NOT User:SYSTEM");
        assert!(out.contains("filter:"), "{out}");
        assert!(out.contains("condition: selection and not filter"), "{out}");
    }

    fn is_depth_error(query: &str) -> bool {
        matches!(
            convert_one(&LuceneFrontend, query, &ctx()),
            Err(ConvertError::QueryParse(msg)) if msg.contains("maximum depth")
        )
    }

    fn parens(n: usize, inner: &str) -> String {
        format!("{}{inner}{}", "(".repeat(n), ")".repeat(n))
    }

    #[test]
    fn parentheses_and_not_prefixes_share_the_depth_limit() {
        let max = MAX_REVERSE_QUERY_DEPTH;
        assert!(!is_depth_error(&parens(max, "a:1")));
        assert!(is_depth_error(&parens(max + 1, "a:1")));
        assert!(!is_depth_error(&format!("{}a:1", "NOT ".repeat(max))));
        assert!(is_depth_error(&format!("{}a:1", "- ".repeat(max + 1))));

        let half = max / 2;
        let mixed = |nots: usize| parens(half, &format!("{}a:1", "! ".repeat(nots)));
        assert!(!is_depth_error(&mixed(max - half)));
        assert!(is_depth_error(&mixed(max - half + 1)));
    }

    #[test]
    fn value_group_counts_as_a_level() {
        let group = |n: usize| format!("a:({})", parens(n, "x"));
        assert!(!is_depth_error(&group(MAX_REVERSE_QUERY_DEPTH - 1)));
        assert!(is_depth_error(&group(MAX_REVERSE_QUERY_DEPTH)));
    }

    #[test]
    fn query_length_is_capped() {
        let at_limit = format!("a:{}", "x".repeat(MAX_REVERSE_QUERY_LEN - 2));
        assert!(convert_one(&LuceneFrontend, &at_limit, &ctx()).is_ok());
        let over = format!("{at_limit}x");
        let err = convert_one(&LuceneFrontend, &over, &ctx()).unwrap_err();
        assert!(err.to_string().contains("maximum is"), "{err}");
    }

    #[test]
    fn same_field_or_collapses_to_value_list() {
        let out = yaml("Image:*\\\\a.exe OR Image:*\\\\b.exe");
        assert!(out.contains("Image|endswith:"), "{out}");
        // A value list, not two selections.
        assert!(
            out.contains("- '\\a.exe'") || out.contains("- '\\\\a.exe'"),
            "{out}"
        );
        assert!(out.contains("condition: selection"), "{out}");
    }

    #[test]
    fn emitted_rule_that_reads_back_differently_is_rejected() {
        let mut rule = convert_one(&LuceneFrontend, "Image:whoami", &ctx())
            .expect("converts")
            .rule;
        verify_emitted_rule(&rule, &rsigma_parser::emit_rule_yaml(&rule)).expect("verifies");
        let detection = rule.detection.named.values_mut().next().unwrap();
        let rsigma_parser::Detection::AllOf(items) = detection else {
            panic!("unexpected detection shape");
        };
        items[0].field.name = Some("Image|contains".to_string());
        let yaml = rsigma_parser::emit_rule_yaml(&rule);
        assert!(verify_emitted_rule(&rule, &yaml).is_err(), "{yaml}");
        assert!(verify_emitted_rule(&rule, &format!("{yaml}---\n{yaml}")).is_err());
    }
}
