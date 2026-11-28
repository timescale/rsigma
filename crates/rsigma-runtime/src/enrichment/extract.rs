//! Extract programs for enrichers, with event values passed as data.
//!
//! A `lookup` or `stix` extract may reference `${detection.*}` and
//! `${correlation.*}` values. They are never pasted into the program text.
//! Instead, each reference becomes a variable the compiled program reads:
//!
//! - jq: `$__v0`, `$__v1`, ... Inside a string literal the reference
//!   becomes the interpolation `\($__v0)`, so `"${...}"` is the value itself.
//! - CEL: `__v0`, `__v1`, ... A string literal that holds a reference is
//!   split into a concatenation, so `'a${...}b'` is `('a' + __v0 + 'b')`.
//! - JSONPath, which has no variables: each value is encoded as a quoted
//!   string literal, escaped for its quote. A reference outside a string
//!   literal becomes a single-quoted literal, so it is valid only where a
//!   JSONPath literal is.
//!
//! Every value is a string. `${ENV_VAR}` references are operator
//! configuration and are substituted into the program text when the
//! enricher is built.
//!
//! jq and CEL programs are compiled once, when the enricher is built. Each
//! evaluation runs on the blocking pool under [`ExtractLimits`], so the
//! enricher timeout returns on time and stops a jq program at its next
//! step.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use rsigma_eval::EvaluationResult;
use rsigma_eval::pipeline::sources::ExtractExpr;
use serde_json::Value;
use tokio::sync::Semaphore;

use super::template::{TemplateRef, render_enricher_reference, template_refs};
use super::{EnrichError, EnrichErrorKind};
use crate::sources::extract::{ExtractLimits, ExtractProgram};

/// The extract an enricher was built with. A program that failed to
/// prepare fails every evaluation with the same error; the config loader
/// rejects it before an enricher is built.
pub(crate) struct EnricherExtract(Result<ExtractTemplate, String>);

impl EnricherExtract {
    pub(crate) fn new(expr: &ExtractExpr, templated: bool) -> Self {
        Self(ExtractTemplate::new(expr, templated))
    }

    pub(crate) async fn apply(
        &self,
        enricher_id: &str,
        data: Value,
        result: &EvaluationResult,
        timeout: Duration,
    ) -> Result<Value, EnrichError> {
        let outcome = match &self.0 {
            Ok(template) => template.evaluate(data, result, timeout).await,
            Err(message) => Err(message.clone()),
        };
        outcome.map_err(|message| EnrichError {
            enricher_id: enricher_id.to_string(),
            kind: EnrichErrorKind::Extract(message),
        })
    }
}

/// An enricher's extract program, ready to evaluate.
pub(crate) struct ExtractTemplate {
    shape: Shape,
}

enum Shape {
    /// Compiled once. `refs[i]` is rendered into variable `i`.
    Compiled {
        program: Arc<ExtractProgram>,
        refs: Vec<String>,
    },
    /// A JSONPath query with values encoded as literals, compiled per
    /// evaluation.
    JsonPath(Vec<JsonPathPart>),
}

enum JsonPathPart {
    Text(String),
    Value {
        reference: String,
        quote: char,
        bare: bool,
    },
}

/// What one evaluation runs on the blocking pool.
enum Job {
    Compiled(Arc<ExtractProgram>, Vec<String>),
    JsonPath(String),
}

impl ExtractTemplate {
    /// Prepare `expr`. With `templated`, `${...}` references are bound as
    /// described in the module documentation; otherwise the text is the
    /// program as written.
    pub(crate) fn new(expr: &ExtractExpr, templated: bool) -> Result<Self, String> {
        if !templated {
            return Ok(Self {
                shape: Shape::Compiled {
                    program: Arc::new(ExtractProgram::compile(expr, &[])?),
                    refs: Vec::new(),
                },
            });
        }
        let shape = match expr {
            ExtractExpr::Jq(code) => {
                let (code, refs) = rewrite_jq(code)?;
                compiled(ExtractExpr::Jq(code), refs)?
            }
            ExtractExpr::Cel(code) => {
                let (code, refs) = rewrite_cel(code)?;
                compiled(ExtractExpr::Cel(code), refs)?
            }
            ExtractExpr::JsonPath(path) => {
                let parts = split_jsonpath(path)?;
                if parts.iter().all(|p| matches!(p, JsonPathPart::Text(_))) {
                    compiled(
                        ExtractExpr::JsonPath(render_jsonpath(&parts, |_| String::new())),
                        Vec::new(),
                    )?
                } else {
                    for probe in ["", "x"] {
                        ExtractProgram::compile(
                            &ExtractExpr::JsonPath(render_jsonpath(&parts, |_| probe.to_string())),
                            &[],
                        )
                        .map_err(|e| {
                            format!(
                                "{e}; a reference outside a string literal stands for a quoted string, so it is valid only where a JSONPath literal is (for example $['${{detection.fields.Name}}'])"
                            )
                        })?;
                    }
                    Shape::JsonPath(parts)
                }
            }
        };
        Ok(Self { shape })
    }

    /// Evaluate against `data`, rendering references from `result`. The
    /// evaluation gives up after `timeout`.
    pub(crate) async fn evaluate(
        &self,
        data: Value,
        result: &EvaluationResult,
        timeout: Duration,
    ) -> Result<Value, String> {
        let job = match &self.shape {
            Shape::Compiled { program, refs } => Job::Compiled(
                Arc::clone(program),
                refs.iter()
                    .map(|r| render_enricher_reference(r, result))
                    .collect(),
            ),
            Shape::JsonPath(parts) => Job::JsonPath(render_jsonpath(parts, |reference| {
                render_enricher_reference(reference, result)
            })),
        };
        run_on_blocking_pool(job, data, timeout).await
    }
}

fn compiled(expr: ExtractExpr, refs: Vec<String>) -> Result<Shape, String> {
    let names: Vec<String> = (0..refs.len()).map(var_name).collect();
    Ok(Shape::Compiled {
        program: Arc::new(ExtractProgram::compile(&expr, &names)?),
        refs,
    })
}

fn var_name(index: usize) -> String {
    format!("__v{index}")
}

/// Extract evaluations that may run at once. A program that cannot be
/// interrupted keeps its slot until it finishes, so a slow one delays other
/// extracts (which then time out) rather than the blocking pool the rest
/// of the runtime uses.
static EXTRACT_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| {
    let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
    Arc::new(Semaphore::new(cpus.max(2) * 2))
});

/// Sets the flag when the evaluation's future is dropped, which is how the
/// enricher timeout reaches a running program.
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

async fn run_on_blocking_pool(job: Job, data: Value, timeout: Duration) -> Result<Value, String> {
    let cancel = Arc::new(AtomicBool::new(false));
    let _cancel_on_drop = CancelOnDrop(Arc::clone(&cancel));
    let limits = ExtractLimits::enrichment(timeout, cancel);
    let permit = Arc::clone(&EXTRACT_SLOTS)
        .acquire_owned()
        .await
        .map_err(|_| "extract slots closed".to_string())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        match job {
            Job::Compiled(program, values) => program.run(&data, values, &limits),
            Job::JsonPath(path) => ExtractProgram::compile(&ExtractExpr::JsonPath(path), &[])?.run(
                &data,
                Vec::new(),
                &limits,
            ),
        }
    })
    .await
    .map_err(|e| format!("extract evaluation failed: {e}"))?
}

/// Where a reference sits in the program text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Position {
    Code,
    /// Inside a string literal, after an unfinished escape (`\`).
    Escaped,
    String,
    Comment,
}

/// Walk `text`, calling `lit` for every run of literal text and `reference`
/// for every `${...}` reference, in order. Environment references are
/// resolved here and passed on as literal text.
fn walk_template(
    text: &str,
    mut lit: impl FnMut(&str) -> Result<(), String>,
    mut reference: impl FnMut(&str, &str) -> Result<(), String>,
) -> Result<(), String> {
    let mut pos = 0;
    for (range, r) in template_refs(text) {
        lit(&text[pos..range.start])?;
        match r {
            TemplateRef::Env(name) => lit(&std::env::var(name).unwrap_or_default())?,
            TemplateRef::Result(inner) => reference(inner, &text[range.clone()])?,
        }
        pos = range.end;
    }
    lit(&text[pos..])
}

fn escaped_reference(whole: &str) -> String {
    format!("reference '{whole}' follows a backslash inside a string literal")
}

// ---------------------------------------------------------------------------
// jq
// ---------------------------------------------------------------------------

/// jq lexer state, enough to tell code, string literals (with `\(...)`
/// interpolation), and comments apart.
#[derive(Default)]
struct JqLexer {
    /// Innermost last. Empty means top-level code.
    stack: Vec<JqState>,
    escape: bool,
    /// Open parentheses in the innermost code context.
    depth: usize,
    depths: Vec<usize>,
}

enum JqState {
    String,
    /// Code inside `\( ... )`.
    Interpolation,
    Comment,
}

impl JqLexer {
    fn position(&self) -> Position {
        match self.stack.last() {
            Some(JqState::String) if self.escape => Position::Escaped,
            Some(JqState::String) => Position::String,
            Some(JqState::Comment) => Position::Comment,
            Some(JqState::Interpolation) | None => Position::Code,
        }
    }

    fn feed(&mut self, text: &str) {
        for c in text.chars() {
            match self.stack.last() {
                Some(JqState::String) => {
                    if self.escape {
                        self.escape = false;
                        if c == '(' {
                            self.stack.push(JqState::Interpolation);
                            self.depths.push(self.depth);
                            self.depth = 0;
                        }
                    } else if c == '\\' {
                        self.escape = true;
                    } else if c == '"' {
                        self.stack.pop();
                    }
                }
                Some(JqState::Comment) => {
                    if c == '\n' {
                        self.stack.pop();
                    }
                }
                Some(JqState::Interpolation) | None => match c {
                    '"' => self.stack.push(JqState::String),
                    '#' => self.stack.push(JqState::Comment),
                    '(' => self.depth += 1,
                    ')' if self.depth == 0 => {
                        if matches!(self.stack.last(), Some(JqState::Interpolation)) {
                            self.stack.pop();
                            self.depth = self.depths.pop().unwrap_or(0);
                        }
                    }
                    ')' => self.depth -= 1,
                    _ => {}
                },
            }
        }
    }
}

/// Rewrite a jq program so each reference reads a variable.
fn rewrite_jq(code: &str) -> Result<(String, Vec<String>), String> {
    let lexer = std::cell::RefCell::new(JqLexer::default());
    let out = std::cell::RefCell::new(String::with_capacity(code.len()));
    let mut refs = Vec::new();
    walk_template(
        code,
        |text| {
            lexer.borrow_mut().feed(text);
            out.borrow_mut().push_str(text);
            Ok(())
        },
        |inner, whole| {
            let var = var_name(refs.len());
            let mut out = out.borrow_mut();
            match lexer.borrow().position() {
                Position::Code => out.push_str(&format!(" ${var} ")),
                Position::String => out.push_str(&format!("\\(${var})")),
                Position::Comment => {
                    out.push_str(whole);
                    return Ok(());
                }
                Position::Escaped => return Err(escaped_reference(whole)),
            }
            refs.push(inner.to_string());
            Ok(())
        },
    )?;
    Ok((out.into_inner(), refs))
}

// ---------------------------------------------------------------------------
// CEL
// ---------------------------------------------------------------------------

/// An open CEL string literal.
struct CelString {
    /// The quote: `"`, `'`, `"""`, or `'''`.
    quote: &'static str,
    /// The prefix letters (`r`, `b`, ...) as written.
    prefix: String,
    raw: bool,
    bytes: bool,
    /// Offset in the output where the literal, prefix included, starts.
    start: usize,
    /// Whether a reference split the literal.
    split: bool,
    escape: bool,
}

#[derive(Default)]
struct CelRewriter {
    out: String,
    string: Option<CelString>,
    comment: bool,
}

impl CelRewriter {
    fn position(&self) -> Position {
        match &self.string {
            Some(s) if s.escape => Position::Escaped,
            Some(_) => Position::String,
            None if self.comment => Position::Comment,
            None => Position::Code,
        }
    }

    fn feed(&mut self, text: &str) {
        let mut rest = text;
        while let Some(c) = rest.chars().next() {
            let len = c.len_utf8();
            if let Some(s) = &mut self.string {
                if s.escape {
                    s.escape = false;
                } else if c == '\\' && !s.raw {
                    s.escape = true;
                } else if rest.starts_with(s.quote) {
                    self.out.push_str(s.quote);
                    rest = &rest[s.quote.len()..];
                    let s = self.string.take().expect("open string");
                    if s.split {
                        self.out.insert(s.start, '(');
                        self.out.push(')');
                    }
                    continue;
                }
            } else if self.comment {
                if c == '\n' {
                    self.comment = false;
                }
            } else if rest.starts_with("//") {
                self.comment = true;
            } else if c == '"' || c == '\'' {
                let quote = match (c, rest.starts_with("\"\"\""), rest.starts_with("'''")) {
                    ('"', true, _) => "\"\"\"",
                    ('\'', _, true) => "'''",
                    ('"', _, _) => "\"",
                    _ => "'",
                };
                let prefix = self.string_prefix();
                self.string = Some(CelString {
                    quote,
                    raw: prefix.contains(['r', 'R']),
                    bytes: prefix.contains(['b', 'B']),
                    start: self.out.len() - prefix.len(),
                    prefix,
                    split: false,
                    escape: false,
                });
                self.out.push_str(quote);
                rest = &rest[quote.len()..];
                continue;
            }
            self.out.push(c);
            rest = &rest[len..];
        }
    }

    /// The `r`/`b` prefix letters written just before a quote.
    fn string_prefix(&self) -> String {
        let tail: String = self
            .out
            .chars()
            .rev()
            .take_while(|c| matches!(c, 'r' | 'R' | 'b' | 'B'))
            .take(3)
            .collect();
        let before = self.out[..self.out.len() - tail.len()].chars().next_back();
        if tail.len() > 2 || before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
            return String::new();
        }
        tail.chars().rev().collect()
    }

    fn reference(&mut self, var: &str, whole: &str) -> Result<bool, String> {
        match self.position() {
            Position::Code => {
                if self.out.trim_end().ends_with('.') {
                    return Err(format!(
                        "reference '{whole}' follows '.'; select a field by value with [{whole}] instead"
                    ));
                }
                self.out.push_str(&format!(" {var} "));
            }
            Position::String => {
                let s = self.string.as_mut().expect("open string");
                if s.bytes {
                    return Err(format!(
                        "reference '{whole}' sits inside a bytes literal; references are strings"
                    ));
                }
                s.split = true;
                let reopen = format!("{} + {var} + {}{}", s.quote, s.prefix, s.quote);
                self.out.push_str(&reopen);
            }
            Position::Comment => {
                self.out.push_str(whole);
                return Ok(false);
            }
            Position::Escaped => return Err(escaped_reference(whole)),
        }
        Ok(true)
    }
}

/// Rewrite a CEL program so each reference reads a variable.
fn rewrite_cel(code: &str) -> Result<(String, Vec<String>), String> {
    let rewriter = std::cell::RefCell::new(CelRewriter::default());
    let mut refs = Vec::new();
    walk_template(
        code,
        |text| {
            rewriter.borrow_mut().feed(text);
            Ok(())
        },
        |inner, whole| {
            if rewriter
                .borrow_mut()
                .reference(&var_name(refs.len()), whole)?
            {
                refs.push(inner.to_string());
            }
            Ok(())
        },
    )?;
    Ok((rewriter.into_inner().out, refs))
}

// ---------------------------------------------------------------------------
// JSONPath
// ---------------------------------------------------------------------------

/// Split a JSONPath query into literal text and references, recording the
/// quote each reference is encoded for.
fn split_jsonpath(path: &str) -> Result<Vec<JsonPathPart>, String> {
    let quote: std::cell::Cell<Option<char>> = std::cell::Cell::new(None);
    let escape = std::cell::Cell::new(false);
    let parts = std::cell::RefCell::new(Vec::new());
    walk_template(
        path,
        |text| {
            for c in text.chars() {
                match quote.get() {
                    Some(_) if escape.get() => escape.set(false),
                    Some(_) if c == '\\' => escape.set(true),
                    Some(q) if c == q => quote.set(None),
                    Some(_) => {}
                    None if c == '\'' || c == '"' => quote.set(Some(c)),
                    None => {}
                }
            }
            parts
                .borrow_mut()
                .push(JsonPathPart::Text(text.to_string()));
            Ok(())
        },
        |inner, whole| {
            if escape.get() {
                return Err(escaped_reference(whole));
            }
            parts.borrow_mut().push(JsonPathPart::Value {
                reference: inner.to_string(),
                quote: quote.get().unwrap_or('\''),
                bare: quote.get().is_none(),
            });
            Ok(())
        },
    )?;
    Ok(parts.into_inner())
}

fn render_jsonpath(parts: &[JsonPathPart], mut value: impl FnMut(&str) -> String) -> String {
    let mut out = String::new();
    for part in parts {
        match part {
            JsonPathPart::Text(text) => out.push_str(text),
            JsonPathPart::Value {
                reference,
                quote,
                bare,
            } => {
                let escaped = jsonpath_escape(&value(reference), *quote);
                if *bare {
                    out.push(*quote);
                    out.push_str(&escaped);
                    out.push(*quote);
                } else {
                    out.push_str(&escaped);
                }
            }
        }
    }
    out
}

/// Escape `value` for the inside of a JSONPath string literal quoted with
/// `quote` (RFC 9535, section 2.3.1.1).
fn jsonpath_escape(value: &str, quote: char) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jq_references_become_variables() {
        assert_eq!(
            rewrite_jq(r#".[] | select(.ip == "${detection.fields.Ip}")"#).unwrap(),
            (
                r#".[] | select(.ip == "\($__v0)")"#.to_string(),
                vec!["detection.fields.Ip".to_string()]
            )
        );
        assert_eq!(
            rewrite_jq(r#".[${detection.fields.Key}] # ${detection.fields.Ignored}"#)
                .unwrap()
                .0,
            r#".[ $__v0 ] # ${detection.fields.Ignored}"#
        );
        assert_eq!(
            rewrite_jq(r#""a\("b${detection.fields.X}" + "c")${detection.fields.Y}""#)
                .unwrap()
                .0,
            r#""a\("b\($__v0)" + "c")\($__v1)""#
        );
        assert!(rewrite_jq(r#""\${detection.fields.X}""#).is_err());
        assert_eq!(
            rewrite_jq(r#""\\${detection.fields.X}""#).unwrap().0,
            r#""\\\($__v0)""#
        );
    }

    #[test]
    fn cel_string_literals_are_split() {
        assert_eq!(
            rewrite_cel("data.filter(x, x.ip == '${detection.fields.Ip}')")
                .unwrap()
                .0,
            "data.filter(x, x.ip == ('' + __v0 + ''))"
        );
        assert_eq!(
            rewrite_cel(r#""a${detection.fields.X}b".size()"#)
                .unwrap()
                .0,
            r#"("a" + __v0 + "b").size()"#
        );
        assert_eq!(
            rewrite_cel(r#"r"a\${detection.fields.X}""#).unwrap().0,
            r#"(r"a\" + __v0 + r"")"#
        );
        assert_eq!(
            rewrite_cel(r#"'''x${detection.fields.X}''' // ${detection.fields.Y}"#)
                .unwrap()
                .0,
            r#"('''x''' + __v0 + '''''') // ${detection.fields.Y}"#
        );
        assert_eq!(
            rewrite_cel("data[${detection.fields.Key}]").unwrap().0,
            "data[ __v0 ]"
        );
        assert!(rewrite_cel("data.${detection.fields.Key}").is_err());
        assert!(rewrite_cel(r#"b"${detection.fields.Key}""#).is_err());
        assert!(rewrite_cel(r#""\${detection.fields.Key}""#).is_err());
    }

    #[test]
    fn jsonpath_values_are_quoted_literals() {
        let parts =
            split_jsonpath("$[?@.ip == '${detection.fields.Ip}' || @.n == ${detection.fields.N}]")
                .unwrap();
        let rendered = render_jsonpath(&parts, |r| match r {
            "detection.fields.Ip" => "a'b\\c\n".to_string(),
            _ => "x\"y".to_string(),
        });
        assert_eq!(rendered, r#"$[?@.ip == 'a\'b\\c\n' || @.n == 'x"y']"#);
        let parts = split_jsonpath(r#"$["${detection.fields.K}"]"#).unwrap();
        assert_eq!(
            render_jsonpath(&parts, |_| "q\"'".to_string()),
            r#"$["q\"'"]"#
        );
        assert!(split_jsonpath(r"$['\${detection.fields.K}']").is_err());
    }

    #[test]
    fn a_jsonpath_reference_outside_a_literal_position_is_rejected() {
        let err = ExtractTemplate::new(
            &ExtractExpr::JsonPath("$.${detection.fields.Name}".into()),
            true,
        )
        .err()
        .unwrap();
        assert!(err.contains("JSONPath literal"), "{err}");
    }

    #[test]
    fn env_references_are_substituted_at_build_time() {
        // SAFETY: the variable name is unique to this test.
        unsafe { std::env::set_var("RSIGMA_TEST_EXTRACT_KEY", "assets") };
        assert_eq!(
            rewrite_jq(r#".${RSIGMA_TEST_EXTRACT_KEY}["${detection.fields.Host}"]"#)
                .unwrap()
                .0,
            r#".assets["\($__v0)"]"#
        );
    }

    #[test]
    fn untemplated_programs_keep_their_text() {
        assert!(
            ExtractTemplate::new(&ExtractExpr::Jq(r#""${detection.fields.X}""#.into()), false)
                .is_ok()
        );
    }
}
