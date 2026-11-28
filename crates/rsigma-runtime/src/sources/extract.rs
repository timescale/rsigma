//! Expression-based data extraction for dynamic sources and enrichers.
//!
//! Supports three extraction languages with dual syntax:
//! - Plain string: always jq (the common case)
//! - Structured object `{ expr, type }`: explicit language selection
//!
//! Supported types: `jq` (via jaq), `jsonpath` (via jsonpath-rust), `cel` (via cel-interpreter).
//!
//! Every evaluation runs under limits: a cap on the number of
//! results, on the size of the result, and, for jq, on the generator steps
//! and the wall-clock time the program may take, so a program that never
//! stops producing values fails instead of holding a thread forever.

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rsigma_eval::pipeline::sources::ExtractExpr;

use super::{SourceError, SourceErrorKind};

/// Apply a typed extract expression to parsed source data.
///
/// The expression is compiled on every call and evaluated under the
/// dynamic-source limits: at most 10,000,000 results, 256 MiB of result,
/// 10,000,000 jq generator steps, and 60 seconds.
pub fn apply_extract(
    data: &serde_json::Value,
    expr: &ExtractExpr,
) -> Result<serde_json::Value, SourceError> {
    let extract_error = |message| SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Extract(message),
    };
    let program = ExtractProgram::compile(expr, &[]).map_err(extract_error)?;
    program
        .run(data, Vec::new(), &ExtractLimits::source())
        .map_err(extract_error)
}

/// Bounds on one extract evaluation.
#[derive(Debug, Clone)]
pub(crate) struct ExtractLimits {
    /// Most results the program may produce.
    pub(crate) max_outputs: usize,
    /// Most bytes the results may take, measured as compact JSON.
    pub(crate) max_bytes: usize,
    /// Most generator steps a jq program may take (`range`, `repeat`,
    /// `recurse`, `while`, `until`, and the definitions built on them).
    pub(crate) max_steps: u64,
    /// When a jq program must have finished.
    pub(crate) deadline: Option<Instant>,
    /// Set by the caller to stop a jq program at its next step or result.
    pub(crate) cancel: Option<Arc<AtomicBool>>,
}

impl ExtractLimits {
    /// Limits for extracting a dynamic source, whose data can be large.
    pub(crate) fn source() -> Self {
        Self {
            max_outputs: 10_000_000,
            max_bytes: 256 * 1024 * 1024,
            max_steps: 10_000_000,
            deadline: Some(Instant::now() + Duration::from_secs(60)),
            cancel: None,
        }
    }

    /// Limits for an enricher extract, whose result is injected into every
    /// detection or correlation it runs on.
    pub(crate) fn enrichment(timeout: Duration, cancel: Arc<AtomicBool>) -> Self {
        Self {
            max_outputs: 10_000,
            max_bytes: 1024 * 1024,
            max_steps: 1_000_000,
            deadline: Instant::now().checked_add(timeout),
            cancel: Some(cancel),
        }
    }
}

/// A compiled extract program.
///
/// A program may read string variables named at compile time: `$name` in
/// jq, `name` in CEL. JSONPath has no variables.
pub(crate) struct ExtractProgram {
    compiled: Compiled,
    vars: usize,
}

enum Compiled {
    Jq(jaq_core::Filter<jaq_core::data::JustLut<jaq_json::Val>>),
    JsonPath(jsonpath_rust::parser::model::JpQuery),
    Cel {
        program: cel::Program,
        names: Vec<String>,
    },
}

impl ExtractProgram {
    /// Compile `expr`. `vars` names the string variables the program may
    /// read, in the order [`ExtractProgram::run`] receives their values.
    pub(crate) fn compile(expr: &ExtractExpr, vars: &[String]) -> Result<Self, String> {
        let compiled = match expr {
            ExtractExpr::Jq(code) => Compiled::Jq(compile_jq(code, vars)?),
            ExtractExpr::JsonPath(path) => {
                if !vars.is_empty() {
                    return Err("JSONPath has no variables".to_string());
                }
                Compiled::JsonPath(
                    jsonpath_rust::parser::parse_json_path(path)
                        .map_err(|e| format!("invalid JSONPath expression: {e}"))?,
                )
            }
            ExtractExpr::Cel(code) => Compiled::Cel {
                program: cel::Program::compile(code)
                    .map_err(|e| format!("invalid CEL expression: {e}"))?,
                names: vars.to_vec(),
            },
        };
        Ok(Self {
            compiled,
            vars: vars.len(),
        })
    }

    /// Evaluate the program against `data` with `values` bound to its
    /// variables. Zero results is `null`, one is the value itself, and more
    /// are an array.
    pub(crate) fn run(
        &self,
        data: &serde_json::Value,
        values: Vec<String>,
        limits: &ExtractLimits,
    ) -> Result<serde_json::Value, String> {
        if values.len() != self.vars {
            return Err(format!(
                "extract expects {} values, got {}",
                self.vars,
                values.len()
            ));
        }
        let mut sink = ResultSink::new(limits);
        match &self.compiled {
            Compiled::Jq(filter) => run_jq(filter, data, values, limits, &mut sink)?,
            Compiled::JsonPath(query) => {
                let refs = jsonpath_rust::query::js_path_process(query, data)
                    .map_err(|e| format!("invalid JSONPath expression: {e}"))?;
                for r in refs {
                    sink.push(r.val.clone())?;
                }
            }
            Compiled::Cel { program, names } => {
                let mut context = cel::Context::default();
                let _ = context.add_variable("data", json_to_cel(data));
                for (name, value) in names.iter().zip(values) {
                    let _ = context.add_variable(name.as_str(), value);
                }
                let result = program
                    .execute(&context)
                    .map_err(|e| format!("CEL execution error: {e}"))?;
                return sink.single(cel_to_json(&result));
            }
        }
        Ok(sink.finish())
    }
}

/// Collects results and enforces the output-count and size limits.
struct ResultSink {
    values: Vec<serde_json::Value>,
    max_outputs: usize,
    bytes_left: usize,
    max_bytes: usize,
}

impl ResultSink {
    fn new(limits: &ExtractLimits) -> Self {
        Self {
            values: Vec::new(),
            max_outputs: limits.max_outputs,
            bytes_left: limits.max_bytes,
            max_bytes: limits.max_bytes,
        }
    }

    fn reserve_output(&self) -> Result<(), String> {
        if self.values.len() >= self.max_outputs {
            return Err(format!(
                "extract produced more than {} results",
                self.max_outputs
            ));
        }
        Ok(())
    }

    fn charge(&mut self, value: &serde_json::Value) -> Result<(), String> {
        if !charge_json(value, &mut self.bytes_left) {
            return Err(self.too_large());
        }
        Ok(())
    }

    fn too_large(&self) -> String {
        format!("extract result exceeded {} bytes", self.max_bytes)
    }

    fn push(&mut self, value: serde_json::Value) -> Result<(), String> {
        self.reserve_output()?;
        self.charge(&value)?;
        self.values.push(value);
        Ok(())
    }

    fn single(mut self, value: serde_json::Value) -> Result<serde_json::Value, String> {
        self.charge(&value)?;
        Ok(value)
    }

    fn finish(mut self) -> serde_json::Value {
        match self.values.len() {
            0 => serde_json::Value::Null,
            1 => self.values.pop().unwrap_or(serde_json::Value::Null),
            _ => serde_json::Value::Array(self.values),
        }
    }
}

/// Subtract the compact-JSON size of `value` from `budget`. Returns `false`
/// once the budget runs out.
fn charge_json(value: &serde_json::Value, budget: &mut usize) -> bool {
    let cost = match value {
        serde_json::Value::Null => 4,
        serde_json::Value::Bool(_) => 5,
        serde_json::Value::Number(_) => 8,
        serde_json::Value::String(s) => s.len() + 2,
        serde_json::Value::Array(items) => items.len() + 2,
        serde_json::Value::Object(map) => map.keys().map(|k| k.len() + 4).sum::<usize>() + 2,
    };
    let Some(left) = budget.checked_sub(cost) else {
        return false;
    };
    *budget = left;
    match value {
        serde_json::Value::Array(items) => items.iter().all(|v| charge_json(v, budget)),
        serde_json::Value::Object(map) => map.values().all(|v| charge_json(v, budget)),
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// jq
// ---------------------------------------------------------------------------

type JqData = jaq_core::data::JustLut<jaq_json::Val>;

/// Native filters a program may not call: `env` reads the process
/// environment, `halt` ends the process, and `stderr_empty` writes to the
/// daemon's stderr outside its logs.
const EXCLUDED_NATIVES: &[&str] = &["env", "halt", "stderr_empty"];

/// Standard-library definitions built on the excluded natives.
const EXCLUDED_DEFS: &[&str] = &["halt", "halt_error", "stderr"];

const TICK: &str = "__rsigma_tick";
const NATIVE_RANGE: &str = "__rsigma_range";

/// Generator definitions that charge one step per value, replacing the
/// standard ones so `limit`, `first`, and friends keep their meaning while
/// an unbounded generator stops at the step limit or the deadline.
const COUNTED_DEFS: &str = r#"
def range($from; $upto; $by): __rsigma_range($from; $upto; $by) | __rsigma_tick;
def repeat(f): def rec: f, (__rsigma_tick as $_ | rec); rec;
def recurse(f): def rec: ., (f | __rsigma_tick as $_ | rec); rec;
def while(cond; update): def rec: if cond then ., (update | __rsigma_tick as $_ | rec) else empty end; rec;
def until(cond; update): def rec: if cond then . else update | __rsigma_tick as $_ | rec end; rec;
"#;

static COUNTED: std::sync::LazyLock<Vec<jaq_core::load::parse::Def<&'static str>>> =
    std::sync::LazyLock::new(|| {
        jaq_core::load::parse(COUNTED_DEFS, |p| p.defs()).unwrap_or_default()
    });

/// The prelude every extract program compiles against: the jaq core,
/// standard, and JSON definitions, with the generators counted and the
/// definitions over excluded natives removed.
fn jq_defs() -> impl Iterator<Item = jaq_core::load::parse::Def<&'static str>> {
    let counted = &*COUNTED;
    let replacement = |def: &jaq_core::load::parse::Def<&'static str>| {
        counted
            .iter()
            .find(|c| c.name == def.name && c.args.len() == def.args.len())
            .cloned()
    };
    let range = counted.iter().find(|c| c.name == "range").cloned();
    let core: Vec<_> = jaq_core::defs()
        .map(|def| replacement(&def).unwrap_or(def))
        .collect();
    range
        .into_iter()
        .chain(core)
        .chain(jaq_std::defs())
        .chain(jaq_json::defs())
        .filter(|def| !EXCLUDED_DEFS.contains(&def.name))
}

fn jq_funs() -> impl Iterator<Item = jaq_core::native::Fun<JqData>> {
    jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs())
        .filter(|(name, _, _)| !EXCLUDED_NATIVES.contains(name))
        .map(|(name, args, native)| {
            let name = if name == "range" { NATIVE_RANGE } else { name };
            (name, args, native)
        })
        .chain([jaq_core::native::run::<JqData>((
            TICK,
            jaq_core::native::v(0),
            tick as jaq_core::RunPtr<JqData>,
        ))])
}

/// Compile a jq program whose `vars` are bound as `$name`.
///
/// A definition that calls itself, directly or through a nested
/// definition, is rejected, because a recursive definition can loop
/// without producing a value and nothing could stop it.
fn compile_jq(code: &str, vars: &[String]) -> Result<jaq_core::Filter<JqData>, String> {
    use jaq_core::load::{Arena, File, Loader};

    if let Some(term) = jaq_core::load::parse(code, |p| p.term())
        && let Some(name) = recursive_def(&term, &mut Vec::new())
    {
        return Err(format!(
            "jq definition '{name}' calls itself; recursive definitions are not supported in extract programs"
        ));
    }

    let arena = Arena::default();
    let modules = Loader::new(jq_defs())
        .load(&arena, File { code, path: () })
        .map_err(|_| format!("invalid jq expression: {code}"))?;
    let names: Vec<String> = vars.iter().map(|v| format!("${v}")).collect();
    jaq_core::Compiler::default()
        .with_funs(jq_funs())
        .with_global_vars(names.iter().map(String::as_str))
        .compile(modules)
        .map_err(|_| format!("jq compile error in: {code}"))
}

/// The first definition in `term` whose body calls a definition that is
/// still being defined. jq resolves names lexically and has no forward
/// references, so every recursion passes through such a call.
fn recursive_def<'s>(
    term: &jaq_core::load::parse::Term<&'s str>,
    open: &mut Vec<&'s str>,
) -> Option<&'s str> {
    use jaq_core::load::lex::StrPart;
    use jaq_core::load::parse::{BinaryOp, Term};
    use jaq_core::path::Part;

    let walk = |t: &Term<&'s str>, open: &mut Vec<&'s str>| recursive_def(t, open);
    match term {
        Term::Id | Term::Recurse | Term::Num(_) | Term::Var(_) | Term::Break(_) => None,
        Term::Str(_, parts) => parts.iter().find_map(|part| match part {
            StrPart::Term(t) => walk(t, open),
            _ => None,
        }),
        Term::Arr(inner) => inner.as_deref().and_then(|t| walk(t, open)),
        Term::Obj(entries) => entries
            .iter()
            .find_map(|(k, v)| walk(k, open).or_else(|| v.as_ref().and_then(|v| walk(v, open)))),
        Term::Neg(t) | Term::Label(_, t) => walk(t, open),
        Term::BinOp(l, op, r) => walk(l, open)
            .or_else(|| match op {
                BinaryOp::Pipe(Some(pattern)) => recursive_pattern(pattern, open),
                _ => None,
            })
            .or_else(|| walk(r, open)),
        Term::Fold(_, xs, pattern, args) => walk(xs, open)
            .or_else(|| recursive_pattern(pattern, open))
            .or_else(|| args.iter().find_map(|t| walk(t, open))),
        Term::TryCatch(t, catch) => {
            walk(t, open).or_else(|| catch.as_deref().and_then(|c| walk(c, open)))
        }
        Term::IfThenElse(branches, otherwise) => branches
            .iter()
            .find_map(|(cond, then)| walk(cond, open).or_else(|| walk(then, open)))
            .or_else(|| otherwise.as_deref().and_then(|t| walk(t, open))),
        Term::Def(defs, body) => defs
            .iter()
            .find_map(|def| {
                open.push(def.name);
                let found = walk(&def.body, open);
                open.pop();
                found
            })
            .or_else(|| walk(body, open)),
        Term::Call(name, args) => open
            .contains(name)
            .then_some(*name)
            .or_else(|| args.iter().find_map(|t| walk(t, open))),
        Term::Path(t, path) => walk(t, open).or_else(|| {
            path.0.iter().find_map(|(part, _)| match part {
                Part::Index(i) => walk(i, open),
                Part::Range(from, upto) => from
                    .as_ref()
                    .and_then(|t| walk(t, open))
                    .or_else(|| upto.as_ref().and_then(|t| walk(t, open))),
            })
        }),
    }
}

fn recursive_pattern<'s>(
    pattern: &jaq_core::load::parse::Pattern<&'s str>,
    open: &mut Vec<&'s str>,
) -> Option<&'s str> {
    use jaq_core::load::parse::Pattern;
    match pattern {
        Pattern::Var(_) => None,
        Pattern::Arr(items) => items.iter().find_map(|p| recursive_pattern(p, open)),
        Pattern::Obj(entries) => entries
            .iter()
            .find_map(|(k, p)| recursive_def(k, open).or_else(|| recursive_pattern(p, open))),
    }
}

fn run_jq(
    filter: &jaq_core::Filter<JqData>,
    data: &serde_json::Value,
    values: Vec<String>,
    limits: &ExtractLimits,
    sink: &mut ResultSink,
) -> Result<(), String> {
    use jaq_core::{Ctx, Vars};

    let input = json_to_val(data.clone());
    let vars = Vars::new(values.into_iter().map(jaq_json::Val::from));
    let ctx = Ctx::<JqData>::new(&filter.lut, vars);
    let budget = Budget::install(limits);
    let mut outcome = Ok(());
    for r in filter.id.run((ctx, input)) {
        if let Err(stop) = budget.check() {
            outcome = Err(stop);
            break;
        }
        let value = match r {
            Ok(value) => value,
            Err(exn) => {
                outcome = Err(match exn.get_err() {
                    Ok(e) => format!("jq execution error: {e}"),
                    Err(_) => "jq execution error: the program stopped".to_string(),
                });
                break;
            }
        };
        if let Err(e) = sink.reserve_output() {
            outcome = Err(e);
            break;
        }
        let mut left = sink.bytes_left;
        let Some(json) = val_to_json(&value, &mut left) else {
            outcome = Err(sink.too_large());
            break;
        };
        sink.bytes_left = left;
        sink.values.push(json);
    }
    // A limit reported as a jq error may have been caught by the program
    // (`try`, `?`, `//`); the limit wins either way.
    budget.exceeded().map_or(outcome, Err)
}

/// Step and time budget for the jq program running on this thread.
struct BudgetState {
    steps_left: u64,
    max_steps: u64,
    deadline: Option<Instant>,
    cancel: Option<Arc<AtomicBool>>,
    exceeded: Option<String>,
}

thread_local! {
    static BUDGET: RefCell<Option<BudgetState>> = const { RefCell::new(None) };
}

/// Installs a budget for the current thread and removes it on drop.
struct Budget;

/// Steps between two reads of the clock.
const CLOCK_EVERY: u64 = 1024;

impl Budget {
    fn install(limits: &ExtractLimits) -> Self {
        BUDGET.with(|b| {
            *b.borrow_mut() = Some(BudgetState {
                steps_left: limits.max_steps,
                max_steps: limits.max_steps,
                deadline: limits.deadline,
                cancel: limits.cancel.clone(),
                exceeded: None,
            });
        });
        Budget
    }

    /// Check the deadline and cancellation between two results.
    fn check(&self) -> Result<(), String> {
        BUDGET.with(|b| match b.borrow_mut().as_mut() {
            Some(state) => state.check_time(),
            None => Ok(()),
        })
    }

    fn exceeded(&self) -> Option<String> {
        BUDGET.with(|b| b.borrow().as_ref().and_then(|s| s.exceeded.clone()))
    }
}

impl Drop for Budget {
    fn drop(&mut self) {
        BUDGET.with(|b| *b.borrow_mut() = None);
    }
}

impl BudgetState {
    fn check_time(&mut self) -> Result<(), String> {
        if let Some(stop) = &self.exceeded {
            return Err(stop.clone());
        }
        let stop = if self
            .cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
        {
            Some("extract was cancelled after its enricher timed out".to_string())
        } else if self.deadline.is_some_and(|d| Instant::now() >= d) {
            Some("extract exceeded its time limit".to_string())
        } else {
            None
        };
        match stop {
            Some(stop) => {
                self.exceeded = Some(stop.clone());
                Err(stop)
            }
            None => Ok(()),
        }
    }

    fn step(&mut self) -> Result<(), String> {
        if let Some(stop) = &self.exceeded {
            return Err(stop.clone());
        }
        if self.steps_left == 0 {
            let stop = format!("extract exceeded {} generator steps", self.max_steps);
            self.exceeded = Some(stop.clone());
            return Err(stop);
        }
        self.steps_left -= 1;
        if self.steps_left.is_multiple_of(CLOCK_EVERY) {
            self.check_time()?;
        }
        Ok(())
    }
}

/// `__rsigma_tick`: pass the input through, charging one step.
fn tick<'a>(cv: jaq_core::Cv<'a, JqData>) -> jaq_core::ValXs<'a, jaq_json::Val> {
    let charged = BUDGET.with(|b| match b.borrow_mut().as_mut() {
        Some(state) => state.step(),
        None => Ok(()),
    });
    jaq_core::native::bome(charged.map(|()| cv.1).map_err(jaq_core::Error::str))
}

// ---------------------------------------------------------------------------
// CEL
// ---------------------------------------------------------------------------

/// Convert a serde_json::Value to a cel::Value.
fn json_to_cel(json: &serde_json::Value) -> cel::Value {
    match json {
        serde_json::Value::Null => cel::Value::Null,
        serde_json::Value::Bool(b) => (*b).into(),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into()
            } else if let Some(u) = n.as_u64() {
                u.into()
            } else if let Some(f) = n.as_f64() {
                f.into()
            } else {
                cel::Value::Null
            }
        }
        serde_json::Value::String(s) => s.as_str().into(),
        serde_json::Value::Array(arr) => {
            let items: Vec<cel::Value> = arr.iter().map(json_to_cel).collect();
            items.into()
        }
        serde_json::Value::Object(map) => {
            let cel_map: std::collections::HashMap<cel::objects::Key, cel::Value> = map
                .iter()
                .map(|(k, v)| (k.as_str().into(), json_to_cel(v)))
                .collect();
            cel_map.into()
        }
    }
}

/// Convert a cel::Value back to serde_json::Value.
fn cel_to_json(val: &cel::Value) -> serde_json::Value {
    match val {
        cel::Value::Null => serde_json::Value::Null,
        cel::Value::Bool(b) => serde_json::Value::Bool(*b),
        cel::Value::Int(i) => serde_json::json!(i),
        cel::Value::UInt(u) => serde_json::json!(u),
        cel::Value::Float(f) => serde_json::json!(f),
        cel::Value::String(s) => serde_json::Value::String(s.to_string()),
        cel::Value::List(list) => {
            let arr: Vec<serde_json::Value> = list.iter().map(cel_to_json).collect();
            serde_json::Value::Array(arr)
        }
        cel::Value::Map(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map.map.iter() {
                let key = match k {
                    cel::objects::Key::String(s) => s.to_string(),
                    cel::objects::Key::Int(i) => i.to_string(),
                    cel::objects::Key::Uint(u) => u.to_string(),
                    cel::objects::Key::Bool(b) => b.to_string(),
                };
                obj.insert(key, cel_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::String(format!("{val:?}")),
    }
}

// ---------------------------------------------------------------------------
// jaq values
// ---------------------------------------------------------------------------

/// Convert a `serde_json::Value` to a jaq `Val`.
fn json_to_val(v: serde_json::Value) -> jaq_json::Val {
    use jaq_core::ValT;
    use jaq_json::Val;

    match v {
        serde_json::Value::Null => Val::Null,
        serde_json::Value::Bool(b) => Val::Bool(b),
        serde_json::Value::Number(n) => Val::from_num(&n.to_string()).unwrap_or(Val::Null),
        serde_json::Value::String(s) => Val::from(s),
        serde_json::Value::Array(arr) => arr.into_iter().map(json_to_val).collect(),
        serde_json::Value::Object(obj) => Val::obj(
            obj.into_iter()
                .map(|(k, v)| (Val::from(k), json_to_val(v)))
                .collect(),
        ),
    }
}

/// Convert a jaq `Val` to a `serde_json::Value`, charging its size to
/// `budget`. Returns `None` once the budget runs out.
///
/// Byte and text strings are decoded with lossy UTF-8 conversion. Non-string
/// object keys are stringified via their Display impl so they round-trip into
/// JSON keys.
fn val_to_json(val: &jaq_json::Val, budget: &mut usize) -> Option<serde_json::Value> {
    use jaq_json::Val;
    use jaq_std::ValT;

    let mut charge = |cost: usize| {
        *budget = budget.checked_sub(cost)?;
        Some(())
    };
    Some(match val {
        Val::Null => {
            charge(4)?;
            serde_json::Value::Null
        }
        Val::Bool(b) => {
            charge(5)?;
            serde_json::Value::Bool(*b)
        }
        Val::Num(_) => {
            charge(8)?;
            if let Some(i) = val.as_isize() {
                serde_json::json!(i)
            } else if let Some(f) = val.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or_else(|| serde_json::Value::String(val.to_string()))
            } else {
                serde_json::Value::String(val.to_string())
            }
        }
        Val::BStr(b) | Val::TStr(b) => {
            charge(b.len() + 2)?;
            serde_json::Value::String(String::from_utf8_lossy(b).into_owned())
        }
        Val::Arr(arr) => {
            charge(arr.len() + 2)?;
            serde_json::Value::Array(
                arr.iter()
                    .map(|v| val_to_json(v, budget))
                    .collect::<Option<_>>()?,
            )
        }
        Val::Obj(obj) => {
            charge(2)?;
            let mut map = serde_json::Map::new();
            for (k, v) in obj.iter() {
                let key = match k {
                    Val::BStr(b) | Val::TStr(b) => String::from_utf8_lossy(b).into_owned(),
                    _ => k.to_string(),
                };
                *budget = budget.checked_sub(key.len() + 4)?;
                map.insert(key, val_to_json(v, budget)?);
            }
            serde_json::Value::Object(map)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jq(code: &str) -> Result<serde_json::Value, String> {
        ExtractProgram::compile(&ExtractExpr::Jq(code.to_string()), &[])?.run(
            &json!({"a": [1, 2, 3]}),
            Vec::new(),
            &ExtractLimits::source(),
        )
    }

    fn tight(timeout: Duration) -> ExtractLimits {
        ExtractLimits::enrichment(timeout, Arc::new(AtomicBool::new(false)))
    }

    #[test]
    fn every_counted_generator_replaces_a_standard_one() {
        let names: Vec<_> = COUNTED.iter().map(|d| (d.name, d.args.len())).collect();
        assert_eq!(
            names,
            [
                ("range", 3),
                ("repeat", 1),
                ("recurse", 1),
                ("while", 2),
                ("until", 2)
            ]
        );
        let core: Vec<_> = jaq_core::defs().map(|d| (d.name, d.args.len())).collect();
        for (name, arity) in names.iter().skip(1) {
            assert!(core.contains(&(*name, *arity)), "{name}/{arity}");
        }
        assert!(
            jaq_core::funs::<JqData>().any(|(name, args, _)| name == "range" && args.len() == 3)
        );
    }

    #[test]
    fn env_is_not_available() {
        for code in ["env", "env.HOME", "$ENV", "$ENV.HOME", "[env] | length"] {
            let err = jq(code).unwrap_err();
            assert!(err.contains("jq"), "{code}: {err}");
        }
    }

    #[test]
    fn halt_and_stderr_are_not_available() {
        for code in [
            "halt",
            "halt_error",
            "halt_error(1)",
            "stderr",
            "\"x\" | stderr",
        ] {
            assert!(jq(code).is_err(), "{code} compiled");
        }
    }

    #[test]
    fn standard_filters_still_work() {
        assert_eq!(jq(".a | map(. * 2)").unwrap(), json!([2, 4, 6]));
        assert_eq!(jq("[range(3)]").unwrap(), json!([0, 1, 2]));
        assert_eq!(jq("[range(0; 10; 4)]").unwrap(), json!([0, 4, 8]));
        assert_eq!(jq("[limit(3; repeat(1))]").unwrap(), json!([1, 1, 1]));
        assert_eq!(
            jq("[1 | recurse(if . < 3 then . + 1 else empty end)]").unwrap(),
            json!([1, 2, 3])
        );
        assert_eq!(jq("[1 | while(. < 4; . + 1)]").unwrap(), json!([1, 2, 3]));
        assert_eq!(jq("1 | until(. > 4; . * 2)").unwrap(), json!(8));
        assert_eq!(jq("[paths] | length").unwrap(), json!(4));
        assert_eq!(jq("[[1, [2]], 3] | flatten").unwrap(), json!([1, 2, 3]));
        assert_eq!(jq("[[1, 2] | combinations(2)] | length").unwrap(), json!(4));
        assert_eq!(
            jq("[[1, 2], [3, 4]] | [combinations] | length").unwrap(),
            json!(4)
        );
        assert_eq!(
            jq("def double: . * 2; .a | map(double)").unwrap(),
            json!([2, 4, 6])
        );
    }

    #[test]
    fn recursive_definitions_are_rejected() {
        for code in [
            "def f: f; f",
            "def f: 1, f; [limit(3; f)]",
            "def f: def g: f; g; f",
            "def f(g): g | f(g); f(.)",
            "def r: .[] | r; r",
        ] {
            let err = jq(code).unwrap_err();
            assert!(err.contains("calls itself"), "{code}: {err}");
        }
    }

    #[test]
    fn unbounded_generators_stop_at_the_step_limit() {
        for code in [
            "repeat(1)",
            "[repeat(1)] | length",
            "last(range(1e18))",
            "reduce range(1e18) as $x (0; . + 1)",
            "1 | until(false; .)",
            "[1 | recurse(. + 1)] | length",
            "[1 | while(true; .)] | length",
            "try (repeat(1)) catch 0",
            "[repeat(1)?] | length",
        ] {
            let started = Instant::now();
            let mut limits = tight(Duration::from_secs(30));
            limits.max_steps = 100_000;
            let err = ExtractProgram::compile(&ExtractExpr::Jq(code.into()), &[])
                .unwrap()
                .run(&json!(null), Vec::new(), &limits)
                .unwrap_err();
            assert!(
                err.contains("generator steps") || err.contains("more than"),
                "{code}: {err}"
            );
            assert!(started.elapsed() < Duration::from_secs(10), "{code}");
        }
    }

    #[test]
    fn a_program_stops_at_its_deadline() {
        let mut limits = tight(Duration::from_millis(50));
        limits.max_steps = u64::MAX;
        limits.max_outputs = usize::MAX;
        limits.max_bytes = usize::MAX;
        let started = Instant::now();
        let err = ExtractProgram::compile(&ExtractExpr::Jq("last(range(1e18))".into()), &[])
            .unwrap()
            .run(&json!(null), Vec::new(), &limits)
            .unwrap_err();
        assert!(err.contains("time limit"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn cancellation_stops_a_running_program() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut limits = ExtractLimits::enrichment(Duration::from_secs(3600), cancel.clone());
        limits.max_steps = u64::MAX;
        let program =
            ExtractProgram::compile(&ExtractExpr::Jq("last(range(1e18))".into()), &[]).unwrap();
        let worker = std::thread::spawn(move || program.run(&json!(null), Vec::new(), &limits));
        std::thread::sleep(Duration::from_millis(50));
        cancel.store(true, Ordering::Relaxed);
        let err = worker.join().unwrap().unwrap_err();
        assert!(err.contains("cancelled"), "{err}");
    }

    #[test]
    fn results_are_capped_by_count_and_size() {
        let limits = tight(Duration::from_secs(30));
        let many = ExtractProgram::compile(&ExtractExpr::Jq(".[]".into()), &[]).unwrap();
        let data = json!((0..20_000).collect::<Vec<_>>());
        assert!(
            many.run(&data, Vec::new(), &limits)
                .unwrap_err()
                .contains("more than 10000 results")
        );
        let big = ExtractProgram::compile(&ExtractExpr::Jq(". * 2".into()), &[]).unwrap();
        let data = json!("x".repeat(600 * 1024));
        assert!(
            big.run(&data, Vec::new(), &limits)
                .unwrap_err()
                .contains("exceeded 1048576 bytes")
        );
        let jp = ExtractProgram::compile(&ExtractExpr::JsonPath("$[*]".into()), &[]).unwrap();
        let data = json!(vec!["y".repeat(1024); 2048]);
        assert!(
            jp.run(&data, Vec::new(), &limits)
                .unwrap_err()
                .contains("bytes")
        );
        let cel = ExtractProgram::compile(&ExtractExpr::Cel("data + data".into()), &[]).unwrap();
        let data = json!("z".repeat(600 * 1024));
        assert!(
            cel.run(&data, Vec::new(), &limits)
                .unwrap_err()
                .contains("bytes")
        );
    }

    #[test]
    fn variables_are_bound_in_order() {
        let vars = ["__v0".to_string(), "__v1".to_string()];
        let program =
            ExtractProgram::compile(&ExtractExpr::Jq("[$__v0, $__v1]".into()), &vars).unwrap();
        assert_eq!(
            program
                .run(
                    &json!(null),
                    vec!["a".into(), "b".into()],
                    &ExtractLimits::source()
                )
                .unwrap(),
            json!(["a", "b"])
        );
        let program =
            ExtractProgram::compile(&ExtractExpr::Cel("[__v0, __v1]".into()), &vars).unwrap();
        assert_eq!(
            program
                .run(
                    &json!(null),
                    vec!["a".into(), "b".into()],
                    &ExtractLimits::source()
                )
                .unwrap(),
            json!(["a", "b"])
        );
    }

    #[test]
    fn a_wrong_number_of_values_is_an_error() {
        let program = ExtractProgram::compile(&ExtractExpr::Jq(".".into()), &[]).unwrap();
        assert!(
            program
                .run(&json!(1), vec!["x".into()], &ExtractLimits::source())
                .is_err()
        );
    }

    #[test]
    fn apply_extract_keeps_its_error_messages() {
        let err = apply_extract(&json!({}), &ExtractExpr::Jq("invalid[[[".into())).unwrap_err();
        assert!(
            matches!(err.kind, SourceErrorKind::Extract(m) if m.contains("invalid jq expression"))
        );
        let err =
            apply_extract(&json!({}), &ExtractExpr::JsonPath("$[invalid".into())).unwrap_err();
        assert!(matches!(err.kind, SourceErrorKind::Extract(m) if m.contains("invalid JSONPath")));
        let err = apply_extract(&json!({}), &ExtractExpr::Cel("1 +".into())).unwrap_err();
        assert!(matches!(err.kind, SourceErrorKind::Extract(m) if m.contains("invalid CEL")));
    }
}
