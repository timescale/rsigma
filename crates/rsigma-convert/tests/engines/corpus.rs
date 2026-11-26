//! Engine cases synthesized from SigmaHQ rules whose conditions need grouping.
//!
//! A rule qualifies when conversion has to parenthesize something (an OR
//! under an AND, or a compound expression under a NOT) and every value is a
//! plain string match that the engines and eval otherwise agree on, so a
//! disagreement points at grouping. Each rule gets events built from its own
//! values: one satisfying every detection at once and one per detection with
//! that detection undone, one per detection branch with that branch
//! satisfied, near misses that undo one field of a branch, and seeded random
//! mixes. Every event
//! carries every field the rule references, and the expected matches are
//! eval's.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use rsigma_eval::Engine;
use rsigma_ir::encoding::expand_encoded_detections;
use rsigma_ir::{
    IrCondition, IrDetection, IrMatcher, IrPattern, IrPatternPart, IrStrOp, LowerOptions,
    lower_rule,
};
use rsigma_parser::{Quantifier, SelectorPattern, parse_sigma_yaml};
use serde_json::{Map, Value};

use super::{Case, IDX_FIELD, eval_matches};

/// Value for a field that satisfies none of the rule's matchers.
const MISS: &str = "rsigma-near-miss";
const RANDOM_EVENTS: usize = 40;
const MAX_EVENTS: usize = 160;

/// Selected cases and how many rules each filter kept.
pub struct CorpusSample {
    pub cases: Vec<Case>,
    pub files: usize,
    pub needs_grouping: usize,
    pub plain_values: usize,
}

/// Build cases from every qualifying rule under the `rules*` directories of a
/// SigmaHQ checkout. `accept` drops rules the engine under test rejects.
pub fn grouping_cases(corpus: &Path, accept: impl Fn(&Case) -> bool) -> CorpusSample {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(corpus)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", corpus.display()))
    {
        let path = entry.unwrap().path();
        if path.is_dir()
            && path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("rules"))
        {
            collect_yaml(&path, &mut files);
        }
    }
    files.sort();
    assert!(!files.is_empty(), "no rules under {}", corpus.display());

    let mut sample = CorpusSample {
        cases: Vec::new(),
        files: files.len(),
        needs_grouping: 0,
        plain_values: 0,
    };
    for path in &files {
        let Some(rule) = Rule::load(path) else {
            continue;
        };
        if !rule.needs_grouping() {
            continue;
        }
        sample.needs_grouping += 1;
        let Some(fields) = rule.plain_fields() else {
            continue;
        };
        sample.plain_values += 1;
        let name = path
            .strip_prefix(corpus)
            .unwrap_or(path)
            .display()
            .to_string();
        let mut case = Case {
            description: String::new(),
            rule_yaml: rule.yaml.clone(),
            pipeline_yaml: None,
            reference_pipeline_yaml: None,
            logsource_category: None,
            events: rule.events(&name, &fields),
            matches: Vec::new(),
            unsupported: Vec::new(),
            known_failures: BTreeMap::new(),
            name,
        };
        case.matches = eval_matches(&case);
        if accept(&case) {
            sample.cases.push(case);
        }
    }
    sample
}

fn collect_yaml(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_yaml(&path, out);
        } else if path.extension().is_some_and(|x| x == "yml") {
            out.push(path);
        }
    }
}

struct Rule {
    yaml: String,
    detections: HashMap<String, IrDetection>,
    condition: IrCondition,
}

impl Rule {
    /// A single detection rule with one condition that eval compiles.
    fn load(path: &Path) -> Option<Self> {
        let yaml = std::fs::read_to_string(path).ok()?;
        let collection = parse_sigma_yaml(&yaml).ok()?;
        if collection.has_errors()
            || collection.rules.len() != 1
            || !collection.correlations.is_empty()
            || !collection.filters.is_empty()
        {
            return None;
        }
        Engine::new().add_collection(&collection).ok()?;
        let mut ir = lower_rule(&collection.rules[0], &LowerOptions::default()).ok()?;
        expand_encoded_detections(&mut ir.detections).ok()?;
        if ir.conditions.len() != 1 {
            return None;
        }
        Some(Self {
            yaml,
            detections: ir.detections,
            condition: ir.conditions.remove(0),
        })
    }

    fn selected(&self, pattern: &SelectorPattern) -> Vec<&IrDetection> {
        let mut names: Vec<&String> = self
            .detections
            .keys()
            .filter(|n| pattern.matches_detection_name(n))
            .collect();
        names.sort();
        names.into_iter().map(|n| &self.detections[n]).collect()
    }

    fn condition_op(&self, cond: &IrCondition) -> Option<Op> {
        match cond {
            IrCondition::Detection(name) => self.detections.get(name).and_then(detection_op),
            IrCondition::And(exprs) => list_op(exprs, Op::And, |e| self.condition_op(e)),
            IrCondition::Or(exprs) => list_op(exprs, Op::Or, |e| self.condition_op(e)),
            IrCondition::Not(_) => Some(Op::Not),
            IrCondition::Selector {
                quantifier,
                pattern,
            } => {
                let op = if matches!(quantifier, Quantifier::All) {
                    Op::And
                } else {
                    Op::Or
                };
                list_op(&self.selected(pattern), op, |d| detection_op(d))
            }
        }
    }

    fn needs_grouping(&self) -> bool {
        self.condition_needs(&self.condition)
    }

    fn condition_needs(&self, cond: &IrCondition) -> bool {
        match cond {
            IrCondition::Detection(name) => self.detections.get(name).is_some_and(detection_needs),
            IrCondition::And(exprs) => exprs
                .iter()
                .any(|e| self.condition_op(e) == Some(Op::Or) || self.condition_needs(e)),
            IrCondition::Or(exprs) => exprs.iter().any(|e| self.condition_needs(e)),
            IrCondition::Not(inner) => {
                self.condition_op(inner).is_some() || self.condition_needs(inner)
            }
            IrCondition::Selector {
                quantifier,
                pattern,
            } => {
                let dets = self.selected(pattern);
                let all = matches!(quantifier, Quantifier::All) && dets.len() > 1;
                dets.into_iter()
                    .any(|d| (all && detection_op(d) == Some(Op::Or)) || detection_needs(d))
            }
        }
    }

    /// Satisfying values per field, or `None` when a detection uses anything
    /// other than plain string matches on named fields.
    fn plain_fields(&self) -> Option<BTreeMap<String, BTreeSet<String>>> {
        let mut fields = BTreeMap::new();
        for det in self.detections.values() {
            plain_detection(det, &mut fields)?;
        }
        Some(fields)
    }

    fn events(&self, name: &str, fields: &BTreeMap<String, BTreeSet<String>>) -> Vec<Value> {
        let base: BTreeMap<String, String> = fields
            .keys()
            .map(|f| (f.clone(), MISS.to_string()))
            .collect();
        let mut events = vec![base.clone()];

        let mut names: Vec<&String> = self.detections.keys().collect();
        names.sort();
        let assign = |branch: &Branch| {
            let mut event = base.clone();
            event.extend(branch.iter().map(|(f, cs)| (f.clone(), compose(cs))));
            event
        };
        let firsts: Vec<Branch> = names
            .iter()
            .filter_map(|n| branches(&self.detections[*n]).into_iter().next())
            .collect();
        let mut all = Branch::new();
        for branch in &firsts {
            for (field, cs) in branch {
                all.entry(field.clone())
                    .or_default()
                    .extend(cs.iter().cloned());
            }
        }
        let all = assign(&all);
        for branch in &firsts {
            let mut without = all.clone();
            for field in branch.keys() {
                without.insert(field.clone(), MISS.to_string());
            }
            events.push(without);
        }
        events.push(all);

        for det in names.into_iter().map(|n| &self.detections[n]) {
            for branch in branches(det) {
                let event = assign(&branch);
                for field in branch.keys() {
                    let mut near = event.clone();
                    near.insert(field.clone(), MISS.to_string());
                    events.push(near);
                }
                events.push(event);
            }
        }

        let mut rng = Rng::new(name);
        for _ in 0..RANDOM_EVENTS {
            let event = fields
                .iter()
                .map(|(f, vs)| {
                    let v = if rng.next().is_multiple_of(2) {
                        vs.iter()
                            .nth((rng.next() as usize) % vs.len())
                            .unwrap()
                            .clone()
                    } else {
                        MISS.to_string()
                    };
                    (f.clone(), v)
                })
                .collect();
            events.push(event);
        }

        let mut seen = BTreeSet::new();
        events
            .into_iter()
            .filter(|e| seen.insert(e.clone()))
            .take(MAX_EVENTS)
            .map(|e| {
                Value::Object(
                    e.into_iter()
                        .map(|(k, v)| (k, Value::from(v)))
                        .collect::<Map<_, _>>(),
                )
            })
            .collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Not,
    And,
    Or,
}

fn list_op<T>(items: &[T], op: Op, item_op: impl Fn(&T) -> Option<Op>) -> Option<Op> {
    match items {
        [] => None,
        [only] => item_op(only),
        _ => Some(op),
    }
}

fn matcher_op(matcher: &IrMatcher) -> Option<Op> {
    match matcher {
        IrMatcher::AnyOf(ms) => list_op(ms, Op::Or, matcher_op),
        IrMatcher::AllOf(ms) => list_op(ms, Op::And, matcher_op),
        IrMatcher::Not(_) => Some(Op::Not),
        _ => None,
    }
}

fn detection_op(det: &IrDetection) -> Option<Op> {
    match det {
        IrDetection::AllOf(items) => list_op(items, Op::And, |it| matcher_op(&it.matcher)),
        IrDetection::AnyOf(dets) => list_op(dets, Op::Or, detection_op),
        IrDetection::And(dets) => list_op(dets, Op::And, detection_op),
        _ => None,
    }
}

fn matcher_needs(matcher: &IrMatcher) -> bool {
    match matcher {
        IrMatcher::Not(inner) => matcher_op(inner).is_some() || matcher_needs(inner),
        IrMatcher::AllOf(ms) => ms
            .iter()
            .any(|m| matcher_op(m) == Some(Op::Or) || matcher_needs(m)),
        IrMatcher::AnyOf(ms) => ms.iter().any(matcher_needs),
        _ => false,
    }
}

fn detection_needs(det: &IrDetection) -> bool {
    match det {
        IrDetection::AllOf(items) => {
            items.len() > 1
                && items
                    .iter()
                    .any(|it| matcher_op(&it.matcher) == Some(Op::Or))
                || items.iter().any(|it| matcher_needs(&it.matcher))
        }
        IrDetection::AnyOf(dets) => dets.iter().any(detection_needs),
        IrDetection::And(dets) => dets
            .iter()
            .any(|d| detection_op(d) == Some(Op::Or) || detection_needs(d)),
        _ => false,
    }
}

fn plain_detection(
    det: &IrDetection,
    fields: &mut BTreeMap<String, BTreeSet<String>>,
) -> Option<()> {
    match det {
        IrDetection::AllOf(items) => {
            for item in items {
                let field = item.field.as_deref()?;
                if item.exists.is_some()
                    || field.is_empty()
                    || field == IDX_FIELD
                    || field.contains(['.', '[', '\n'])
                {
                    return None;
                }
                let values = fields.entry(field.to_string()).or_default();
                plain_matcher(&item.matcher, values)?;
            }
            Some(())
        }
        IrDetection::AnyOf(dets) => dets.iter().try_for_each(|d| plain_detection(d, fields)),
        _ => None,
    }
}

/// Record values satisfying `matcher` (or its operand, for a negation).
/// Wildcards under `startswith` and `endswith` are excluded because eval
/// handles them differently from the backends for unrelated reasons.
fn plain_matcher(matcher: &IrMatcher, values: &mut BTreeSet<String>) -> Option<()> {
    match matcher {
        IrMatcher::Str { op, pattern, .. } => {
            if pattern.has_wildcards() && matches!(op, IrStrOp::StartsWith | IrStrOp::EndsWith) {
                return None;
            }
            values.insert(compose(&[(*op, body(pattern)?)]));
            Some(())
        }
        IrMatcher::AnyOf(ms) => ms.iter().try_for_each(|m| plain_matcher(m, values)),
        IrMatcher::AllOf(ms) => {
            for m in ms {
                plain_matcher(m, &mut BTreeSet::new())?;
            }
            values.insert(compose(&constraints(matcher)?));
            Some(())
        }
        IrMatcher::Not(inner) => plain_matcher(inner, values),
        _ => None,
    }
}

/// A string operator and the literal text of its pattern.
type Constraint = (IrStrOp, String);

/// Constraints per field that together satisfy one OR branch.
type Branch = BTreeMap<String, Vec<Constraint>>;

fn body(pattern: &IrPattern) -> Option<String> {
    let mut body = String::new();
    for part in &pattern.parts {
        match part {
            IrPatternPart::Literal(s) => body.push_str(s),
            IrPatternPart::WildcardMulti => body.push('x'),
            IrPatternPart::WildcardSingle => body.push('y'),
        }
    }
    (!body.contains(['\n', '\0'])).then_some(body)
}

/// One value meeting every constraint: an exact value if there is one,
/// otherwise the first prefix, every substring, and the first suffix.
fn compose(constraints: &[Constraint]) -> String {
    if let Some((_, exact)) = constraints.iter().find(|(op, _)| *op == IrStrOp::Exact) {
        return exact.clone();
    }
    let first = |want: IrStrOp| {
        constraints
            .iter()
            .find(|(op, _)| *op == want)
            .map_or("", |(_, b)| b.as_str())
    };
    let contains: Vec<&str> = constraints
        .iter()
        .filter(|(op, _)| *op == IrStrOp::Contains)
        .map(|(_, b)| b.as_str())
        .collect();
    format!(
        "{}a {} z{}",
        first(IrStrOp::StartsWith),
        contains.join(" "),
        first(IrStrOp::EndsWith)
    )
}

/// Constraints that satisfy `matcher`; `None` leaves the field at the miss
/// value, which satisfies a negation.
fn constraints(matcher: &IrMatcher) -> Option<Vec<Constraint>> {
    match matcher {
        IrMatcher::Str { op, pattern, .. } => Some(vec![(*op, body(pattern)?)]),
        IrMatcher::AnyOf(ms) => ms.first().and_then(constraints),
        IrMatcher::AllOf(ms) => {
            let mut all = Vec::new();
            for m in ms {
                all.extend(constraints(m)?);
            }
            Some(all)
        }
        _ => None,
    }
}

/// The OR branches of a detection.
fn branches(det: &IrDetection) -> Vec<Branch> {
    match det {
        IrDetection::AllOf(items) => {
            let mut branch = Branch::new();
            for item in items {
                if let (Some(field), Some(cs)) = (&item.field, constraints(&item.matcher)) {
                    branch.entry(field.clone()).or_default().extend(cs);
                }
            }
            vec![branch]
        }
        IrDetection::AnyOf(dets) => dets.iter().flat_map(branches).collect(),
        _ => Vec::new(),
    }
}

/// Deterministic per-rule generator (xorshift64 seeded with FNV-1a).
struct Rng(u64);

impl Rng {
    fn new(seed: &str) -> Self {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in seed.bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        Self(h | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}
