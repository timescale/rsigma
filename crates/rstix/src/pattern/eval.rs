//! STIX pattern evaluator (Levels 1–3).

mod observed_data;
pub use observed_data::evaluate_observed_data;

use crate::core::{QueryableStixObject, StixTimestamp};
use crate::model::Bundle;
use crate::model::sco::ScoObject;
use crate::pattern::ast::{
    Comparison, ComparisonOp, ComparisonTree, Duration, ObservationExpr, PatternAst,
    PatternConstant, PatternScoType, TimeUnit,
};
use crate::pattern::context::{ObservationContext, TimestampedObservation};
use crate::pattern::error::PatternMatchError;
use crate::pattern::lexer::MAX_OBSERVATIONS;
use crate::pattern::path::{self, FieldValue};
use crate::pattern::security;

/// Evaluate a parsed pattern against timestamped observations.
pub fn evaluate(ast: &PatternAst, ctx: &ObservationContext<'_>) -> Result<bool, PatternMatchError> {
    if ctx.observations.is_empty() {
        if requires_timestamps(ast) {
            return Err(PatternMatchError::MissingTimestamp);
        }
        return Ok(false);
    }
    ensure_observation_count(ctx)?;
    ensure_observation_timestamps(ast, ctx)?;
    eval_node(ast, ctx, None, None)
}

/// Evaluate a single observation expression against one SCO (Level 1 shortcut).
pub fn matches_single(ast: &PatternAst, sco: &ScoObject) -> Result<bool, PatternMatchError> {
    matches_single_with_bundle(ast, sco, None)
}

/// Level 1 shortcut with optional bundle for `_ref` dereference.
pub fn matches_single_with_bundle(
    ast: &PatternAst,
    sco: &ScoObject,
    bundle: Option<&Bundle>,
) -> Result<bool, PatternMatchError> {
    if !is_single_observation(ast) {
        return Err(PatternMatchError::NotSingleObservation);
    }
    let PatternAst::Observation(obs) = ast else {
        return Err(PatternMatchError::NotSingleObservation);
    };
    observation_matches(obs, sco, bundle)
}

fn is_single_observation(ast: &PatternAst) -> bool {
    matches!(ast, PatternAst::Observation(_))
}

fn requires_timestamps(ast: &PatternAst) -> bool {
    match ast {
        PatternAst::Within { .. }
        | PatternAst::Repeats { .. }
        | PatternAst::StartStop { .. }
        | PatternAst::FollowedBy { .. } => true,
        PatternAst::And { left, right, .. } | PatternAst::Or { left, right, .. } => {
            requires_timestamps(left) || requires_timestamps(right)
        }
        PatternAst::Observation(_) => false,
    }
}

fn ensure_observation_count(ctx: &ObservationContext<'_>) -> Result<(), PatternMatchError> {
    if ctx.observations.len() > MAX_OBSERVATIONS {
        return Err(PatternMatchError::TooManyObservations {
            count: ctx.observations.len(),
            max: MAX_OBSERVATIONS,
        });
    }
    Ok(())
}

fn ensure_observation_timestamps(
    ast: &PatternAst,
    ctx: &ObservationContext<'_>,
) -> Result<(), PatternMatchError> {
    if !requires_timestamps(ast) {
        return Ok(());
    }
    if ctx.observations.iter().any(|entry| entry.at.is_none()) {
        return Err(PatternMatchError::MissingTimestamp);
    }
    Ok(())
}

fn observation_time<'a>(
    entry: &'a TimestampedObservation<'a>,
) -> Result<&'a StixTimestamp, PatternMatchError> {
    entry.at.as_ref().ok_or(PatternMatchError::MissingTimestamp)
}

fn eval_node(
    ast: &PatternAst,
    ctx: &ObservationContext<'_>,
    window_start: Option<&StixTimestamp>,
    window_stop: Option<&StixTimestamp>,
) -> Result<bool, PatternMatchError> {
    match ast {
        PatternAst::Observation(obs) => {
            for entry in ctx.observations.iter() {
                if !observation_matches(obs, entry.sco, ctx.bundle)? {
                    continue;
                }
                if !timestamp_in_window(entry.at.as_ref(), window_start, window_stop) {
                    continue;
                }
                return Ok(true);
            }
            Ok(false)
        }
        PatternAst::And { left, right, .. } => {
            for i in 0..ctx.observations.len() {
                if !matches_at_index(left, ctx, i, window_start, window_stop)? {
                    continue;
                }
                for j in 0..ctx.observations.len() {
                    if i == j {
                        continue;
                    }
                    if matches_at_index(right, ctx, j, window_start, window_stop)? {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        PatternAst::Or { left, right, .. } => Ok(eval_node(left, ctx, window_start, window_stop)?
            || eval_node(right, ctx, window_start, window_stop)?),
        PatternAst::FollowedBy { left, right, .. } => {
            eval_followed_by(left, right, ctx, window_start, window_stop)
        }
        PatternAst::Within {
            inner, duration, ..
        } => eval_within(
            inner,
            ctx,
            duration_seconds(duration),
            window_start,
            window_stop,
        ),
        PatternAst::Repeats { inner, count, .. } => Ok(witness_count_at_least(
            inner,
            ctx,
            *count as usize,
            window_start,
            window_stop,
        )?),
        PatternAst::StartStop {
            inner, start, stop, ..
        } => eval_node(inner, ctx, Some(start), Some(stop)),
    }
}

fn eval_followed_by(
    left: &PatternAst,
    right: &PatternAst,
    ctx: &ObservationContext<'_>,
    window_start: Option<&StixTimestamp>,
    window_stop: Option<&StixTimestamp>,
) -> Result<bool, PatternMatchError> {
    if let PatternAst::Repeats { inner, count, .. } = right {
        for i in 0..ctx.observations.len() {
            if !matches_at_index(left, ctx, i, window_start, window_stop)? {
                continue;
            }
            let t_left = observation_time(&ctx.observations[i])?;
            let mut hits = 0usize;
            for j in 0..ctx.observations.len() {
                if i == j {
                    continue;
                }
                let t_right = observation_time(&ctx.observations[j])?;
                if t_right < t_left {
                    continue;
                }
                if !timestamp_in_window(Some(t_right), window_start, window_stop) {
                    continue;
                }
                if matches_at_index(inner, ctx, j, window_start, window_stop)? {
                    hits += 1;
                }
            }
            if hits >= *count as usize {
                return Ok(true);
            }
        }
        return Ok(false);
    }

    for i in 0..ctx.observations.len() {
        if !matches_at_index(left, ctx, i, window_start, window_stop)? {
            continue;
        }
        for j in 0..ctx.observations.len() {
            if i == j {
                continue;
            }
            if !matches_at_index(right, ctx, j, window_start, window_stop)? {
                continue;
            }
            let t_left = observation_time(&ctx.observations[i])?;
            let t_right = observation_time(&ctx.observations[j])?;
            if t_left <= t_right {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn eval_within(
    inner: &PatternAst,
    ctx: &ObservationContext<'_>,
    max_secs: f64,
    window_start: Option<&StixTimestamp>,
    window_stop: Option<&StixTimestamp>,
) -> Result<bool, PatternMatchError> {
    any_witness_within(inner, ctx, max_secs, window_start, window_stop)
}

/// Short-circuit witness search for WITHIN (existence + span check, no cartesian enumeration).
fn any_witness_within(
    ast: &PatternAst,
    ctx: &ObservationContext<'_>,
    max_secs: f64,
    window_start: Option<&StixTimestamp>,
    window_stop: Option<&StixTimestamp>,
) -> Result<bool, PatternMatchError> {
    match ast {
        PatternAst::Observation(_) => {
            for i in 0..ctx.observations.len() {
                if !matches_at_index(ast, ctx, i, window_start, window_stop)? {
                    continue;
                }
                if witness_timestamp_span(&[i], ctx)? <= max_secs {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        PatternAst::And { left, right, .. } => {
            for i in 0..ctx.observations.len() {
                if !matches_at_index(left, ctx, i, window_start, window_stop)? {
                    continue;
                }
                for j in 0..ctx.observations.len() {
                    if i == j {
                        continue;
                    }
                    if !matches_at_index(right, ctx, j, window_start, window_stop)? {
                        continue;
                    }
                    if witness_timestamp_span(&[i, j], ctx)? <= max_secs {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        PatternAst::Or { left, right, .. } => {
            Ok(
                any_witness_within(left, ctx, max_secs, window_start, window_stop)?
                    || any_witness_within(right, ctx, max_secs, window_start, window_stop)?,
            )
        }
        PatternAst::FollowedBy { .. } => {
            for witness in collect_witnesses(ast, ctx, window_start, window_stop)? {
                if witness_timestamp_span(&witness, ctx)? <= max_secs {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        PatternAst::Within { inner, .. } | PatternAst::Repeats { inner, .. } => {
            any_witness_within(inner, ctx, max_secs, window_start, window_stop)
        }
        PatternAst::StartStop {
            inner, start, stop, ..
        } => any_witness_within(inner, ctx, max_secs, Some(start), Some(stop)),
    }
}

/// Count disjoint witnesses up to `need`, stopping early once the threshold is met.
fn witness_count_at_least(
    ast: &PatternAst,
    ctx: &ObservationContext<'_>,
    need: usize,
    window_start: Option<&StixTimestamp>,
    window_stop: Option<&StixTimestamp>,
) -> Result<bool, PatternMatchError> {
    if need == 0 {
        return Ok(true);
    }
    match ast {
        PatternAst::Observation(_) => {
            let mut found = 0usize;
            for i in 0..ctx.observations.len() {
                if matches_at_index(ast, ctx, i, window_start, window_stop)? {
                    found += 1;
                    if found >= need {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        PatternAst::And { left, right, .. } => {
            let mut found = 0usize;
            for i in 0..ctx.observations.len() {
                if !matches_at_index(left, ctx, i, window_start, window_stop)? {
                    continue;
                }
                for j in 0..ctx.observations.len() {
                    if i == j {
                        continue;
                    }
                    if matches_at_index(right, ctx, j, window_start, window_stop)? {
                        found += 1;
                        if found >= need {
                            return Ok(true);
                        }
                    }
                }
            }
            Ok(false)
        }
        PatternAst::Or { left, right, .. } => {
            Ok(
                witness_count_at_least(left, ctx, need, window_start, window_stop)?
                    || witness_count_at_least(right, ctx, need, window_start, window_stop)?,
            )
        }
        PatternAst::Within { inner, .. } | PatternAst::Repeats { inner, .. } => {
            witness_count_at_least(inner, ctx, need, window_start, window_stop)
        }
        PatternAst::StartStop {
            inner, start, stop, ..
        } => witness_count_at_least(inner, ctx, need, Some(start), Some(stop)),
        PatternAst::FollowedBy { .. } => {
            let witnesses = collect_witnesses(ast, ctx, window_start, window_stop)?;
            Ok(witnesses.len() >= need)
        }
    }
}

fn collect_witnesses(
    ast: &PatternAst,
    ctx: &ObservationContext<'_>,
    window_start: Option<&StixTimestamp>,
    window_stop: Option<&StixTimestamp>,
) -> Result<Vec<Vec<usize>>, PatternMatchError> {
    match ast {
        PatternAst::Observation(_) => {
            let mut out = Vec::new();
            for i in 0..ctx.observations.len() {
                if matches_at_index(ast, ctx, i, window_start, window_stop)? {
                    out.push(vec![i]);
                }
            }
            Ok(out)
        }
        PatternAst::And { left, right, .. } => {
            let left_w = collect_witnesses(left, ctx, window_start, window_stop)?;
            let right_w = collect_witnesses(right, ctx, window_start, window_stop)?;
            Ok(merge_disjoint_witness_sets(&left_w, &right_w))
        }
        PatternAst::Or { left, right, .. } => {
            let mut out = collect_witnesses(left, ctx, window_start, window_stop)?;
            out.extend(collect_witnesses(right, ctx, window_start, window_stop)?);
            Ok(out)
        }
        PatternAst::FollowedBy { left, right, .. } => {
            let mut out = Vec::new();
            if let PatternAst::Repeats { inner, count, .. } = right.as_ref() {
                for i in 0..ctx.observations.len() {
                    if !matches_at_index(left, ctx, i, window_start, window_stop)? {
                        continue;
                    }
                    let mut rhs = Vec::new();
                    for j in 0..ctx.observations.len() {
                        if i == j {
                            continue;
                        }
                        let t_left = observation_time(&ctx.observations[i])?;
                        let t_right = observation_time(&ctx.observations[j])?;
                        if t_right < t_left {
                            continue;
                        }
                        if matches_at_index(inner, ctx, j, window_start, window_stop)? {
                            rhs.push(j);
                        }
                    }
                    if rhs.len() >= *count as usize {
                        let mut witness = vec![i];
                        witness.extend(rhs.into_iter().take(*count as usize));
                        out.push(witness);
                    }
                }
                return Ok(out);
            }
            for i in 0..ctx.observations.len() {
                if !matches_at_index(left, ctx, i, window_start, window_stop)? {
                    continue;
                }
                for j in 0..ctx.observations.len() {
                    if i == j {
                        continue;
                    }
                    if !matches_at_index(right, ctx, j, window_start, window_stop)? {
                        continue;
                    }
                    let t_left = observation_time(&ctx.observations[i])?;
                    let t_right = observation_time(&ctx.observations[j])?;
                    if t_left <= t_right {
                        out.push(vec![i, j]);
                    }
                }
            }
            Ok(out)
        }
        PatternAst::Within { inner, .. } | PatternAst::Repeats { inner, .. } => {
            collect_witnesses(inner, ctx, window_start, window_stop)
        }
        PatternAst::StartStop {
            inner, start, stop, ..
        } => collect_witnesses(inner, ctx, Some(start), Some(stop)),
    }
}

fn merge_disjoint_witness_sets(left: &[Vec<usize>], right: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    for l in left {
        for r in right {
            if l.iter().any(|idx| r.contains(idx)) {
                continue;
            }
            let mut merged = l.clone();
            merged.extend(r.iter().copied());
            out.push(merged);
        }
    }
    out
}

fn witness_timestamp_span(
    indices: &[usize],
    ctx: &ObservationContext<'_>,
) -> Result<f64, PatternMatchError> {
    if indices.is_empty() {
        return Ok(f64::INFINITY);
    }
    let mut min_ts = observation_time(&ctx.observations[indices[0]])?;
    let mut max_ts = min_ts;
    for &idx in indices.iter().skip(1) {
        let ts = observation_time(&ctx.observations[idx])?;
        if ts < min_ts {
            min_ts = ts;
        }
        if ts > max_ts {
            max_ts = ts;
        }
    }
    Ok(duration_between(min_ts, max_ts))
}

fn timestamp_in_window(
    at: Option<&StixTimestamp>,
    start: Option<&StixTimestamp>,
    stop: Option<&StixTimestamp>,
) -> bool {
    let Some(at) = at else {
        return false;
    };
    if let Some(start) = start
        && at < start
    {
        return false;
    }
    if let Some(stop) = stop
        && at >= stop
    {
        return false;
    }
    true
}

fn duration_between(start: &StixTimestamp, end: &StixTimestamp) -> f64 {
    (end.as_datetime().unix_timestamp() - start.as_datetime().unix_timestamp()) as f64
}

fn matches_at_index(
    ast: &PatternAst,
    ctx: &ObservationContext<'_>,
    idx: usize,
    window_start: Option<&StixTimestamp>,
    window_stop: Option<&StixTimestamp>,
) -> Result<bool, PatternMatchError> {
    let entry = &ctx.observations[idx];
    if !timestamp_in_window(entry.at.as_ref(), window_start, window_stop) {
        return Ok(false);
    }
    match ast {
        PatternAst::Observation(obs) => Ok(observation_matches(obs, entry.sco, ctx.bundle)?),
        PatternAst::And { left, right, .. } => {
            witness_includes_index_and(left, right, ctx, idx, window_start, window_stop)
        }
        PatternAst::FollowedBy { .. } => {
            Ok(collect_witnesses(ast, ctx, window_start, window_stop)?
                .iter()
                .any(|w| w.contains(&idx)))
        }
        PatternAst::Or { left, right, .. } => {
            Ok(matches_at_index(left, ctx, idx, window_start, window_stop)?
                || matches_at_index(right, ctx, idx, window_start, window_stop)?)
        }
        PatternAst::Within { inner, .. } | PatternAst::Repeats { inner, .. } => {
            matches_at_index(inner, ctx, idx, window_start, window_stop)
        }
        PatternAst::StartStop {
            inner, start, stop, ..
        } => matches_at_index(inner, ctx, idx, Some(start), Some(stop)),
    }
}

fn witness_includes_index_and(
    left: &PatternAst,
    right: &PatternAst,
    ctx: &ObservationContext<'_>,
    idx: usize,
    window_start: Option<&StixTimestamp>,
    window_stop: Option<&StixTimestamp>,
) -> Result<bool, PatternMatchError> {
    if matches_at_index(left, ctx, idx, window_start, window_stop)? {
        for j in 0..ctx.observations.len() {
            if j != idx && matches_at_index(right, ctx, j, window_start, window_stop)? {
                return Ok(true);
            }
        }
    }
    if matches_at_index(right, ctx, idx, window_start, window_stop)? {
        for j in 0..ctx.observations.len() {
            if j != idx && matches_at_index(left, ctx, j, window_start, window_stop)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn duration_seconds(duration: &Duration) -> f64 {
    let factor = match duration.unit {
        TimeUnit::Seconds => 1.0,
        TimeUnit::Minutes => 60.0,
        TimeUnit::Hours => 3_600.0,
        TimeUnit::Days => 86_400.0,
        TimeUnit::Months => 2_592_000.0,
        TimeUnit::Years => 31_536_000.0,
    };
    duration.value * factor
}

fn observation_matches(
    obs: &ObservationExpr,
    sco: &ScoObject,
    bundle: Option<&Bundle>,
) -> Result<bool, PatternMatchError> {
    if !sco_type_matches(&obs.object_type, sco) {
        return Ok(false);
    }
    eval_comparison_tree(&obs.root, sco, bundle)
}

fn sco_type_matches(expected: &PatternScoType, sco: &ScoObject) -> bool {
    match expected {
        PatternScoType::Known(kind) => QueryableStixObject::type_name(sco) == kind.as_str(),
        PatternScoType::Custom(name) => QueryableStixObject::type_name(sco) == name,
    }
}

fn eval_comparison_tree(
    tree: &ComparisonTree,
    sco: &ScoObject,
    bundle: Option<&Bundle>,
) -> Result<bool, PatternMatchError> {
    let result = match tree {
        ComparisonTree::Cmp(cmp) => eval_comparison(cmp, sco, bundle)?,
        ComparisonTree::And { left, right, .. } => {
            eval_comparison_tree(left, sco, bundle)? && eval_comparison_tree(right, sco, bundle)?
        }
        ComparisonTree::Or { left, right, .. } => {
            eval_comparison_tree(left, sco, bundle)? || eval_comparison_tree(right, sco, bundle)?
        }
        ComparisonTree::Not { inner, .. } => !eval_comparison_tree(inner, sco, bundle)?,
    };
    Ok(result)
}

fn eval_comparison(
    cmp: &Comparison,
    sco: &ScoObject,
    bundle: Option<&Bundle>,
) -> Result<bool, PatternMatchError> {
    if cmp.op == ComparisonOp::Exists {
        let values = path::resolve_path_values(sco, &cmp.path, bundle)?;
        let result = !values.is_empty();
        return Ok(if cmp.negated { !result } else { result });
    }
    let values = path::resolve_path_values(sco, &cmp.path, bundle)?;
    let Some(constant) = cmp.value.as_ref() else {
        return Ok(false);
    };
    let mut matched = false;
    for value in values {
        if compare_values(cmp.op, value, constant)? {
            matched = true;
            break;
        }
    }
    Ok(if cmp.negated { !matched } else { matched })
}

fn compare_values(
    op: ComparisonOp,
    left: FieldValue,
    right: &PatternConstant,
) -> Result<bool, PatternMatchError> {
    Ok(match op {
        ComparisonOp::Eq => equals_value(left, right),
        ComparisonOp::NotEq => !equals_value(left, right),
        ComparisonOp::Gt => compare_order(left, right).is_gt(),
        ComparisonOp::Lt => compare_order(left, right).is_lt(),
        ComparisonOp::Gte => {
            let ord = compare_order(left, right);
            ord.is_gt() || ord.is_eq()
        }
        ComparisonOp::Lte => {
            let ord = compare_order(left, right);
            ord.is_lt() || ord.is_eq()
        }
        ComparisonOp::In => match right {
            PatternConstant::List(items) => {
                items.iter().any(|item| equals_value(left.clone(), item))
            }
            _ => false,
        },
        ComparisonOp::Like => match (field_value_str(&left), right) {
            (Some(s), PatternConstant::String(pat)) => like_match(s, pat.as_str()),
            _ => false,
        },
        ComparisonOp::Matches => match (left, right) {
            (FieldValue::Str(s), PatternConstant::String(re)) => regex_match(&s, re)?,
            (FieldValue::Bytes(b), PatternConstant::String(re)) => bytes_regex_match(&b, re)?,
            _ => false,
        },
        ComparisonOp::IsSubset => match (field_value_str(&left), right) {
            (Some(s), PatternConstant::String(net)) => path::cidr_subset(s, net.as_str()),
            _ => false,
        },
        ComparisonOp::IsSuperset => match (field_value_str(&left), right) {
            (Some(s), PatternConstant::String(net)) => path::cidr_superset(s, net.as_str()),
            _ => false,
        },
        ComparisonOp::Exists => false,
    })
}

fn regex_match(value: &str, pattern: &str) -> Result<bool, PatternMatchError> {
    Ok(security::compile_regex(pattern)?.is_match(value))
}

fn bytes_regex_match(bytes: &[u8], pattern: &str) -> Result<bool, PatternMatchError> {
    let haystack: String = bytes.iter().map(|&b| b as char).collect();
    regex_match(&haystack, pattern)
}

fn equals_value(left: FieldValue, right: &PatternConstant) -> bool {
    if let Some(s) = field_value_str(&left) {
        return equals_str(s, right);
    }
    match (left, right) {
        (FieldValue::Int(a), PatternConstant::String(b)) => b.parse::<i64>().is_ok_and(|n| n == a),
        (FieldValue::Float(a), PatternConstant::String(b)) => {
            b.parse::<f64>().is_ok_and(|n| (a - n).abs() < f64::EPSILON)
        }
        (FieldValue::Bool(a), PatternConstant::String(b)) => match b.as_str() {
            "true" => a,
            "false" => !a,
            _ => false,
        },
        (FieldValue::Bytes(b), PatternConstant::Hex(h)) => b.as_slice() == h,
        (FieldValue::Bytes(b), PatternConstant::Binary(bin)) => b.as_slice() == bin.as_slice(),
        (FieldValue::Int(a), PatternConstant::Int(b)) => a == *b,
        (FieldValue::Float(a), PatternConstant::Float(b)) => (a - *b).abs() < f64::EPSILON,
        (FieldValue::Bool(a), PatternConstant::Bool(b)) => a == *b,
        (FieldValue::Timestamp(a), PatternConstant::Timestamp(b)) => a == *b,
        (FieldValue::Int(a), PatternConstant::Float(b)) => ((a as f64) - *b).abs() < f64::EPSILON,
        (FieldValue::Float(a), PatternConstant::Int(b)) => (a - (*b as f64)).abs() < f64::EPSILON,
        _ => false,
    }
}

fn field_value_str(field: &FieldValue) -> Option<&str> {
    match field {
        FieldValue::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

fn equals_str(s: &str, right: &PatternConstant) -> bool {
    match right {
        // STIX §9.6: `=` is exact string equality; CIDR containment is ISSUBSET/ISSUPERSET only.
        PatternConstant::String(v) => s == v,
        PatternConstant::Hex(h) => hex_string_eq(s, h),
        PatternConstant::Binary(b) => base64_decode(s).is_some_and(|decoded| decoded == *b),
        _ => false,
    }
}

fn compare_order(left: FieldValue, right: &PatternConstant) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (left, right) {
        (FieldValue::Int(a), PatternConstant::Int(b)) => a.cmp(b),
        (FieldValue::Float(a), PatternConstant::Float(b)) => {
            a.partial_cmp(b).unwrap_or(Ordering::Equal)
        }
        (FieldValue::Int(a), PatternConstant::Float(b)) => {
            (a as f64).partial_cmp(b).unwrap_or(Ordering::Equal)
        }
        (FieldValue::Float(a), PatternConstant::Int(b)) => {
            a.partial_cmp(&(*b as f64)).unwrap_or(Ordering::Equal)
        }
        (FieldValue::Timestamp(a), PatternConstant::Timestamp(b)) => a.cmp(b),
        _ => Ordering::Equal,
    }
}

fn hex_string_eq(value: &str, expected: &[u8]) -> bool {
    decode_hex(value).is_some_and(|decoded| decoded == expected)
        || value.eq_ignore_ascii_case(&encode_hex(expected))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_nibble(pair.first()?)?;
            let lo = hex_nibble(pair.get(1)?)?;
            Some(hi << 4 | lo)
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_nibble(byte: &u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn base64_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(value).ok()
}

fn like_match(value: &str, pattern: &str) -> bool {
    like_bytes(value.as_bytes(), pattern.as_bytes())
}

/// Iterative `%`/`_` wildcard match (O(n·m), constant space). Recursive backtracking on
/// `%` is exponential and is a DoS vector for untrusted Indicator patterns.
fn like_bytes(value: &[u8], pattern: &[u8]) -> bool {
    let mut value_idx = 0usize;
    let mut pattern_idx = 0usize;
    let mut star_pattern: Option<usize> = None;
    let mut star_value: usize = 0;

    while value_idx < value.len() {
        if pattern_idx < pattern.len()
            && (pattern[pattern_idx] == b'_' || pattern[pattern_idx] == value[value_idx])
        {
            value_idx += 1;
            pattern_idx += 1;
            continue;
        }
        if pattern_idx < pattern.len() && pattern[pattern_idx] == b'%' {
            star_pattern = Some(pattern_idx);
            star_value = value_idx;
            pattern_idx += 1;
            continue;
        }
        let Some(star) = star_pattern else {
            return false;
        };
        pattern_idx = star + 1;
        star_value += 1;
        value_idx = star_value;
    }

    while pattern_idx < pattern.len() && pattern[pattern_idx] == b'%' {
        pattern_idx += 1;
    }
    pattern_idx == pattern.len()
}

#[cfg(all(test, feature = "serde"))]
mod level1 {
    use super::*;
    use crate::model::sco::ScoObject;
    use crate::pattern::Pattern;

    fn parse(s: &str) -> Pattern {
        Pattern::parse(s).expect("parse")
    }

    fn ipv4(json: &str) -> ScoObject {
        ScoObject::Ipv4Addr(serde_json::from_str(json).expect("ipv4"))
    }

    fn file(json: &str) -> ScoObject {
        ScoObject::File(serde_json::from_str(json).expect("file"))
    }

    fn process(json: &str) -> ScoObject {
        ScoObject::Process(serde_json::from_str(json).expect("process"))
    }

    #[test]
    fn ipv4_equality_true() {
        let sco = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-single.json"
        ));
        let pattern = parse("[ipv4-addr:value = '198.51.100.3']");
        assert!(pattern.matches_single(&sco).expect("eval"));
    }

    #[test]
    fn ipv4_equality_false() {
        let sco = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-single.json"
        ));
        let pattern = parse("[ipv4-addr:value = '10.0.0.1']");
        assert!(!pattern.matches_single(&sco).expect("eval"));
    }

    #[test]
    fn file_hash_md5() {
        let sco = file(include_str!(
            "../../tests/fixtures/spec/sco/file-basic.json"
        ));
        let pattern = parse(
            "[file:hashes.'SHA-256' = 'fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db']",
        );
        assert!(pattern.matches_single(&sco).expect("eval"));
    }

    #[test]
    fn process_name_from_command_line() {
        let sco = process(include_str!(
            "../../tests/fixtures/spec/sco/process-basic.json"
        ));
        let pattern = parse("[process:name = 'gedit-bin']");
        assert!(pattern.matches_single(&sco).expect("eval"));
    }

    #[test]
    fn not_negates_comparison() {
        let sco = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-single.json"
        ));
        let pattern = parse("[ipv4-addr:value != '10.0.0.1']");
        assert!(pattern.matches_single(&sco).expect("eval"));
    }

    #[test]
    fn email_multipart_ref_name_with_bundle() {
        use crate::model::Bundle;
        let sco = ScoObject::parse_str(include_str!(
            "../../tests/fixtures/pattern/eval/spec-9-8-email-bundle-email-message.json"
        ))
        .expect("email");
        let bundle = Bundle::parse(include_str!(
            "../../tests/fixtures/pattern/eval/spec-9-8-email-bundle.json"
        ))
        .expect("bundle");
        let from_eq = parse("[email-message:from_ref.value = 'from@example.com']");
        assert!(
            from_eq
                .matches_single_with_bundle(&sco, Some(&bundle))
                .expect("from eq"),
            "from_ref.value equality"
        );
        let from_pat = parse("[email-message:from_ref.value MATCHES '.+\\\\@example\\\\.com$']");
        assert!(
            from_pat
                .matches_single_with_bundle(&sco, Some(&bundle))
                .expect("from eval"),
            "from_ref.value regex"
        );
        let body_pat = parse(
            "[email-message:body_multipart[*].body_raw_ref.name MATCHES '^Final Report.+\\\\.exe$']",
        );
        assert!(
            body_pat
                .matches_single_with_bundle(&sco, Some(&bundle))
                .expect("body eval"),
            "body_raw_ref.name regex"
        );
        let pattern = parse(
            "[email-message:from_ref.value MATCHES '.+\\\\@example\\\\.com$' AND email-message:body_multipart[*].body_raw_ref.name MATCHES '^Final Report.+\\\\.exe$']",
        );
        assert!(
            pattern
                .matches_single_with_bundle(&sco, Some(&bundle))
                .expect("eval")
        );
    }

    #[test]
    fn matches_operator_regex() {
        let sco = process(include_str!(
            "../../tests/fixtures/spec/sco/process-basic.json"
        ));
        let pattern = parse("[process:command_line MATCHES '\\\\./gedit-bin.*']");
        assert!(pattern.matches_single(&sco).expect("eval"));
    }

    #[test]
    fn matches_rejects_multi_observation() {
        let pattern =
            parse("[ipv4-addr:value = '1.1.1.1'] AND [domain-name:value = 'example.com']");
        let sco = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-single.json"
        ));
        assert_eq!(
            pattern.matches_single(&sco).unwrap_err(),
            PatternMatchError::NotSingleObservation
        );
    }
}

#[cfg(all(test, feature = "serde"))]
mod level2 {
    use crate::core::StixTimestamp;
    use crate::model::sco::ScoObject;
    use crate::pattern::Pattern;
    use crate::pattern::context::{ObservationContext, TimestampedObservation};

    fn ts(s: &str) -> StixTimestamp {
        StixTimestamp::parse(s).expect("ts")
    }

    fn ipv4(json: &str) -> ScoObject {
        ScoObject::Ipv4Addr(serde_json::from_str(json).expect("ipv4"))
    }

    fn domain(json: &str) -> ScoObject {
        ScoObject::DomainName(serde_json::from_str(json).expect("domain"))
    }

    #[test]
    fn and_requires_distinct_observations() {
        let ipv4 = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-single.json"
        ));
        let domain = domain(include_str!(
            "../../tests/fixtures/spec/sco/domain-name-basic.json"
        ));
        let observations = [
            TimestampedObservation {
                sco: &ipv4,
                at: Some(ts("2024-01-01T00:00:00.000Z")),
            },
            TimestampedObservation {
                sco: &domain,
                at: Some(ts("2024-01-01T00:00:01.000Z")),
            },
        ];
        let ctx = ObservationContext::from_scos(&observations);
        let pattern = Pattern::parse(
            "[ipv4-addr:value = '198.51.100.3'] AND [domain-name:value = 'example.com']",
        )
        .expect("parse");
        assert!(pattern.evaluate(&ctx).expect("eval"));
    }

    #[test]
    fn or_matches_either_observation() {
        let ipv4 = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-single.json"
        ));
        let domain = domain(include_str!(
            "../../tests/fixtures/spec/sco/domain-name-basic.json"
        ));
        let observations = [
            TimestampedObservation {
                sco: &ipv4,
                at: Some(ts("2024-01-01T00:00:00.000Z")),
            },
            TimestampedObservation {
                sco: &domain,
                at: Some(ts("2024-01-01T00:00:01.000Z")),
            },
        ];
        let ctx = ObservationContext::from_scos(&observations);
        let pattern =
            Pattern::parse("[ipv4-addr:value = '10.0.0.1'] OR [domain-name:value = 'example.com']")
                .expect("parse");
        assert!(pattern.evaluate(&ctx).expect("eval"));
    }

    #[test]
    fn followedby_requires_distinct_observations() {
        let ipv4 = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-single.json"
        ));
        let observations = [TimestampedObservation {
            sco: &ipv4,
            at: Some(ts("2024-01-01T00:00:00.000Z")),
        }];
        let ctx = ObservationContext::from_scos(&observations);
        let pattern = Pattern::parse(
            "[ipv4-addr:value = '198.51.100.3'] FOLLOWEDBY [ipv4-addr:value = '198.51.100.3']",
        )
        .expect("parse");
        assert!(!pattern.evaluate(&ctx).expect("eval"));
    }

    #[test]
    fn followedby_ordering() {
        let ipv4 = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-single.json"
        ));
        let domain = domain(include_str!(
            "../../tests/fixtures/spec/sco/domain-name-basic.json"
        ));
        let observations = [
            TimestampedObservation {
                sco: &ipv4,
                at: Some(ts("2024-01-01T00:00:00.000Z")),
            },
            TimestampedObservation {
                sco: &domain,
                at: Some(ts("2024-01-01T00:00:01.000Z")),
            },
        ];
        let ctx = ObservationContext::from_scos(&observations);
        let pattern = Pattern::parse(
            "[ipv4-addr:value = '198.51.100.3'] FOLLOWEDBY [domain-name:value = 'example.com']",
        )
        .expect("parse");
        assert!(pattern.evaluate(&ctx).expect("eval"));
    }
}

#[cfg(all(test, feature = "serde"))]
mod level3 {
    use super::PatternMatchError;
    use crate::core::StixTimestamp;
    use crate::model::sco::ScoObject;
    use crate::pattern::Pattern;
    use crate::pattern::context::{ObservationContext, TimestampedObservation};

    fn ts(s: &str) -> StixTimestamp {
        StixTimestamp::parse(s).expect("ts")
    }

    fn ipv4(json: &str) -> ScoObject {
        ScoObject::Ipv4Addr(serde_json::from_str(json).expect("ipv4"))
    }

    fn domain(json: &str) -> ScoObject {
        ScoObject::DomainName(serde_json::from_str(json).expect("domain"))
    }

    #[test]
    fn within_single_observation() {
        let sco = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-single.json"
        ));
        let observations = [TimestampedObservation {
            sco: &sco,
            at: Some(ts("2024-01-01T00:00:00.000Z")),
        }];
        let ctx = ObservationContext::from_scos(&observations);
        let pattern =
            Pattern::parse("[ipv4-addr:value = '198.51.100.3'] WITHIN 5 MINUTES").expect("parse");
        assert!(pattern.evaluate(&ctx).expect("eval"));
    }

    #[test]
    fn within_and_pair_in_window() {
        let ipv4 = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-single.json"
        ));
        let domain = domain(include_str!(
            "../../tests/fixtures/spec/sco/domain-name-basic.json"
        ));
        let observations = [
            TimestampedObservation {
                sco: &ipv4,
                at: Some(ts("2024-01-01T00:00:00.000Z")),
            },
            TimestampedObservation {
                sco: &domain,
                at: Some(ts("2024-01-01T00:01:00.000Z")),
            },
        ];
        let ctx = ObservationContext::from_scos(&observations);
        let pattern = Pattern::parse(
            "([ipv4-addr:value = '198.51.100.3'] AND [domain-name:value = 'example.com']) WITHIN 120 SECONDS",
        )
        .expect("parse");
        assert!(pattern.evaluate(&ctx).expect("eval"));
    }

    #[test]
    fn repeats_requires_distinct_observations() {
        let ipv4 = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-single.json"
        ));
        let observations = [TimestampedObservation {
            sco: &ipv4,
            at: Some(ts("2024-01-01T00:00:00.000Z")),
        }];
        let ctx = ObservationContext::from_scos(&observations);
        let pattern =
            Pattern::parse("[ipv4-addr:value = '198.51.100.3'] REPEATS 2 TIMES").expect("parse");
        assert!(!pattern.evaluate(&ctx).expect("eval"));
    }

    #[test]
    fn start_stop_window() {
        let sco = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-cidr.json"
        ));
        let observations = [TimestampedObservation {
            sco: &sco,
            at: Some(ts("2014-06-15T00:00:00.000Z")),
        }];
        let ctx = ObservationContext::from_scos(&observations);
        let pattern = Pattern::parse(
            "[ipv4-addr:value = '198.51.100.0/24'] START t'2014-06-01T00:00:00Z' STOP t'2014-07-01T00:00:00Z'",
        )
        .expect("parse");
        assert!(pattern.evaluate(&ctx).expect("eval"));
    }

    #[test]
    fn start_stop_excludes_stop_boundary() {
        let sco = ipv4(include_str!(
            "../../tests/fixtures/spec/sco/ipv4-addr-cidr.json"
        ));
        let observations = [TimestampedObservation {
            sco: &sco,
            at: Some(ts("2014-07-01T00:00:00.000Z")),
        }];
        let ctx = ObservationContext::from_scos(&observations);
        let pattern = Pattern::parse(
            "[ipv4-addr:value = '198.51.100.0/24'] START t'2014-06-01T00:00:00Z' STOP t'2014-07-01T00:00:00Z'",
        )
        .expect("parse");
        assert!(!pattern.evaluate(&ctx).expect("eval"));
    }

    #[test]
    fn missing_timestamp_on_empty_context() {
        let ctx = ObservationContext::from_scos(&[]);
        let pattern =
            Pattern::parse("[ipv4-addr:value = '198.51.100.3'] WITHIN 5 MINUTES").expect("parse");
        assert_eq!(
            pattern.evaluate(&ctx).unwrap_err(),
            PatternMatchError::MissingTimestamp
        );
    }
}
