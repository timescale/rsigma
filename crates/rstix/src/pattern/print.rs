//! Canonical STIX pattern printer (STIX Specification §9).

use std::fmt::Write;

use base64::Engine;

use crate::core::StixTimestamp;
use crate::pattern::ast::{
    Comparison, ComparisonOp, ComparisonTree, Duration, ObjectPath, ObservationExpr, PathStep,
    PatternAst, PatternConstant, TimeUnit,
};

const PREC_FOLLOWEDBY: u8 = 0;
const PREC_OR: u8 = 1;
const PREC_AND: u8 = 2;

const CMP_PREC_OR: u8 = 0;
const CMP_PREC_AND: u8 = 1;
const CMP_PREC_NOT: u8 = 2;

/// Render a parsed pattern AST as a canonical STIX pattern string.
pub(crate) fn print(ast: &PatternAst) -> String {
    let mut out = String::new();
    print_observation(ast, PREC_FOLLOWEDBY, &mut out);
    out
}

fn print_observation(ast: &PatternAst, min_prec: u8, out: &mut String) {
    match ast {
        PatternAst::FollowedBy { left, right, .. } => {
            let wrap = min_prec > PREC_FOLLOWEDBY;
            if wrap {
                out.push('(');
            }
            print_observation(left, PREC_FOLLOWEDBY, out);
            out.push_str(" FOLLOWEDBY ");
            print_observation(right, PREC_FOLLOWEDBY, out);
            if wrap {
                out.push(')');
            }
        }
        PatternAst::Or { left, right, .. } => {
            let wrap = min_prec > PREC_OR;
            if wrap {
                out.push('(');
            }
            print_observation(left, PREC_OR, out);
            out.push_str(" OR ");
            print_observation(right, PREC_OR, out);
            if wrap {
                out.push(')');
            }
        }
        PatternAst::And { left, right, .. } => {
            let wrap = min_prec > PREC_AND;
            if wrap {
                out.push('(');
            }
            print_observation(left, PREC_AND, out);
            out.push_str(" AND ");
            print_observation(right, PREC_AND, out);
            if wrap {
                out.push(')');
            }
        }
        PatternAst::Within {
            inner, duration, ..
        } => {
            print_qualifier_inner(inner, out);
            out.push_str(" WITHIN ");
            print_duration(duration, out);
        }
        PatternAst::Repeats { inner, count, .. } => {
            print_qualifier_inner(inner, out);
            write!(out, " REPEATS {count} TIMES").expect("fmt");
        }
        PatternAst::StartStop {
            inner, start, stop, ..
        } => {
            print_qualifier_inner(inner, out);
            out.push_str(" START ");
            print_timestamp(start, out);
            out.push_str(" STOP ");
            print_timestamp(stop, out);
        }
        PatternAst::Observation(obs) => print_bracketed_observation(obs, out),
    }
}

fn print_qualifier_inner(ast: &PatternAst, out: &mut String) {
    match ast {
        PatternAst::FollowedBy { .. } | PatternAst::Or { .. } | PatternAst::And { .. } => {
            out.push('(');
            print_observation(ast, PREC_FOLLOWEDBY, out);
            out.push(')');
        }
        _ => print_observation(ast, PREC_FOLLOWEDBY, out),
    }
}

fn print_bracketed_observation(obs: &ObservationExpr, out: &mut String) {
    out.push('[');
    print_comparison_tree(&obs.root, CMP_PREC_OR, out);
    out.push(']');
}

fn print_comparison_tree(tree: &ComparisonTree, min_prec: u8, out: &mut String) {
    match tree {
        ComparisonTree::Or { left, right, .. } => {
            let wrap = min_prec > CMP_PREC_OR;
            if wrap {
                out.push('(');
            }
            print_comparison_tree(left, CMP_PREC_OR, out);
            out.push_str(" OR ");
            print_comparison_tree(right, CMP_PREC_OR, out);
            if wrap {
                out.push(')');
            }
        }
        ComparisonTree::And { left, right, .. } => {
            let wrap = min_prec > CMP_PREC_AND;
            if wrap {
                out.push('(');
            }
            print_comparison_tree(left, CMP_PREC_AND, out);
            out.push_str(" AND ");
            print_comparison_tree(right, CMP_PREC_AND, out);
            if wrap {
                out.push(')');
            }
        }
        ComparisonTree::Not { inner, .. } => {
            let wrap = min_prec > CMP_PREC_NOT;
            if wrap {
                out.push('(');
            }
            out.push_str("NOT ");
            print_comparison_tree(inner, CMP_PREC_NOT, out);
            if wrap {
                out.push(')');
            }
        }
        ComparisonTree::Cmp(cmp) => print_comparison(cmp, out),
    }
}

fn print_comparison(cmp: &Comparison, out: &mut String) {
    if matches!(cmp.op, ComparisonOp::Exists) {
        if cmp.negated {
            out.push_str("NOT ");
        }
        out.push_str("EXISTS ");
        print_object_path(&cmp.path, out);
        return;
    }

    print_object_path(&cmp.path, out);
    out.push(' ');
    if cmp.negated {
        out.push_str("NOT ");
    }
    out.push_str(print_op(cmp.op));
    if let Some(value) = &cmp.value {
        out.push(' ');
        print_constant(value, out);
    }
}

fn print_op(op: ComparisonOp) -> &'static str {
    match op {
        ComparisonOp::Eq => "=",
        ComparisonOp::NotEq => "!=",
        ComparisonOp::Gt => ">",
        ComparisonOp::Lt => "<",
        ComparisonOp::Gte => ">=",
        ComparisonOp::Lte => "<=",
        ComparisonOp::In => "IN",
        ComparisonOp::Like => "LIKE",
        ComparisonOp::Matches => "MATCHES",
        ComparisonOp::IsSubset => "ISSUBSET",
        ComparisonOp::IsSuperset => "ISSUPERSET",
        ComparisonOp::Exists => "EXISTS",
    }
}

fn print_object_path(path: &ObjectPath, out: &mut String) {
    out.push_str(path.object_type.type_name());
    out.push(':');
    let mut first = true;
    for step in &path.steps {
        match step {
            PathStep::Property(name) => {
                if first {
                    out.push_str(name);
                    first = false;
                } else {
                    out.push('.');
                    out.push_str(name);
                }
            }
            PathStep::DictKey(key) => {
                out.push('.');
                print_dict_key(key, out);
            }
            PathStep::Index(idx) => {
                write!(out, "[{idx}]").expect("fmt");
            }
            PathStep::AnyIndex => out.push_str("[*]"),
            PathStep::Reference => {}
        }
    }
}

fn print_dict_key(key: &str, out: &mut String) {
    if is_simple_dict_key(key) {
        out.push_str(key);
    } else {
        out.push('\'');
        print_escaped_string(key, out);
        out.push('\'');
    }
}

fn is_simple_dict_key(key: &str) -> bool {
    let Some(first) = key.chars().next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn print_constant(value: &PatternConstant, out: &mut String) {
    match value {
        PatternConstant::String(s) => {
            out.push('\'');
            print_escaped_string(s, out);
            out.push('\'');
        }
        PatternConstant::Int(n) => write!(out, "{n}").expect("fmt"),
        PatternConstant::Float(f) => print_float(*f, out),
        PatternConstant::Bool(b) => write!(out, "{b}").expect("fmt"),
        PatternConstant::Timestamp(ts) => print_timestamp(ts, out),
        PatternConstant::Hex(bytes) => {
            out.push_str("h'");
            for byte in bytes {
                write!(out, "{byte:02x}").expect("fmt");
            }
            out.push('\'');
        }
        PatternConstant::Binary(bytes) => {
            out.push_str("b'");
            out.push_str(&base64::engine::general_purpose::STANDARD.encode(bytes));
            out.push('\'');
        }
        PatternConstant::List(items) => {
            out.push('(');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push_str(", ");
                }
                print_constant(item, out);
            }
            out.push(')');
        }
    }
}

fn print_float(value: f64, out: &mut String) {
    if value.fract() == 0.0 && value >= i64::MIN as f64 && value <= i64::MAX as f64 {
        write!(out, "{}", value as i64).expect("fmt");
    } else {
        write!(out, "{value}").expect("fmt");
    }
}

fn print_duration(duration: &Duration, out: &mut String) {
    print_float(duration.value, out);
    out.push(' ');
    out.push_str(match duration.unit {
        TimeUnit::Seconds => "SECONDS",
        TimeUnit::Minutes => "MINUTES",
        TimeUnit::Hours => "HOURS",
        TimeUnit::Days => "DAYS",
        TimeUnit::Months => "MONTHS",
        TimeUnit::Years => "YEARS",
    });
}

fn print_timestamp(ts: &StixTimestamp, out: &mut String) {
    out.push_str("t'");
    out.push_str(&ts.to_rfc3339());
    out.push('\'');
}

fn print_escaped_string(value: &str, out: &mut String) {
    for ch in value.chars() {
        match ch {
            '\'' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pattern;

    fn round_trip(source: &str) {
        let first = Pattern::parse(source).unwrap_or_else(|e| panic!("parse {source:?}: {e}"));
        let printed = print(first.ast());
        let second =
            Pattern::parse(&printed).unwrap_or_else(|e| panic!("re-parse {printed:?}: {e}"));
        assert!(
            first.ast().semantic_eq(second.ast()),
            "semantic mismatch\n  source:  {source}\n  printed: {printed}"
        );
    }

    #[test]
    fn spec_section_9_8_level1_round_trip() {
        let lines = include_str!("../../tests/fixtures/pattern/spec-section-9-8-level1.txt");
        for line in lines.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            round_trip(line);
        }
    }

    #[test]
    fn spec_section_9_8_level23_round_trip() {
        let lines = include_str!("../../tests/fixtures/pattern/spec-section-9-8-level23.txt");
        for line in lines.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            round_trip(line);
        }
    }

    #[test]
    fn parenthesized_followedby_within_round_trip() {
        round_trip(
            "([file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4'] FOLLOWEDBY [windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\foo\\\\bar']) WITHIN 300 SECONDS",
        );
    }

    #[test]
    fn display_matches_print() {
        let pattern = Pattern::parse("[ipv4-addr:value = '198.51.100.1/32']").expect("parse");
        assert_eq!(pattern.canonical(), print(pattern.ast()));
        assert_eq!(pattern.to_string(), print(pattern.ast()));
    }
}
