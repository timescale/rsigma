//! Hand-rolled Prometheus text-exposition parser, scoped to the two per-rule
//! counter families the rule commands join on.
//!
//! This module is deliberately std-only (no serde, no HTTP, no crate imports)
//! so it is the shared metrics reader's single untrusted-input surface and can
//! be compiled standalone by the `fuzz_scorecard_promtext` cargo-fuzz target
//! via a `#[path]` include. It must never panic on any byte input; every
//! malformed or unrelated line is skipped. It matches the repo's
//! `DelimitedWriter`/JUnit-writer precedent of a small hand-rolled format
//! reader/writer rather than a new dependency.

use std::collections::BTreeMap;

/// The two per-rule counter families the rule commands join on, from #27/#36.
pub(crate) const DETECTION_METRIC: &str = "rsigma_detection_matches_by_rule_total";
pub(crate) const CORRELATION_METRIC: &str = "rsigma_correlation_matches_by_rule_total";

/// Parse a Prometheus text-exposition snapshot, summing the two
/// `*_matches_by_rule_total` families by their `rule_title` label.
///
/// Total and panic-free: every malformed or unrelated line is skipped, and only
/// the two metric families with a `rule_title` label contribute. `rule_title`
/// is not guaranteed unique (see `docs/reference/metrics.md`); colliding titles
/// (whether across label sets or across rules) add together here.
pub(crate) fn parse_exposition(text: &str) -> BTreeMap<String, u64> {
    let mut by_title: BTreeMap<String, u64> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, rest)) = split_metric_name(line) else {
            continue;
        };
        if name != DETECTION_METRIC && name != CORRELATION_METRIC {
            continue;
        }
        // The two families always carry labels; a sample with no label block is
        // not one of ours.
        let Some((labels, value_part)) = rest.strip_prefix('{').and_then(|r| r.split_once('}'))
        else {
            continue;
        };
        let Some(title) = label_value(labels, "rule_title") else {
            continue;
        };
        let Some(value) = parse_sample_value(value_part) else {
            continue;
        };
        *by_title.entry(title).or_insert(0) += value;
    }
    by_title
}

/// Split a sample line into the metric name and the remainder (`{labels} value`
/// or ` value`). Returns `None` when the leading token is not a metric name.
fn split_metric_name(line: &str) -> Option<(&str, &str)> {
    let end = line
        .find(|c: char| c == '{' || c.is_whitespace())
        .unwrap_or(line.len());
    if end == 0 {
        return None;
    }
    Some((&line[..end], &line[end..]))
}

/// Extract a quoted label value from a Prometheus label block, honoring the
/// exposition-format escapes (`\"`, `\\`, `\n`). Returns the first match for
/// `key`.
///
/// Char-based throughout so it never splits a multibyte character (the input is
/// arbitrary fuzzed text) and never panics: a malformed fragment (no `=`, an
/// unquoted value, or an unterminated quote) ends the scan with `None`.
fn label_value(labels: &str, key: &str) -> Option<String> {
    let mut it = labels.chars().peekable();
    loop {
        // Skip separators and whitespace to the start of a label name.
        while let Some(&c) = it.peek() {
            if c == ',' || c.is_whitespace() {
                it.next();
            } else {
                break;
            }
        }
        it.peek()?;

        // Read the label name up to '=' (or bail at ',' / end).
        let mut name = String::new();
        let mut saw_eq = false;
        while let Some(&c) = it.peek() {
            if c == '=' {
                it.next();
                saw_eq = true;
                break;
            }
            if c == ',' {
                break;
            }
            name.push(c);
            it.next();
        }
        if !saw_eq {
            return None;
        }

        // The value must be double-quoted.
        it.next_if_eq(&'"')?;

        // Read the quoted value, decoding the exposition escapes.
        let mut value = String::new();
        let mut closed = false;
        while let Some(c) = it.next() {
            match c {
                '\\' => match it.next() {
                    Some('n') => value.push('\n'),
                    Some('"') => value.push('"'),
                    Some('\\') => value.push('\\'),
                    Some(other) => {
                        value.push('\\');
                        value.push(other);
                    }
                    None => value.push('\\'),
                },
                '"' => {
                    closed = true;
                    break;
                }
                other => value.push(other),
            }
        }
        if !closed {
            return None;
        }
        if name.trim() == key {
            return Some(value);
        }
        // Otherwise advance to the next label; the loop's separator skip
        // consumes the comma.
    }
}

/// Parse the value token of a sample (`{labels} <value> [timestamp]`), tolerating
/// a trailing timestamp and surrounding whitespace. Counter values are floats in
/// the exposition format; they are rounded to a non-negative integer fire count.
fn parse_sample_value(value_part: &str) -> Option<u64> {
    let token = value_part.split_whitespace().next()?;
    let v: f64 = token.parse().ok()?;
    if !v.is_finite() || v < 0.0 {
        return None;
    }
    Some(v.round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_families_and_sums_collisions() {
        let text = "\
# HELP rsigma_detection_matches_by_rule_total Detection matches per rule.
# TYPE rsigma_detection_matches_by_rule_total counter
rsigma_detection_matches_by_rule_total{rule_title=\"Whoami\",level=\"low\"} 5
rsigma_detection_matches_by_rule_total{rule_title=\"Whoami\",level=\"high\"} 3
rsigma_correlation_matches_by_rule_total{rule_title=\"Brute Force\",level=\"high\",correlation_type=\"event_count\"} 2
some_other_metric{rule_title=\"Ignored\"} 99
";
        let m = parse_exposition(text);
        // Same title across two label sets sums to 8.
        assert_eq!(m.get("Whoami"), Some(&8));
        assert_eq!(m.get("Brute Force"), Some(&2));
        assert!(!m.contains_key("Ignored"));
    }

    #[test]
    fn skips_malformed_lines_without_panicking() {
        let text = "\
rsigma_detection_matches_by_rule_total{rule_title=\"Has Value\"} 4
rsigma_detection_matches_by_rule_total{rule_title=\"No Value\"}
rsigma_detection_matches_by_rule_total{no_title=\"x\"} 7
rsigma_detection_matches_by_rule_total 12
garbage line with no structure
rsigma_detection_matches_by_rule_total{rule_title=\"Bad Number\"} not_a_number
";
        let m = parse_exposition(text);
        assert_eq!(m.get("Has Value"), Some(&4));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn label_value_handles_escapes_and_ordering() {
        let labels = r#"level="low",rule_title="A \"quoted\" rule",correlation_type="x""#;
        assert_eq!(
            label_value(labels, "rule_title").as_deref(),
            Some("A \"quoted\" rule")
        );
        assert_eq!(label_value(labels, "missing"), None);
    }

    #[test]
    fn label_value_keeps_unescaped_multibyte() {
        let labels = r#"rule_title="Suspicious café access""#;
        assert_eq!(
            label_value(labels, "rule_title").as_deref(),
            Some("Suspicious café access")
        );
    }

    #[test]
    fn parse_value_rounds_and_rejects_negative() {
        assert_eq!(parse_sample_value(" 5"), Some(5));
        assert_eq!(parse_sample_value(" 5.0 169000"), Some(5));
        assert_eq!(parse_sample_value(" 5.6"), Some(6));
        assert_eq!(parse_sample_value(" -1"), None);
        assert_eq!(parse_sample_value(" NaN"), None);
        assert_eq!(parse_sample_value("  "), None);
    }

    #[test]
    fn never_panics_on_adversarial_bytes() {
        // A grab-bag of malformed shapes: unterminated quotes, lone braces,
        // trailing backslashes, empty labels. The parser must just skip them.
        for s in [
            "rsigma_detection_matches_by_rule_total{rule_title=\"unterminated",
            "rsigma_detection_matches_by_rule_total{=\"\"} 1",
            "rsigma_detection_matches_by_rule_total{rule_title=\"x\\",
            "rsigma_detection_matches_by_rule_total{",
            "rsigma_detection_matches_by_rule_total{}",
            "{rule_title=\"x\"} 1",
        ] {
            let _ = parse_exposition(s);
        }
    }
}
