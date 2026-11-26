//! Applying string and encoding modifiers to values before a pipeline runs.
//!
//! pySigma applies value modifiers when it parses a rule, so its value
//! transformations see `*foo*` for `contains: foo` and the encoded text for
//! `base64: foo`. rsigma keeps the raw value and its modifiers until it
//! compiles or converts the rule. A pipeline with
//! [`ApplyModifiers::First`] rewrites the values the way pySigma does before
//! its transformations run.

use rsigma_ir::encoding::{check_encodable, expand_encoded};
use rsigma_ir::{IrEncoding, IrPattern, IrPatternPart, IrStrOp};
use rsigma_parser::value::{SpecialChar, StringPart};
use rsigma_parser::{
    Detection, DetectionItem, FieldSpec, Modifier, SigmaRule, SigmaString, SigmaValue,
};

use super::transformations::{merge_plain_parts, parts_to_original};

/// When a pipeline's transformations see the effect of value modifiers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ApplyModifiers {
    /// Transformations see the raw values. The modifiers stay on the
    /// detection items and apply when the rule compiles or converts.
    #[default]
    Last,
    /// Before the pipeline's transformations run, `contains`, `startswith`,
    /// and `endswith` become wildcards in the values, and the encoding
    /// modifiers (`base64`, `base64offset`, `wide`, `utf16`, `utf16be`, and
    /// `windash`) encode them, as pySigma does when it parses a rule.
    First,
}

/// Rewrite every detection item of `rule` whose modifiers can be expressed
/// in its values. Items that cannot are left for compilation to handle.
pub(super) fn apply_to_rule(rule: &mut SigmaRule) {
    for detection in rule.detection.named.values_mut() {
        apply_to_detection(detection);
    }
}

fn apply_to_detection(detection: &mut Detection) {
    match detection {
        Detection::AllOf(items) => {
            *items = std::mem::take(items)
                .into_iter()
                .flat_map(|item| rewrite_item(&item).unwrap_or_else(|| vec![item]))
                .collect();
        }
        Detection::AnyOf(subs) | Detection::And(subs) => {
            subs.iter_mut().for_each(apply_to_detection);
        }
        Detection::ArrayMatch { body, .. } => apply_to_detection(body),
        Detection::Conditional { named, .. } => named.values_mut().for_each(apply_to_detection),
        Detection::Keywords(_) => {}
    }
}

/// The items that replace `item` once its modifiers are applied, or `None`
/// when they cannot be expressed in its values.
///
/// An item is rewritten only when it has a field and every modifier is a
/// string operator, an encoding, or one of `all`, `cased`, and `neq`, which it
/// keeps. A value without a field matches anywhere in the event, so `*x` there
/// is not the same match as `endswith: x`.
fn rewrite_item(item: &DetectionItem) -> Option<Vec<DetectionItem>> {
    let modifiers = &item.field.modifiers;
    let mut encodings = Vec::new();
    let mut kept = Vec::new();
    for modifier in modifiers {
        match modifier {
            Modifier::Contains
            | Modifier::StartsWith
            | Modifier::EndsWith
            | Modifier::Base64
            | Modifier::Base64Offset
            | Modifier::Wide
            | Modifier::Utf16be
            | Modifier::Utf16
            | Modifier::WindAsh => {}
            Modifier::All | Modifier::Cased | Modifier::Neq => kept.push(*modifier),
            _ => return None,
        }
    }
    let op = if modifiers.contains(&Modifier::Contains) {
        IrStrOp::Contains
    } else if modifiers.contains(&Modifier::StartsWith) {
        IrStrOp::StartsWith
    } else if modifiers.contains(&Modifier::EndsWith) {
        IrStrOp::EndsWith
    } else {
        IrStrOp::Exact
    };
    for (modifier, encoding) in [
        (Modifier::Wide, IrEncoding::Wide),
        (Modifier::Utf16be, IrEncoding::Utf16Be),
        (Modifier::Utf16, IrEncoding::Utf16),
        (Modifier::Base64, IrEncoding::Base64),
        (Modifier::Base64Offset, IrEncoding::Base64Offset),
        (Modifier::WindAsh, IrEncoding::Windash),
    ] {
        if modifiers.contains(&modifier) {
            encodings.push(encoding);
        }
    }
    if item.field.name.is_none()
        || (op == IrStrOp::Exact && encodings.is_empty())
        || item.values.is_empty()
    {
        return None;
    }

    let mut groups = Vec::with_capacity(item.values.len());
    for value in &item.values {
        let pattern = match value {
            SigmaValue::String(s) => pattern_from_sigma(s),
            SigmaValue::Integer(n) if encodings.is_empty() => literal(n.to_string()),
            SigmaValue::Float(n) if encodings.is_empty() => literal(n.to_string()),
            _ => return None,
        };
        let variants = if encodings.is_empty() {
            vec![(op, pattern)]
        } else {
            check_encodable(&encodings, &pattern).ok()?;
            expand_encoded(&encodings, op, &pattern).ok()?
        };
        // An empty value list would turn the item into a null check.
        if variants.is_empty() {
            return None;
        }
        groups.push(
            variants
                .into_iter()
                .map(|(op, pattern)| SigmaValue::String(sigma_string(op, &pattern)))
                .collect::<Vec<_>>(),
        );
    }

    let item_with = |modifiers: Vec<Modifier>, values: Vec<SigmaValue>| DetectionItem {
        field: FieldSpec::new(item.field.name.clone(), modifiers),
        values,
    };
    if groups.iter().all(|variants| variants.len() == 1) {
        return Some(vec![item_with(kept, groups.concat())]);
    }
    // Several variants per value are alternatives, so `all` no longer joins
    // the values of one item. Each value becomes its own AND-linked item,
    // which `neq` cannot follow because it negates the whole item.
    let all = kept.contains(&Modifier::All);
    kept.retain(|m| *m != Modifier::All);
    if !all || groups.len() == 1 {
        return Some(vec![item_with(kept, groups.concat())]);
    }
    if kept.contains(&Modifier::Neq) {
        return None;
    }
    Some(
        groups
            .into_iter()
            .map(|variants| item_with(kept.clone(), variants))
            .collect(),
    )
}

fn pattern_from_sigma(s: &SigmaString) -> IrPattern {
    let parts = s
        .parts
        .iter()
        .map(|part| match part {
            StringPart::Plain(text) => IrPatternPart::Literal(text.clone()),
            StringPart::Special(SpecialChar::WildcardMulti) => IrPatternPart::WildcardMulti,
            StringPart::Special(SpecialChar::WildcardSingle) => IrPatternPart::WildcardSingle,
        })
        .collect();
    IrPattern { parts }
}

fn literal(text: String) -> IrPattern {
    IrPattern {
        parts: vec![IrPatternPart::Literal(text)],
    }
}

/// The Sigma string that matches `pattern` under `op` without a modifier.
/// Like pySigma, it adds no `*` where the value already has one.
fn sigma_string(op: IrStrOp, pattern: &IrPattern) -> SigmaString {
    let wildcard = || StringPart::Special(SpecialChar::WildcardMulti);
    let mut parts: Vec<StringPart> = pattern
        .parts
        .iter()
        .map(|part| match part {
            IrPatternPart::Literal(text) => StringPart::Plain(text.clone()),
            IrPatternPart::WildcardMulti => wildcard(),
            IrPatternPart::WildcardSingle => StringPart::Special(SpecialChar::WildcardSingle),
        })
        .filter(|part| !matches!(part, StringPart::Plain(text) if text.is_empty()))
        .collect();
    let is_wildcard = |part: Option<&StringPart>| {
        matches!(part, Some(StringPart::Special(SpecialChar::WildcardMulti)))
    };
    if matches!(op, IrStrOp::Contains | IrStrOp::EndsWith) && !is_wildcard(parts.first()) {
        parts.insert(0, wildcard());
    }
    if matches!(op, IrStrOp::Contains | IrStrOp::StartsWith) && !is_wildcard(parts.last()) {
        parts.push(wildcard());
    }
    let parts = merge_plain_parts(parts);
    let original = parts_to_original(&parts);
    SigmaString { parts, original }
}
