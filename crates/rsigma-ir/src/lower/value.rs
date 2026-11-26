//! Lower a single `SigmaValue` under a modifier context into [`IrMatcher`].
//!
//! Lowering is purely structural: it resolves *which* comparison applies and
//! preserves the value faithfully (original case, wildcards intact, encodings
//! recorded as explicit [`IrEncoding`] steps). It does **not** lowercase,
//! compile regexes, or expand encodings; eval does those when it compiles a
//! rule, and convert expands encodings before rendering.

use rsigma_parser::validate::check_cidr;
use rsigma_parser::value::{SpecialChar, StringPart};
use rsigma_parser::{SigmaString, SigmaValue};

use crate::encoding::check_encodable;
use crate::error::IrError;
use crate::{
    IrEncoding, IrExpandPart, IrMatcher, IrNumber, IrPattern, IrPatternPart, IrStrOp,
    NumericLiteral,
};

use super::helpers::{ExpandSegment, Result, scan_expand, value_to_number, value_to_plain_string};
use super::mod_ctx::ModCtx;

/// Build an [`IrPattern`] from a parser [`SigmaString`], preserving literal
/// case and wildcard structure.
fn pattern_from_sigma(s: &SigmaString) -> IrPattern {
    let parts = s
        .parts
        .iter()
        .map(|p| match p {
            StringPart::Plain(t) => IrPatternPart::Literal(t.clone()),
            StringPart::Special(SpecialChar::WildcardMulti) => IrPatternPart::WildcardMulti,
            StringPart::Special(SpecialChar::WildcardSingle) => IrPatternPart::WildcardSingle,
        })
        .collect();
    IrPattern { parts }
}

fn plain_pattern(s: &str) -> IrPattern {
    IrPattern {
        parts: vec![IrPatternPart::Literal(s.to_string())],
    }
}

/// Field name referenced by `|fieldref`. Wildcards are rejected; an escaped
/// `\*` is a literal asterisk in the name.
fn fieldref_name(value: &SigmaValue) -> Result<String> {
    match value {
        SigmaValue::String(s) => s.as_plain().ok_or_else(|| {
            IrError::IncompatibleValue("field reference must not contain wildcards".into())
        }),
        other => value_to_plain_string(other),
    }
}

/// The string operator implied by the modifier context.
fn str_op(ctx: &ModCtx) -> IrStrOp {
    if ctx.contains {
        IrStrOp::Contains
    } else if ctx.startswith {
        IrStrOp::StartsWith
    } else if ctx.endswith {
        IrStrOp::EndsWith
    } else {
        IrStrOp::Exact
    }
}

/// Ordered encoding transforms present in the context (empty if none).
fn encodings(ctx: &ModCtx) -> Vec<IrEncoding> {
    let mut out = Vec::new();
    // UTF-16 dialects (mutually exclusive, validated upstream) come first,
    // then the base64 strategy or windash, mirroring the byte pipeline order.
    if ctx.wide {
        out.push(IrEncoding::Wide);
    }
    if ctx.utf16be {
        out.push(IrEncoding::Utf16Be);
    }
    if ctx.utf16 {
        out.push(IrEncoding::Utf16);
    }
    if ctx.base64 {
        out.push(IrEncoding::Base64);
    }
    if ctx.base64offset {
        out.push(IrEncoding::Base64Offset);
    }
    if ctx.windash {
        out.push(IrEncoding::Windash);
    }
    out
}

/// Lower a single `SigmaValue` using the modifier context.
pub(super) fn lower_value(value: &SigmaValue, ctx: &ModCtx) -> Result<IrMatcher> {
    let ci = ctx.is_case_insensitive();

    if ctx.expand
        && let SigmaValue::String(s) = value
    {
        return lower_expand(s, ctx);
    }

    if let Some(part) = ctx.timestamp_part {
        let inner = match value {
            SigmaValue::Integer(n) => IrMatcher::NumericEq(IrNumber::Literal((*n).into())),
            SigmaValue::Float(n) => IrMatcher::NumericEq(IrNumber::Literal((*n).into())),
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                let n = NumericLiteral::parse(&plain).ok_or_else(|| {
                    IrError::IncompatibleValue(format!(
                        "timestamp part modifier requires numeric value, got: {plain}"
                    ))
                })?;
                IrMatcher::NumericEq(IrNumber::Literal(n))
            }
            _ => {
                return Err(IrError::IncompatibleValue(
                    "timestamp part modifier requires numeric value".into(),
                ));
            }
        };
        return Ok(IrMatcher::TimestampPart {
            part,
            inner: Box::new(inner),
        });
    }

    if ctx.fieldref {
        let field_name = fieldref_name(value)?;
        return Ok(IrMatcher::FieldRef {
            field: field_name,
            op: str_op(ctx),
            case_insensitive: ci,
        });
    }

    if ctx.re {
        let pattern = value_to_plain_string(value)?;
        return Ok(IrMatcher::Regex {
            pattern,
            case_insensitive: ctx.ignore_case,
            multiline: ctx.multiline,
            dotall: ctx.dotall,
            cased: ctx.cased,
        });
    }

    if ctx.cidr {
        let cidr_str = value_to_plain_string(value)?;
        check_cidr(&cidr_str).map_err(IrError::IncompatibleValue)?;
        return Ok(IrMatcher::Cidr { network: cidr_str });
    }

    if ctx.has_numeric_comparison() {
        let n = value_to_number(value)?;
        if ctx.gt {
            return Ok(IrMatcher::NumericGt(IrNumber::Literal(n)));
        }
        if ctx.gte {
            return Ok(IrMatcher::NumericGte(IrNumber::Literal(n)));
        }
        if ctx.lt {
            return Ok(IrMatcher::NumericLt(IrNumber::Literal(n)));
        }
        if ctx.lte {
            return Ok(IrMatcher::NumericLte(IrNumber::Literal(n)));
        }
    }

    match value {
        SigmaValue::Integer(n) => {
            if ctx.contains || ctx.startswith || ctx.endswith {
                return Ok(lower_str(plain_pattern(&n.to_string()), ctx));
            }
            return Ok(IrMatcher::NumericEq(IrNumber::Literal((*n).into())));
        }
        SigmaValue::Float(n) => {
            if ctx.contains || ctx.startswith || ctx.endswith {
                return Ok(lower_str(plain_pattern(&n.to_string()), ctx));
            }
            return Ok(IrMatcher::NumericEq(IrNumber::Literal((*n).into())));
        }
        SigmaValue::Bool(b) => return Ok(IrMatcher::BoolEq(*b)),
        SigmaValue::Null => return Ok(IrMatcher::Null),
        SigmaValue::String(_) => {}
    }

    let sigma_str = match value {
        SigmaValue::String(s) => s,
        _ => unreachable!(),
    };

    // Encoding transforms operate on the untransformed plain text and are kept
    // explicit for the compile/convert consumers to interpret.
    let enc = encodings(ctx);
    if !enc.is_empty() {
        let pattern = pattern_from_sigma(sigma_str);
        check_encodable(&enc, &pattern)?;
        return Ok(IrMatcher::Encoded {
            encodings: enc,
            op: str_op(ctx),
            pattern,
            case_insensitive: ci,
        });
    }

    Ok(lower_str(pattern_from_sigma(sigma_str), ctx))
}

/// Lower an `expand` value from its raw source text. Placeholders a pipeline
/// already resolved are gone, so a value without any lowers like a value
/// without `expand`; the remaining placeholders are filled from event fields
/// at match time.
fn lower_expand(s: &SigmaString, ctx: &ModCtx) -> Result<IrMatcher> {
    let mut template = Vec::new();
    let mut parts = Vec::new();
    let mut has_placeholder = false;
    let mut has_wildcard = false;
    for segment in scan_expand(&s.original) {
        match segment {
            ExpandSegment::Literal(text) => {
                template.push(IrExpandPart::Literal(text.clone()));
                parts.push(StringPart::Plain(text));
            }
            ExpandSegment::Wildcard(c) => {
                has_wildcard = true;
                parts.push(StringPart::Special(c));
            }
            ExpandSegment::Placeholder(name) => {
                has_placeholder = true;
                template.push(IrExpandPart::Placeholder(name));
            }
        }
    }

    let mut plain_ctx = *ctx;
    plain_ctx.expand = false;
    if !has_placeholder {
        let value = SigmaValue::String(SigmaString {
            parts,
            original: s.original.clone(),
        });
        return lower_value(&value, &plain_ctx);
    }
    if has_wildcard {
        return Err(IrError::IncompatibleValue(
            "|expand placeholders that no pipeline resolved cannot be combined with wildcards"
                .into(),
        ));
    }
    if !encodings(ctx).is_empty() {
        return Err(IrError::IncompatibleValue(
            "|expand placeholders that no pipeline resolved cannot be combined with encoding modifiers".into(),
        ));
    }
    Ok(IrMatcher::Expand {
        template,
        op: str_op(ctx),
        case_insensitive: ctx.is_case_insensitive(),
    })
}

fn lower_str(pattern: IrPattern, ctx: &ModCtx) -> IrMatcher {
    IrMatcher::Str {
        op: str_op(ctx),
        pattern,
        case_insensitive: ctx.is_case_insensitive(),
    }
}

/// Lower a keyword value (case-insensitive contains by default).
///
/// Keywords carry no field and match substring-wise across all event values;
/// the faithful pattern lets eval reproduce the plain-vs-wildcard behavior and
/// convert render the term.
/// A field-less boolean searches the event for the word `true` or `false`.
/// It has no `contains`, so it lowers like a field-less string without one.
pub(super) fn lower_fieldless_bool(b: bool) -> IrMatcher {
    IrMatcher::Str {
        op: IrStrOp::Exact,
        pattern: plain_pattern(if b { "true" } else { "false" }),
        case_insensitive: true,
    }
}

pub(super) fn lower_value_keywords(value: &SigmaValue) -> Result<IrMatcher> {
    let ci = true;
    match value {
        SigmaValue::String(s) => Ok(IrMatcher::Str {
            op: IrStrOp::Contains,
            pattern: pattern_from_sigma(s),
            case_insensitive: ci,
        }),
        SigmaValue::Integer(n) => Ok(IrMatcher::NumericEq(IrNumber::Literal((*n).into()))),
        SigmaValue::Float(n) => Ok(IrMatcher::NumericEq(IrNumber::Literal((*n).into()))),
        // Keywords search text, so a YAML boolean is the word `true`/`false`.
        SigmaValue::Bool(b) => Ok(IrMatcher::Str {
            op: IrStrOp::Contains,
            pattern: plain_pattern(if *b { "true" } else { "false" }),
            case_insensitive: ci,
        }),
        SigmaValue::Null => Ok(IrMatcher::Null),
    }
}
