//! Lower a single `SigmaValue` under a modifier context into [`IrMatcher`].
//!
//! Lowering is purely structural: it resolves *which* comparison applies and
//! preserves the value faithfully (original case, wildcards intact, encodings
//! recorded as explicit [`IrEncoding`] steps). It does **not** lowercase,
//! compile regexes, or expand encodings; those are the compile step's job in
//! eval and are rendered structurally by convert.

use rsigma_parser::value::{SpecialChar, StringPart};
use rsigma_parser::{SigmaString, SigmaValue};

use crate::error::IrError;
use crate::{IrEncoding, IrMatcher, IrNumber, IrPattern, IrPatternPart, IrStrOp};

use super::helpers::{Result, parse_expand_template, value_to_f64, value_to_plain_string};
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

    if ctx.expand {
        let plain = value_to_plain_string(value)?;
        let template = parse_expand_template(&plain);
        return Ok(IrMatcher::Expand {
            template,
            case_insensitive: ci,
        });
    }

    if let Some(part) = ctx.timestamp_part {
        let inner = match value {
            SigmaValue::Integer(n) => IrMatcher::NumericEq(IrNumber::Literal(*n as f64)),
            SigmaValue::Float(n) => IrMatcher::NumericEq(IrNumber::Literal(*n)),
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                let n: f64 = plain.parse().map_err(|_| {
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
        let field_name = value_to_plain_string(value)?;
        return Ok(IrMatcher::FieldRef {
            field: field_name,
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
        return Ok(IrMatcher::Cidr { network: cidr_str });
    }

    if ctx.has_numeric_comparison() {
        let n = value_to_f64(value)?;
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

    if ctx.has_neq() {
        let mut inner_ctx = *ctx;
        inner_ctx.neq = false;
        let inner = lower_value(value, &inner_ctx)?;
        return Ok(IrMatcher::Not(Box::new(inner)));
    }

    match value {
        SigmaValue::Integer(n) => {
            if ctx.contains || ctx.startswith || ctx.endswith {
                return Ok(lower_str(plain_pattern(&n.to_string()), ctx));
            }
            return Ok(IrMatcher::NumericEq(IrNumber::Literal(*n as f64)));
        }
        SigmaValue::Float(n) => {
            if ctx.contains || ctx.startswith || ctx.endswith {
                return Ok(lower_str(plain_pattern(&n.to_string()), ctx));
            }
            return Ok(IrMatcher::NumericEq(IrNumber::Literal(*n)));
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
        let plain = sigma_str
            .as_plain()
            .unwrap_or_else(|| sigma_str.original.clone());
        return Ok(IrMatcher::Encoded {
            encodings: enc,
            op: str_op(ctx),
            value: plain,
            case_insensitive: ci,
        });
    }

    Ok(lower_str(pattern_from_sigma(sigma_str), ctx))
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
pub(super) fn lower_value_keywords(value: &SigmaValue) -> Result<IrMatcher> {
    let ci = true;
    match value {
        SigmaValue::String(s) => Ok(IrMatcher::Str {
            op: IrStrOp::Contains,
            pattern: pattern_from_sigma(s),
            case_insensitive: ci,
        }),
        SigmaValue::Integer(n) => Ok(IrMatcher::NumericEq(IrNumber::Literal(*n as f64))),
        SigmaValue::Float(n) => Ok(IrMatcher::NumericEq(IrNumber::Literal(*n))),
        SigmaValue::Bool(b) => Ok(IrMatcher::BoolEq(*b)),
        SigmaValue::Null => Ok(IrMatcher::Null),
    }
}
