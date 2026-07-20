//! Lower a single `SigmaValue` under a modifier context into [`IrMatcher`].

use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rsigma_parser::{SigmaString, SigmaValue};

use crate::error::IrError;
use crate::{IrMatcher, IrNumber, IrValue};

use super::helpers::{
    Result, base64_offset_patterns, build_regex_pattern, expand_windash, parse_expand_template,
    sigma_parts_to_regex_pattern, sigma_string_to_bytes, to_utf16_bom_bytes, to_utf16be_bytes,
    to_utf16le_bytes, value_to_f64, value_to_plain_string,
};
use super::mod_ctx::ModCtx;

fn lit(s: impl Into<String>) -> IrValue {
    IrValue::Literal(s.into())
}

fn maybe_lower(plain: &str, ci: bool) -> String {
    if ci {
        plain.to_lowercase()
    } else {
        plain.to_string()
    }
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
        let full = build_regex_pattern(&pattern, ctx.ignore_case, ctx.multiline, ctx.dotall)?;
        return Ok(IrMatcher::Regex { pattern: lit(full) });
    }

    if ctx.cidr {
        let cidr_str = value_to_plain_string(value)?;
        let _: ipnet::IpNet = cidr_str.parse()?;
        return Ok(IrMatcher::Cidr {
            network: lit(cidr_str),
        });
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
                return lower_string_value(&n.to_string(), ctx);
            }
            return Ok(IrMatcher::NumericEq(IrNumber::Literal(*n as f64)));
        }
        SigmaValue::Float(n) => {
            if ctx.contains || ctx.startswith || ctx.endswith {
                return lower_string_value(&n.to_string(), ctx);
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

    let mut bytes = sigma_string_to_bytes(sigma_str);

    if ctx.wide {
        bytes = to_utf16le_bytes(&bytes);
    }
    if ctx.utf16be {
        bytes = to_utf16be_bytes(&bytes);
    }
    if ctx.utf16 {
        bytes = to_utf16_bom_bytes(&bytes);
    }

    if ctx.base64 {
        let encoded = BASE64_STANDARD.encode(&bytes);
        return lower_string_value(&encoded, ctx);
    }

    if ctx.base64offset {
        let patterns = base64_offset_patterns(&bytes);
        let matchers: Vec<IrMatcher> = patterns
            .into_iter()
            .map(|p| IrMatcher::Contains {
                value: lit(maybe_lower(&p, ci)),
                case_insensitive: ci,
            })
            .collect();
        return Ok(IrMatcher::AnyOf(matchers));
    }

    if ctx.windash {
        let plain = sigma_str
            .as_plain()
            .unwrap_or_else(|| sigma_str.original.clone());
        let variants = expand_windash(&plain)?;
        let matchers: Result<Vec<IrMatcher>> = variants
            .into_iter()
            .map(|v| lower_string_value(&v, ctx))
            .collect();
        return Ok(IrMatcher::AnyOf(matchers?));
    }

    lower_sigma_string(sigma_str, ctx)
}

fn lower_sigma_string(sigma_str: &SigmaString, ctx: &ModCtx) -> Result<IrMatcher> {
    let ci = ctx.is_case_insensitive();

    if sigma_str.is_plain() {
        let plain = sigma_str.as_plain().unwrap_or_default();
        return lower_string_value(&plain, ctx);
    }

    let pattern = sigma_parts_to_regex_pattern(
        &sigma_str.parts,
        ci,
        ctx.contains,
        ctx.startswith,
        ctx.endswith,
    );
    Regex::new(&pattern)?;
    Ok(IrMatcher::Regex {
        pattern: lit(pattern),
    })
}

fn lower_string_value(plain: &str, ctx: &ModCtx) -> Result<IrMatcher> {
    let ci = ctx.is_case_insensitive();
    let value = lit(maybe_lower(plain, ci));

    if ctx.contains {
        Ok(IrMatcher::Contains {
            value,
            case_insensitive: ci,
        })
    } else if ctx.startswith {
        Ok(IrMatcher::StartsWith {
            value,
            case_insensitive: ci,
        })
    } else if ctx.endswith {
        Ok(IrMatcher::EndsWith {
            value,
            case_insensitive: ci,
        })
    } else {
        Ok(IrMatcher::Exact {
            value,
            case_insensitive: ci,
        })
    }
}

/// Lower a keyword value (case-insensitive contains by default).
pub(super) fn lower_value_keywords(value: &SigmaValue) -> Result<IrMatcher> {
    let ci = true;
    match value {
        SigmaValue::String(s) => {
            if s.is_plain() {
                let plain = s.as_plain().unwrap_or_default();
                Ok(IrMatcher::Contains {
                    value: lit(maybe_lower(&plain, ci)),
                    case_insensitive: ci,
                })
            } else {
                let pattern = super::helpers::keywords_wildcard_pattern(&s.parts, ci);
                Regex::new(&pattern)?;
                Ok(IrMatcher::Regex {
                    pattern: lit(pattern),
                })
            }
        }
        SigmaValue::Integer(n) => Ok(IrMatcher::NumericEq(IrNumber::Literal(*n as f64))),
        SigmaValue::Float(n) => Ok(IrMatcher::NumericEq(IrNumber::Literal(*n))),
        SigmaValue::Bool(b) => Ok(IrMatcher::BoolEq(*b)),
        SigmaValue::Null => Ok(IrMatcher::Null),
    }
}

// Re-export Regex for lower_sigma_string validation without pulling into callers.
use regex::Regex;
