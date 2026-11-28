//! Compile resolved IR string matchers into concrete [`CompiledMatcher`]s.

use regex::Regex;

use rsigma_ir::encoding::expand_encoded;
use rsigma_ir::{IrEncoding, IrPattern, IrPatternPart, IrStrOp};
use rsigma_parser::validate::WINDASH_CHARS;

use crate::error::{EvalError, Result};
use crate::matcher::{CompiledMatcher, GroupMode};

/// Compile a string match over a wildcard-aware pattern.
pub(super) fn compile_str(op: IrStrOp, pattern: &IrPattern, ci: bool) -> Result<CompiledMatcher> {
    match pattern.as_plain() {
        Some(plain) => Ok(compile_plain(op, &plain, ci)),
        None => compile_wildcard(op, pattern, ci),
    }
}

/// Compile a string match over a plain value (no wildcards).
pub(super) fn compile_plain(op: IrStrOp, plain: &str, ci: bool) -> CompiledMatcher {
    let value = if ci {
        plain.to_lowercase()
    } else {
        plain.to_string()
    };
    match op {
        IrStrOp::Contains => CompiledMatcher::Contains {
            value,
            case_insensitive: ci,
        },
        IrStrOp::StartsWith => CompiledMatcher::StartsWith {
            value,
            case_insensitive: ci,
        },
        IrStrOp::EndsWith => CompiledMatcher::EndsWith {
            value,
            case_insensitive: ci,
        },
        IrStrOp::Exact => CompiledMatcher::Exact {
            value,
            case_insensitive: ci,
        },
    }
}

/// Compile a pattern with wildcards into a regex, anchored as `op` requires.
fn compile_wildcard(op: IrStrOp, pattern: &IrPattern, ci: bool) -> Result<CompiledMatcher> {
    let mut re = String::from(if ci { "(?is)" } else { "(?s)" });
    if !matches!(op, IrStrOp::Contains | IrStrOp::EndsWith) {
        re.push('^');
    }
    for part in &pattern.parts {
        match part {
            IrPatternPart::Literal(text) => re.push_str(&regex::escape(text)),
            IrPatternPart::WildcardMulti => re.push_str(".*"),
            IrPatternPart::WildcardSingle => re.push('.'),
        }
    }
    if !matches!(op, IrStrOp::Contains | IrStrOp::StartsWith) {
        re.push('$');
    }
    let regex = Regex::new(&re).map_err(EvalError::InvalidRegex)?;
    Ok(CompiledMatcher::Regex(regex))
}

/// Compile an encoding-transformed string match.
///
/// A `windash` value with dash characters and no base64 strategy compiles to
/// one regex (see [`compile_windash`]); every other value compiles into one
/// matcher per encoded variant.
pub(super) fn compile_encoded(
    encodings: &[IrEncoding],
    op: IrStrOp,
    pattern: &IrPattern,
    ci: bool,
) -> Result<CompiledMatcher> {
    if let Some(matcher) = compile_windash(encodings, op, pattern, ci)? {
        return Ok(matcher);
    }
    let mut matchers = expand_encoded(encodings, op, pattern)?
        .iter()
        .map(|(op, pattern)| compile_str(*op, pattern, ci))
        .collect::<Result<Vec<_>>>()?;
    Ok(match matchers.len() {
        1 => matchers.remove(0),
        _ => CompiledMatcher::AnyOf(matchers),
    })
}

/// The regex class of the characters `windash` treats as interchangeable.
const WINDASH_CLASS: &str = r"[\-/\x{2013}\x{2014}\x{2015}]";

/// Compile a `windash` value into a single regex with [`WINDASH_CLASS`] at
/// every dash position, instead of one matcher per combination of dashes.
///
/// The regex matches exactly the strings the expanded variants match:
///
/// - With wildcards, every variant was a `(?is)` (or `(?s)` under `cased`)
///   regex, so the class takes the place of the alternation.
/// - Without wildcards and case-insensitive, every variant was a plain
///   comparison against the `to_lowercase`d haystack. The regex is built from
///   the lowercased value without `(?i)` and runs inside a
///   [`CompiledMatcher::CaseInsensitiveGroup`], which lowercases the haystack
///   the same way. Lowercasing never produces or changes a dash character, so
///   the dash positions are those of the value.
/// - Without wildcards and `cased`, the regex runs on the haystack as is.
///
/// A UTF-16 encoding interleaves each character with a NUL, as
/// [`rsigma_ir::encoding::utf16_pattern`] does. Returns `None` when the value
/// has no dash character or a base64 strategy applies, whose output depends
/// on every byte of each variant.
pub(super) fn compile_windash(
    encodings: &[IrEncoding],
    op: IrStrOp,
    pattern: &IrPattern,
    ci: bool,
) -> Result<Option<CompiledMatcher>> {
    if !encodings.contains(&IrEncoding::Windash)
        || encodings
            .iter()
            .any(|e| matches!(e, IrEncoding::Base64 | IrEncoding::Base64Offset))
    {
        return Ok(None);
    }
    let has_dash = pattern.parts.iter().any(|part| {
        matches!(part, IrPatternPart::Literal(text) if text.chars().any(|c| WINDASH_CHARS.contains(&c)))
    });
    if !has_dash {
        return Ok(None);
    }
    let utf16 = encodings.iter().copied().find(|e| {
        matches!(
            e,
            IrEncoding::Wide | IrEncoding::Utf16 | IrEncoding::Utf16Be
        )
    });

    let plain = pattern.as_plain();
    let lowered = ci && plain.is_some();
    let mut re = String::new();
    if plain.is_none() {
        re.push_str(if ci { "(?is)" } else { "(?s)" });
    }
    if !matches!(op, IrStrOp::Contains | IrStrOp::EndsWith) {
        re.push('^');
    }
    if utf16 == Some(IrEncoding::Utf16) {
        re.push_str(&regex::escape("\u{feff}"));
    }
    let push_literal = |text: &str, re: &mut String| {
        for c in text.chars() {
            let unit = if WINDASH_CHARS.contains(&c) {
                WINDASH_CLASS.to_string()
            } else {
                regex::escape(c.encode_utf8(&mut [0; 4]))
            };
            match utf16 {
                Some(IrEncoding::Utf16Be) => {
                    re.push_str(r"\x00");
                    re.push_str(&unit);
                }
                Some(_) => {
                    re.push_str(&unit);
                    re.push_str(r"\x00");
                }
                None => re.push_str(&unit),
            }
        }
    };
    match plain {
        Some(text) if lowered => push_literal(&text.to_lowercase(), &mut re),
        Some(text) => push_literal(&text, &mut re),
        None => {
            for part in &pattern.parts {
                match part {
                    IrPatternPart::Literal(text) => push_literal(text, &mut re),
                    IrPatternPart::WildcardMulti => re.push_str(".*"),
                    IrPatternPart::WildcardSingle => re.push('.'),
                }
            }
        }
    }
    if !matches!(op, IrStrOp::Contains | IrStrOp::StartsWith) {
        re.push('$');
    }
    let regex = CompiledMatcher::Regex(Regex::new(&re).map_err(EvalError::InvalidRegex)?);
    Ok(Some(if lowered {
        CompiledMatcher::CaseInsensitiveGroup {
            children: vec![regex],
            mode: GroupMode::Any,
        }
    } else {
        regex
    }))
}
