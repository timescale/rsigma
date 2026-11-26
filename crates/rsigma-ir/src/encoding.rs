//! Expansion of encoding modifiers into plain string matches.
//!
//! [`IrMatcher::Encoded`] keeps the untransformed value and its encodings.
//! [`expand_encoded`] replays them into the concrete string matches that eval
//! compiles and conversion backends render, so both agree on the variants a
//! rule matches.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::error::IrError;
use crate::hir::{IrDetection, IrEncoding, IrMatcher, IrPattern, IrPatternPart, IrStrOp};

/// Replacement characters for the `windash` modifier per Sigma spec:
/// `-`, `/`, `–` (en dash U+2013), `—` (em dash U+2014), `―` (horizontal bar U+2015).
const WINDASH_CHARS: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];

/// Maximum number of dash positions allowed in windash expansion.
/// 5^8 = 390,625 variants; beyond this the expansion is too large.
pub const MAX_WINDASH_DASHES: usize = 8;

/// Replace every [`IrMatcher::Encoded`] in `detections` with the plain string
/// matches its encodings produce: a single [`IrMatcher::Str`], or an
/// [`IrMatcher::AnyOf`] of them when there are several variants.
pub fn expand_encoded_detections(
    detections: &mut HashMap<String, IrDetection>,
) -> Result<(), IrError> {
    detections
        .values_mut()
        .try_for_each(expand_encoded_detection)
}

/// Replace every [`IrMatcher::Encoded`] in one detection, as
/// [`expand_encoded_detections`] does for a whole detection map.
pub fn expand_encoded_detection(det: &mut IrDetection) -> Result<(), IrError> {
    match det {
        IrDetection::AllOf(items) => items
            .iter_mut()
            .try_for_each(|item| expand_encoded_matcher(&mut item.matcher)),
        IrDetection::AnyOf(dets) | IrDetection::And(dets) => {
            dets.iter_mut().try_for_each(expand_encoded_detection)
        }
        IrDetection::Keywords(matcher) => expand_encoded_matcher(matcher),
        IrDetection::ArrayMatch { body, .. } => expand_encoded_detection(body),
        IrDetection::Conditional { named, .. } => expand_encoded_detections(named),
    }
}

/// Replace every [`IrMatcher::Encoded`] in `matcher` with the plain string
/// matches its encodings produce, as [`expand_encoded_detections`] does for a
/// whole detection map.
pub fn expand_encoded_matcher(matcher: &mut IrMatcher) -> Result<(), IrError> {
    match matcher {
        IrMatcher::Encoded {
            encodings,
            op,
            pattern,
            case_insensitive,
        } => {
            let ci = *case_insensitive;
            let mut variants: Vec<IrMatcher> = expand_encoded(encodings, *op, pattern)?
                .into_iter()
                .map(|(op, pattern)| IrMatcher::Str {
                    op,
                    pattern,
                    case_insensitive: ci,
                })
                .collect();
            *matcher = match variants.len() {
                1 => variants.remove(0),
                _ => IrMatcher::AnyOf(variants),
            };
            Ok(())
        }
        IrMatcher::Not(inner) | IrMatcher::TimestampPart { inner, .. } => {
            expand_encoded_matcher(inner)
        }
        IrMatcher::AnyOf(ms) | IrMatcher::AllOf(ms) => {
            ms.iter_mut().try_for_each(expand_encoded_matcher)
        }
        _ => Ok(()),
    }
}

/// Expand an encoding-transformed string match into plain string matches,
/// one per variant, any of which matches.
///
/// Windash variants are expanded first, then each variant is encoded as
/// UTF-16 and base64 or base64offset when those apply. A base64offset
/// variant is a substring of the encoded value, so its operator is
/// [`IrStrOp::Contains`]; every other variant keeps `op`.
pub fn expand_encoded(
    encodings: &[IrEncoding],
    op: IrStrOp,
    pattern: &IrPattern,
) -> Result<Vec<(IrStrOp, IrPattern)>, IrError> {
    let variants = if encodings.contains(&IrEncoding::Windash) {
        windash_variants(pattern)?
    } else {
        vec![pattern.clone()]
    };
    let utf16 = encodings.iter().copied().find(|e| {
        matches!(
            e,
            IrEncoding::Wide | IrEncoding::Utf16 | IrEncoding::Utf16Be
        )
    });
    let base64 = encodings
        .iter()
        .copied()
        .find(|e| matches!(e, IrEncoding::Base64 | IrEncoding::Base64Offset));

    let mut out = Vec::with_capacity(variants.len());
    for variant in &variants {
        let Some(base64) = base64 else {
            let encoded = match utf16 {
                Some(encoding) => utf16_pattern(encoding, variant),
                None => variant.clone(),
            };
            out.push((op, encoded));
            continue;
        };
        let plain = variant.as_plain().ok_or_else(|| {
            IrError::InvalidModifiers("|base64 and |base64offset do not support wildcards".into())
        })?;
        let bytes = match utf16 {
            Some(IrEncoding::Wide) => to_utf16le_bytes(plain.as_bytes()),
            Some(IrEncoding::Utf16Be) => to_utf16be_bytes(plain.as_bytes()),
            Some(IrEncoding::Utf16) => to_utf16_bom_bytes(plain.as_bytes()),
            _ => plain.into_bytes(),
        };
        if base64 == IrEncoding::Base64 {
            out.push((op, literal(BASE64_STANDARD.encode(&bytes))));
        } else {
            out.extend(
                base64_offset_patterns(&bytes)
                    .into_iter()
                    .map(|p| (IrStrOp::Contains, literal(p))),
            );
        }
    }
    Ok(out)
}

/// Reject values an encoding chain cannot represent: wildcards under base64,
/// whose output has no character boundaries to keep them at, and non-ASCII
/// text under a UTF-16 encoding that is matched as a string.
pub fn check_encodable(encodings: &[IrEncoding], pattern: &IrPattern) -> Result<(), IrError> {
    let base64 = encodings
        .iter()
        .any(|e| matches!(e, IrEncoding::Base64 | IrEncoding::Base64Offset));
    if base64 && pattern.has_wildcards() {
        return Err(IrError::IncompatibleValue(
            "|base64 and |base64offset do not support wildcards; escape * and ? as \\* and \\? to match them literally".into(),
        ));
    }
    let utf16 = encodings.iter().any(|e| {
        matches!(
            e,
            IrEncoding::Wide | IrEncoding::Utf16 | IrEncoding::Utf16Be
        )
    });
    let non_ascii = pattern
        .parts
        .iter()
        .any(|p| matches!(p, IrPatternPart::Literal(t) if !t.is_ascii()));
    if utf16 && !base64 && non_ascii {
        return Err(IrError::IncompatibleValue(
            "|wide, |utf16, and |utf16be without |base64 or |base64offset require an ASCII value"
                .into(),
        ));
    }
    Ok(())
}

fn literal(text: String) -> IrPattern {
    IrPattern {
        parts: vec![IrPatternPart::Literal(text)],
    }
}

/// Convert bytes to UTF-16LE representation (wide string / utf16le).
pub fn to_utf16le_bytes(bytes: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(bytes);
    let mut wide = Vec::with_capacity(s.len() * 2);
    for c in s.chars() {
        let mut buf = [0u16; 2];
        let encoded = c.encode_utf16(&mut buf);
        for u in encoded {
            wide.extend_from_slice(&u.to_le_bytes());
        }
    }
    wide
}

/// Convert bytes to UTF-16BE representation.
pub fn to_utf16be_bytes(bytes: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(bytes);
    let mut wide = Vec::with_capacity(s.len() * 2);
    for c in s.chars() {
        let mut buf = [0u16; 2];
        let encoded = c.encode_utf16(&mut buf);
        for u in encoded {
            wide.extend_from_slice(&u.to_be_bytes());
        }
    }
    wide
}

/// Convert bytes to UTF-16 with BOM (little-endian, BOM = FF FE).
pub fn to_utf16_bom_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![0xFF, 0xFE];
    result.extend_from_slice(&to_utf16le_bytes(bytes));
    result
}

/// Generate base64 offset patterns for a byte sequence.
///
/// Produces up to 3 patterns for byte offsets 0, 1, and 2 within a
/// base64 3-byte alignment group. Each pattern is the stable middle
/// portion of the encoding: characters that depend on the bytes before or
/// after the value are dropped at both ends.
pub fn base64_offset_patterns(value: &[u8]) -> Vec<String> {
    const START: [usize; 3] = [0, 2, 3];
    const END_TRIM: [usize; 3] = [0, 3, 2];

    let mut patterns = Vec::with_capacity(3);
    for offset in 0..3usize {
        let mut padded = vec![0u8; offset];
        padded.extend_from_slice(value);
        let encoded = BASE64_STANDARD.encode(&padded);
        let end = encoded.len() - END_TRIM[(value.len() + offset) % 3];
        if START[offset] < end {
            patterns.push(encoded[START[offset]..end].to_string());
        }
    }
    patterns
}

/// Expand windash variants: every `-`, `/`, `–`, `—`, or `―` in a literal
/// part of `pattern` is a position, and each variant substitutes one of those
/// five characters at every position. Wildcards are kept as they are.
pub fn windash_variants(pattern: &IrPattern) -> Result<Vec<IrPattern>, IrError> {
    let positions: Vec<(usize, usize)> = pattern
        .parts
        .iter()
        .enumerate()
        .filter_map(|(i, part)| match part {
            IrPatternPart::Literal(text) => Some((i, text)),
            _ => None,
        })
        .flat_map(|(i, text)| {
            text.char_indices()
                .filter(|(_, c)| WINDASH_CHARS.contains(c))
                .map(move |(byte, _)| (i, byte))
        })
        .collect();

    if positions.is_empty() {
        return Ok(vec![pattern.clone()]);
    }

    let n = positions.len();
    if n > MAX_WINDASH_DASHES {
        return Err(IrError::InvalidModifiers(format!(
            "windash modifier: value contains {n} dash or slash characters, max is \
             {MAX_WINDASH_DASHES} (would generate {} variants)",
            5u64.saturating_pow(n as u32)
        )));
    }

    let total = WINDASH_CHARS.len().pow(n as u32);
    let mut variants = Vec::with_capacity(total);
    for combo in 0..total {
        let mut parts = pattern.parts.clone();
        let mut idx = combo;
        // Replace from back to front to preserve byte positions.
        for &(part, byte) in positions.iter().rev() {
            if let IrPatternPart::Literal(text) = &mut parts[part] {
                let width = text[byte..].chars().next().map_or(1, char::len_utf8);
                let replacement = WINDASH_CHARS[idx % WINDASH_CHARS.len()];
                text.replace_range(byte..byte + width, replacement.encode_utf8(&mut [0; 4]));
            }
            idx /= WINDASH_CHARS.len();
        }
        variants.push(IrPattern { parts });
    }

    Ok(variants)
}

/// Encode the literal parts of an ASCII `pattern` as UTF-16 code units, one
/// character per code unit, keeping wildcards. `utf16` adds a byte order mark.
pub fn utf16_pattern(encoding: IrEncoding, pattern: &IrPattern) -> IrPattern {
    let mut parts = Vec::with_capacity(pattern.parts.len() + 1);
    if encoding == IrEncoding::Utf16 {
        parts.push(IrPatternPart::Literal("\u{feff}".to_string()));
    }
    for part in &pattern.parts {
        parts.push(match part {
            IrPatternPart::Literal(text) => {
                let mut wide = String::with_capacity(text.len() * 2);
                for c in text.chars() {
                    if encoding == IrEncoding::Utf16Be {
                        wide.push('\0');
                        wide.push(c);
                    } else {
                        wide.push(c);
                        wide.push('\0');
                    }
                }
                IrPatternPart::Literal(wide)
            }
            other => other.clone(),
        });
    }
    IrPattern { parts }
}
