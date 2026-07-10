//! STIX §9.6.1 NFC normalization for LIKE/MATCHES string comparisons.

use std::borrow::Cow;

use unicode_normalization::UnicodeNormalization;

/// NFC-normalize a string per STIX §9.6.1 (`LIKE` / `MATCHES` operands).
pub(crate) fn nfc<'a>(input: &'a str) -> Cow<'a, str> {
    if input.is_ascii() {
        return Cow::Borrowed(input);
    }
    let normalized: String = input.nfc().collect();
    if normalized == input {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfc_composes_ograve() {
        let decomposed = "o\u{0300}";
        let composed = nfc(decomposed);
        assert_eq!(composed.as_ref(), "\u{00F2}");
    }
}
