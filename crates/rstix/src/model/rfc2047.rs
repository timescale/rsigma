//! RFC 2047 encoded-word decoding for email header values (STIX §6.6).

use base64::{Engine, engine::general_purpose::STANDARD};
use encoding_rs::Encoding;

/// Decode RFC 2047 encoded-words in `value` (STIX §6.6 MUST before inclusion).
///
/// Plain strings without `=?` are returned unchanged. Text that is not a
/// well-formed encoded-word, or names a charset this decoder does not know,
/// is kept as written. Whitespace between two adjacent encoded-words is
/// dropped (RFC 2047 §6.2).
pub fn decode_header_value(value: &str) -> String {
    if !value.contains("=?") {
        return value.to_owned();
    }

    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    let mut after_word = false;
    while let Some(start) = rest.find("=?") {
        let (before, candidate) = rest.split_at(start);
        match decode_encoded_word(candidate) {
            Some(word) => {
                let only_space = before
                    .bytes()
                    .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'));
                if !(after_word && only_space) {
                    out.push_str(before);
                }
                out.push_str(&word.decoded);
                rest = &candidate[word.consumed..];
                after_word = true;
            }
            None => {
                out.push_str(before);
                out.push_str("=?");
                rest = &candidate[2..];
                after_word = false;
            }
        }
    }
    out.push_str(rest);
    out
}

struct DecodedWord {
    decoded: String,
    consumed: usize,
}

/// `token` from RFC 2047 §2: printable ASCII without SPACE, CTLs, or especials.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| {
            b.is_ascii_graphic()
                && !matches!(
                    b,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'.'
                        | b'='
                )
        })
}

fn decode_encoded_word(input: &str) -> Option<DecodedWord> {
    let body = input.strip_prefix("=?")?;
    let (charset, body) = body.split_once('?')?;
    let (encoding, body) = body.split_once('?')?;
    let payload_end = body.find("?=")?;
    let payload = &body[..payload_end];
    if !is_token(charset)
        || !is_token(encoding)
        || !payload.bytes().all(|b| b.is_ascii_graphic() && b != b'?')
    {
        return None;
    }
    let consumed = 2 + charset.len() + 1 + encoding.len() + 1 + payload_end + 2;

    // RFC 2231 §5 allows a language suffix: `charset*language`.
    let charset = charset.split_once('*').map_or(charset, |(name, _)| name);
    let encoding_rs = Encoding::for_label(charset.as_bytes())?;
    let bytes = if encoding.eq_ignore_ascii_case("Q") {
        decode_q_payload(payload)?
    } else if encoding.eq_ignore_ascii_case("B") {
        STANDARD.decode(payload).ok()?
    } else {
        return None;
    };
    let (decoded, _, _) = encoding_rs.decode(&bytes);
    Some(DecodedWord {
        decoded: decoded.into_owned(),
        consumed,
    })
}

fn decode_q_payload(payload: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(payload.len());
    let mut input = payload.bytes();
    while let Some(byte) = input.next() {
        match byte {
            b'_' => bytes.push(b' '),
            b'=' => {
                let hi = hex_value(input.next()?)?;
                let lo = hex_value(input.next()?)?;
                bytes.push(hi << 4 | lo);
            }
            other => bytes.push(other),
        }
    }
    Some(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_q_encoded_word() {
        let decoded = decode_header_value("=?UTF-8?Q?hello=20world?=");
        assert_eq!(decoded, "hello world");
    }

    #[test]
    fn leaves_plain_text_unchanged() {
        assert_eq!(
            decode_header_value("Conference Agenda"),
            "Conference Agenda"
        );
    }

    #[test]
    fn decodes_b_words_and_charsets() {
        assert_eq!(decode_header_value("=?utf-8?B?w6l0w6k=?="), "été");
        assert_eq!(decode_header_value("=?ISO-8859-1?Q?caf=E9?="), "café");
        assert_eq!(decode_header_value("=?UTF-8*en?Q?hi?="), "hi");
    }

    #[test]
    fn drops_space_between_adjacent_words_only() {
        assert_eq!(decode_header_value("=?UTF-8?Q?a?= =?UTF-8?Q?b?="), "ab");
        assert_eq!(
            decode_header_value("=?UTF-8?Q?a?= x =?UTF-8?Q?b?="),
            "a x b"
        );
        assert_eq!(decode_header_value("re: =?UTF-8?Q?a?="), "re: a");
    }

    #[test]
    fn malformed_words_stay_as_written_and_later_words_still_decode() {
        for (input, expected) in [
            ("=?UTF-8?Q?bad=ZZ?= =?UTF-8?Q?ok?=", "=?UTF-8?Q?bad=ZZ?= ok"),
            ("=?UTF-8?X?abc?=", "=?UTF-8?X?abc?="),
            ("=?no-such-charset?Q?abc?=", "=?no-such-charset?Q?abc?="),
            ("=?UTF-8?Q?a b?=", "=?UTF-8?Q?a b?="),
            ("=?UTF-8?B?!!!?=", "=?UTF-8?B?!!!?="),
            ("=?", "=?"),
            ("x =? y", "x =? y"),
            ("=?UTF-8?Q?=", "=?UTF-8?Q?="),
        ] {
            assert_eq!(decode_header_value(input), expected, "{input}");
        }
    }

    #[test]
    fn q_payload_never_truncates_non_ascii_characters() {
        // `Ł` is U+0141; a byte cast would turn it into `A` and form valid hex.
        assert_eq!(decode_header_value("=?UTF-8?Q?=ŁŁ?="), "=?UTF-8?Q?=ŁŁ?=");
        assert_eq!(decode_header_value("=?UTF-8?Q?é?="), "=?UTF-8?Q?é?=");
    }

    #[test]
    fn nested_words_decode_one_level() {
        let once = decode_header_value("=?UTF-8?Q?=3D=3FUTF-8=3FQ=3Fx=3F=3D?=");
        assert_eq!(once, "=?UTF-8?Q?x?=");
        assert_eq!(decode_header_value("=?UTF-8?Q??="), "");
    }
}
