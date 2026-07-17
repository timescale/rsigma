//! RFC 2047 encoded-word decoding for email header values (STIX §6.6).

use base64::{Engine, engine::general_purpose::STANDARD};
use encoding_rs::{Encoding, UTF_8};

/// Decode RFC 2047 encoded-words in `value` (STIX §6.6 MUST before inclusion).
///
/// Plain strings without `=?` are returned unchanged.
pub fn decode_header_value(value: &str) -> String {
    if !value.contains("=?") {
        return value.to_owned();
    }

    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("=?") {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let Some(decoded) = decode_encoded_word(rest) else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&decoded.decoded);
        rest = &rest[decoded.consumed..];
    }
    out.push_str(rest);
    out
}

struct DecodedWord {
    decoded: String,
    consumed: usize,
}

fn decode_encoded_word(input: &str) -> Option<DecodedWord> {
    let input = input.strip_prefix("=?")?;
    let charset_end = input.find('?')?;
    let charset = &input[..charset_end];
    let rest = &input[charset_end + 1..];
    let encoding_end = rest.find('?')?;
    let encoding = &rest[..encoding_end];
    let payload_part = &rest[encoding_end + 1..];
    let payload_end = payload_part.find("?=")?;
    let payload = &payload_part[..payload_end];
    let consumed = 2 + charset_end + 1 + encoding_end + 1 + payload_end + 2;

    let bytes = match encoding.to_ascii_uppercase().as_str() {
        "Q" => decode_q_payload(payload)?,
        "B" => STANDARD.decode(payload).ok()?,
        _ => return None,
    };
    let encoding = Encoding::for_label(charset.as_bytes()).unwrap_or(UTF_8);
    let (decoded, _, _) = encoding.decode(&bytes);
    Some(DecodedWord {
        decoded: decoded.into_owned(),
        consumed,
    })
}

fn decode_q_payload(payload: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(payload.len());
    let mut chars = payload.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '_' {
            bytes.push(b' ');
            continue;
        }
        if ch == '=' {
            let hi = chars.next()?;
            let lo = chars.next()?;
            let hex = [hi as u8, lo as u8];
            bytes.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
            continue;
        }
        bytes.push(ch as u8);
    }
    Some(bytes)
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
}
