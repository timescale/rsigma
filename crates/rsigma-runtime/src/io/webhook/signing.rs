//! HMAC request signing for the webhook sink.
//!
//! Generates signature headers over the exact rendered body bytes so a
//! receiving endpoint can verify a delivery's authenticity and integrity, and
//! (for the timestamped schemes) reject replays. The default `standard` scheme
//! follows the cross-industry Standard Webhooks convention; `github` and
//! `custom` profiles cover GitHub-style and Stripe-style receivers.
//!
//! rsigma only *produces* signatures; a receiver must compare them in constant
//! time.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// HMAC hash function for the `custom` scheme.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Algorithm {
    Sha256,
    Sha512,
}

/// Output encoding for a `custom`-scheme signature.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Encoding {
    Hex,
    Base64,
}

/// A fully-resolved `custom` signing profile.
#[derive(Debug, Clone)]
pub(crate) struct CustomScheme {
    pub algorithm: Algorithm,
    pub encoding: Encoding,
    pub signature_header: String,
    /// Header value template; the `{signature}` token is required. Also
    /// supports `{timestamp}` and `{id}`.
    pub value_format: String,
    /// What gets HMAC'd. Supports `{body}`, `{timestamp}`, and `{id}`.
    pub signed_payload: String,
    pub timestamp_header: Option<String>,
    pub id_header: Option<String>,
}

/// The signing convention a webhook emits.
#[derive(Debug, Clone)]
pub(crate) enum SigningScheme {
    /// Standard Webhooks: `webhook-id` / `webhook-timestamp` /
    /// `webhook-signature: v1,<base64 HMAC-SHA256 of "{id}.{timestamp}.{body}">`.
    Standard,
    /// GitHub-style `X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of body>`.
    Github,
    /// Operator-defined header(s), algorithm, encoding, and payload template.
    Custom(CustomScheme),
}

impl SigningScheme {
    /// Header names this scheme emits, used at startup to reject a collision
    /// with a user-configured header (does not require the resolved keys).
    pub(crate) fn header_names(&self) -> Vec<String> {
        match self {
            SigningScheme::Standard => vec![
                "webhook-id".to_string(),
                "webhook-timestamp".to_string(),
                "webhook-signature".to_string(),
            ],
            SigningScheme::Github => vec!["X-Hub-Signature-256".to_string()],
            SigningScheme::Custom(c) => {
                let mut v = vec![c.signature_header.clone()];
                if let Some(h) = &c.timestamp_header {
                    v.push(h.clone());
                }
                if let Some(h) = &c.id_header {
                    v.push(h.clone());
                }
                v
            }
        }
    }
}

/// Renders signature headers for a webhook delivery.
///
/// Built once at startup from validated config. [`WebhookSigner::sign`] is a
/// pure function of its inputs, so a retry that re-supplies the same `now` and
/// `id` (from the per-delivery [`crate::io::DeliveryContext`]) reproduces an
/// identical signature.
pub(crate) struct WebhookSigner {
    scheme: SigningScheme,
    /// HMAC keys, primary first. A second key (rotation) produces a second
    /// signature so a receiver accepts either during a key rollover. Held in
    /// `Zeroizing` so the secret bytes are wiped from memory when the signer is
    /// dropped (paired with the `hmac` crate's `zeroize` feature, which wipes
    /// the key inside each transient MAC).
    keys: Vec<Zeroizing<Vec<u8>>>,
}

impl WebhookSigner {
    pub(crate) fn new(scheme: SigningScheme, keys: Vec<Zeroizing<Vec<u8>>>) -> Self {
        WebhookSigner { scheme, keys }
    }

    /// Header name/value pairs to add to the request, signing `body` with the
    /// configured scheme.
    pub(crate) fn sign(&self, body: &str, now: SystemTime, id: &str) -> Vec<(String, String)> {
        let ts = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        match &self.scheme {
            SigningScheme::Standard => {
                // Sign "{id}.{timestamp}.{body}" without allocating a combined
                // body-sized string: feed the parts to the MAC incrementally.
                let ts_str = ts.to_string();
                let parts: [&[u8]; 5] = [
                    id.as_bytes(),
                    b".",
                    ts_str.as_bytes(),
                    b".",
                    body.as_bytes(),
                ];
                let value = self
                    .keys
                    .iter()
                    .map(|k| format!("v1,{}", BASE64.encode(hmac_sha256_parts(k, &parts))))
                    .collect::<Vec<_>>()
                    .join(" ");
                vec![
                    ("webhook-id".to_string(), id.to_string()),
                    ("webhook-timestamp".to_string(), ts_str),
                    ("webhook-signature".to_string(), value),
                ]
            }
            SigningScheme::Github => {
                // Rotation is rejected at config time, so there is one key.
                let mac = hmac_sha256(&self.keys[0], body.as_bytes());
                vec![(
                    "X-Hub-Signature-256".to_string(),
                    format!("sha256={}", hex::encode(mac)),
                )]
            }
            SigningScheme::Custom(c) => {
                let ts_str = ts.to_string();
                let payload_values = [("body", body), ("timestamp", ts_str.as_str()), ("id", id)];
                let value = self
                    .keys
                    .iter()
                    .map(|k| {
                        let raw = match c.algorithm {
                            Algorithm::Sha256 => {
                                hmac_template::<HmacSha256>(k, &c.signed_payload, &payload_values)
                            }
                            Algorithm::Sha512 => {
                                hmac_template::<HmacSha512>(k, &c.signed_payload, &payload_values)
                            }
                        };
                        let sig = match c.encoding {
                            Encoding::Hex => hex::encode(raw),
                            Encoding::Base64 => BASE64.encode(raw),
                        };
                        let mut header = Vec::with_capacity(c.value_format.len() + sig.len());
                        expand(
                            &c.value_format,
                            &[
                                ("signature", sig.as_str()),
                                ("timestamp", ts_str.as_str()),
                                ("id", id),
                            ],
                            |part| header.extend_from_slice(part),
                        );
                        String::from_utf8(header).expect("UTF-8 parts concatenate to UTF-8")
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                let mut out = vec![(c.signature_header.clone(), value)];
                if let Some(h) = &c.timestamp_header {
                    out.push((h.clone(), ts_str));
                }
                if let Some(h) = &c.id_header {
                    out.push((h.clone(), id.to_string()));
                }
                out
            }
        }
    }
}

/// Expand the `{name}` tokens of `template` from `values` in one pass,
/// handing each literal run and each substituted value to `emit` in order.
///
/// Substituted text is never scanned again, so a value that itself contains
/// `{body}` or `{id}` is emitted verbatim. A brace that does not open a known
/// token is literal text.
fn expand(template: &str, values: &[(&str, &str)], mut emit: impl FnMut(&[u8])) {
    let mut literal = 0;
    let mut pos = 0;
    while let Some(offset) = template[pos..].find('{') {
        let open = pos + offset;
        let rest = &template[open + 1..];
        let token = values.iter().find(|(name, _)| {
            rest.strip_prefix(name)
                .is_some_and(|after| after.starts_with('}'))
        });
        match token {
            Some((name, value)) => {
                emit(&template.as_bytes()[literal..open]);
                emit(value.as_bytes());
                pos = open + name.len() + 2;
                literal = pos;
            }
            None => pos = open + 1,
        }
    }
    emit(&template.as_bytes()[literal..]);
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_sha256_parts(key, &[data])
}

fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

/// HMAC of `template` expanded from `values`, fed to the MAC part by part.
fn hmac_template<M: Mac + KeyInit>(key: &[u8], template: &str, values: &[(&str, &str)]) -> Vec<u8> {
    let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    expand(template, values, |part| mac.update(part));
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn standard_matches_the_published_spec_vector() {
        // The canonical Standard Webhooks (svix) test vector: the secret is the
        // base64 body of a `whsec_`-prefixed key.
        let key = BASE64.decode("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
        let signer = WebhookSigner::new(SigningScheme::Standard, vec![Zeroizing::new(key)]);

        let headers = signer.sign(
            r#"{"test": 2432232314}"#,
            at(1_614_265_330),
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
        );

        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(
            get("webhook-id").as_deref(),
            Some("msg_p5jXN8AQM9LWM0D4loKWxJek")
        );
        assert_eq!(get("webhook-timestamp").as_deref(), Some("1614265330"));
        assert_eq!(
            get("webhook-signature").as_deref(),
            Some("v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="),
        );
    }

    #[test]
    fn github_matches_the_documented_vector() {
        // GitHub's own documentation example.
        let signer = WebhookSigner::new(
            SigningScheme::Github,
            vec![Zeroizing::new(b"It's a Secret to Everybody".to_vec())],
        );
        let headers = signer.sign("Hello, World!", at(0), "unused");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "X-Hub-Signature-256");
        assert_eq!(
            headers[0].1,
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
        );
    }

    #[test]
    fn custom_renders_stripe_style_value_and_signed_payload() {
        let scheme = SigningScheme::Custom(CustomScheme {
            algorithm: Algorithm::Sha256,
            encoding: Encoding::Hex,
            signature_header: "Stripe-Signature".to_string(),
            value_format: "t={timestamp},v1={signature}".to_string(),
            signed_payload: "{timestamp}.{body}".to_string(),
            timestamp_header: None,
            id_header: None,
        });
        let key = b"top-secret".to_vec();
        let signer = WebhookSigner::new(scheme, vec![Zeroizing::new(key.clone())]);

        let body = r#"{"a":1}"#;
        let headers = signer.sign(body, at(1_700_000_000), "msg_x");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Stripe-Signature");

        // Independently recompute the HMAC over "{timestamp}.{body}".
        let expected = hex::encode(hmac_sha256(&key, format!("1700000000.{body}").as_bytes()));
        assert_eq!(headers[0].1, format!("t=1700000000,v1={expected}"));
    }

    #[test]
    fn custom_tokens_inside_the_body_are_signed_verbatim() {
        let scheme = SigningScheme::Custom(CustomScheme {
            algorithm: Algorithm::Sha256,
            encoding: Encoding::Hex,
            signature_header: "X-Signature".to_string(),
            value_format: "id={id},t={timestamp},v1={signature}".to_string(),
            signed_payload: "{id}.{timestamp}.{body}".to_string(),
            timestamp_header: None,
            id_header: None,
        });
        let key = b"top-secret".to_vec();
        let signer = WebhookSigner::new(scheme, vec![Zeroizing::new(key.clone())]);

        let body = r#"{"msg":"{timestamp} {id} {body} {signature} {unknown"}"#;
        let headers = signer.sign(body, at(1_700_000_000), "msg_{body}");

        let expected = hex::encode(hmac_sha256(
            &key,
            format!("msg_{{body}}.1700000000.{body}").as_bytes(),
        ));
        assert_eq!(
            headers[0].1,
            format!("id=msg_{{body}},t=1700000000,v1={expected}"),
            "inserted values are never expanded again"
        );
    }

    #[test]
    fn rotated_custom_signatures_each_expand_the_value_format_once() {
        let scheme = SigningScheme::Custom(CustomScheme {
            algorithm: Algorithm::Sha512,
            encoding: Encoding::Base64,
            signature_header: "X-Signature".to_string(),
            value_format: "{timestamp}:{signature}".to_string(),
            signed_payload: "{body}".to_string(),
            timestamp_header: None,
            id_header: None,
        });
        let signer = WebhookSigner::new(
            scheme,
            vec![
                Zeroizing::new(b"new".to_vec()),
                Zeroizing::new(b"old".to_vec()),
            ],
        );
        let headers = signer.sign("{timestamp}", at(5), "msg");
        let expected: Vec<String> = [b"new".as_slice(), b"old".as_slice()]
            .iter()
            .map(|key| format!("5:{}", BASE64.encode(hmac_sha512(key, b"{timestamp}"))))
            .collect();
        assert_eq!(headers[0].1, expected.join(" "));
    }

    #[test]
    fn expand_writes_unknown_braces_literally() {
        let mut out = Vec::new();
        expand("{a}{{b}}{a", &[("a", "{b}"), ("b", "B")], |part| {
            out.extend_from_slice(part)
        });
        assert_eq!(String::from_utf8(out).unwrap(), "{b}{B}{a");
    }

    #[test]
    fn custom_emits_optional_timestamp_and_id_headers() {
        let scheme = SigningScheme::Custom(CustomScheme {
            algorithm: Algorithm::Sha512,
            encoding: Encoding::Base64,
            signature_header: "X-Signature".to_string(),
            value_format: "{signature}".to_string(),
            signed_payload: "{id}.{body}".to_string(),
            timestamp_header: Some("X-Signature-Timestamp".to_string()),
            id_header: Some("X-Webhook-Id".to_string()),
        });
        let signer = WebhookSigner::new(scheme, vec![Zeroizing::new(b"k".to_vec())]);
        let headers = signer.sign("{}", at(42), "msg_y");
        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"X-Signature"));
        assert!(names.contains(&"X-Signature-Timestamp"));
        assert!(names.contains(&"X-Webhook-Id"));
        assert_eq!(
            headers.iter().find(|(k, _)| k == "X-Webhook-Id").unwrap().1,
            "msg_y",
        );
    }

    #[test]
    fn standard_rotation_emits_two_space_joined_signatures() {
        let signer = WebhookSigner::new(
            SigningScheme::Standard,
            vec![
                Zeroizing::new(b"new-key".to_vec()),
                Zeroizing::new(b"old-key".to_vec()),
            ],
        );
        let headers = signer.sign("{}", at(10), "msg_1");
        let value = &headers
            .iter()
            .find(|(k, _)| k == "webhook-signature")
            .unwrap()
            .1;
        let parts: Vec<&str> = value.split(' ').collect();
        assert_eq!(parts.len(), 2, "rotation should emit two signatures");
        assert!(parts.iter().all(|p| p.starts_with("v1,")));
        assert_ne!(parts[0], parts[1], "distinct keys, distinct signatures");
    }

    #[test]
    fn signing_is_deterministic_across_calls() {
        let signer =
            WebhookSigner::new(SigningScheme::Standard, vec![Zeroizing::new(b"k".to_vec())]);
        let a = signer.sign("body", at(99), "msg_z");
        let b = signer.sign("body", at(99), "msg_z");
        assert_eq!(
            a, b,
            "same inputs reproduce the same headers (retry safety)"
        );
    }
}
