#![no_main]
//! `email-message` RFC 2047 decoding and the save and reload round trip.
//!
//! Whatever the wire parse accepts must serialize and deserialize to the same
//! object, still validate, and reload unchanged with decoding off, the way
//! `FsStore` reads it back.

use libfuzzer_sys::fuzz_target;
use rstix::model::sco::ScoObject;
use rstix::model::{ParseOptions, StixObject};

fn wire(header: &str, with_enc: bool) -> String {
    let mut message = serde_json::json!({
        "type": "email-message",
        "spec_version": "2.1",
        "id": "email-message--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        "is_multipart": false,
        "subject": header,
        "message_id": header,
        "received_lines": [header, header],
        "additional_header_fields": { "X-Fuzz": [header] },
        "body": header,
    });
    if with_enc {
        message["subject_enc"] = serde_json::json!("UTF-8");
    }
    message.to_string()
}

fn check(json: &str) {
    let stored = ParseOptions::default().decode_email_encoded_words(false);
    let Ok((object, _)) = rstix::parse_object_with_extras_and_options(json, &ParseOptions::default())
    else {
        return;
    };
    if let StixObject::Sco(ScoObject::EmailMessage(message)) = &object {
        message.validate().expect("accepted message validates");
        let encoded = serde_json::to_string(message).expect("serialize");
        let decoded: rstix::model::sco::EmailMessage =
            serde_json::from_str(&encoded).expect("serde round trip");
        assert_eq!(&decoded, message);
        decoded.validate().expect("round-tripped message validates");
    }
    let saved = serde_json::to_string(&object).expect("serialize object");
    let (reloaded, _) =
        rstix::parse_object_with_extras_and_options(&saved, &stored).expect("reload");
    assert_eq!(reloaded, object);
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    match mode % 3 {
        0 => check(&wire(text, false)),
        1 => check(&wire(text, true)),
        _ => check(text),
    }
});
