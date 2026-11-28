//! Integration tests for the `store-fs` feature.

use rstix::parse_bundle;
use rstix::store::{FsStore, StixStore};
use std::fs;

#[test]
fn fs_store_roundtrip_on_disk() {
    let root = std::env::temp_dir().join(format!("rstix-fs-it-{}", uuid::Uuid::new_v4()));
    let _ = fs::remove_dir_all(&root);
    let bundle = parse_bundle(include_str!("fixtures/store/sco-ipv4-minimal.json")).expect("parse");
    {
        let store = FsStore::open(&root).expect("open");
        store.import_bundle(&bundle).expect("import");
    }
    let store = FsStore::open(&root).expect("reopen");
    let sco_id = bundle.objects()[0].id().clone();
    assert!(store.get(&sco_id).expect("get").is_some());
    let _ = fs::remove_dir_all(&root);
}

/// Real-world RFC 2047 headers: Latin-1 and UTF-8, Q and B, adjacent words,
/// ISO-2022-JP, and an encoded-word inside a `Received` comment.
const WIRE_HEADERS: &[&str] = &[
    "=?ISO-8859-1?Q?Andr=E9?= Pirard <PIRARD@vm1.ulg.ac.be>",
    "=?UTF-8?B?8J+UpSBVcmdlbnQ6IGludm9pY2Ugb3ZlcmR1ZQ==?=",
    "=?UTF-8?Q?Re=3A_Quarterly_r=C3=A9sum=C3=A9?= =?UTF-8?Q?_draft?=",
    "=?iso-2022-jp?B?GyRCJUYlOSVIGyhC?=",
    "from mx.example.net (=?UTF-8?Q?m=C3=BCnchen?= relay) by mail.example.org",
    "Plain subject, no encoded words",
];

/// Values that decode to text that itself looks like an encoded-word, or to nothing.
const NESTED_HEADERS: &[&str] = &[
    "=?UTF-8?Q?=3D=3FUTF-8=3FQ=3Fhello=3F=3D?=",
    "=?UTF-8?B?PT9VVEYtOD9CP2FHVnNiRzg9Pz0=?=",
    "=?UTF-8?Q?=3D=3FUTF-8=3FQ=3F=3F=3D?=",
];

fn email_wire(header: &str, with_enc: bool) -> String {
    let mut message = serde_json::json!({
        "type": "email-message",
        "spec_version": "2.1",
        "id": format!("email-message--{}", uuid::Uuid::new_v4()),
        "is_multipart": false,
        "subject": header,
        "message_id": header,
        "received_lines": [header],
        "additional_header_fields": { "X-Original-Subject": [header] },
        "body": header,
    });
    if with_enc {
        message["subject_enc"] = serde_json::json!("UTF-8");
    }
    message.to_string()
}

#[test]
fn email_message_round_trips_through_serde_and_the_fs_store() {
    use rstix::model::StixObject;
    use rstix::model::sco::ScoObject;

    let root = std::env::temp_dir().join(format!("rstix-fs-email-{}", uuid::Uuid::new_v4()));
    let mut accepted = Vec::new();
    for header in WIRE_HEADERS.iter().chain(NESTED_HEADERS) {
        for with_enc in [false, true] {
            let wire = email_wire(header, with_enc);
            let Ok(object) = rstix::parse_object(&wire) else {
                continue;
            };
            let StixObject::Sco(ScoObject::EmailMessage(message)) = &object else {
                panic!("not an email-message: {object:?}");
            };
            assert_eq!(
                message.body.as_deref(),
                Some(*header),
                "body is content, not a header"
            );
            message.validate().expect("accepted message validates");

            let json = serde_json::to_string(message).expect("serialize");
            let again: rstix::model::sco::EmailMessage =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&again, message, "serde round trip of {header}");
            again.validate().expect("round-tripped message validates");
            accepted.push(object);
        }
    }
    assert_eq!(
        accepted.len(),
        2 * (WIRE_HEADERS.len() + NESTED_HEADERS.len()),
        "every sample is accepted on the wire"
    );

    {
        let store = FsStore::open(&root).expect("open");
        store.import_objects(&accepted).expect("store");
    }
    let store = FsStore::open(&root).expect("reopen");
    store.reload_from_disk().expect("reload");
    for object in &accepted {
        assert_eq!(
            store.get(object.id()).unwrap().as_ref(),
            Some(object),
            "store round trip of {}",
            object.id()
        );
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn wire_decoding_is_one_level_and_can_be_turned_off() {
    use rstix::model::sco::ScoObject;
    use rstix::model::{ParseOptions, StixObject};

    let subject = |object: StixObject| match object {
        StixObject::Sco(ScoObject::EmailMessage(message)) => message.subject.unwrap(),
        other => panic!("{other:?}"),
    };
    let wire = email_wire(NESTED_HEADERS[0], true);
    let decoded = rstix::parse_object(&wire).expect("wire");
    assert_eq!(subject(decoded.clone()), "=?UTF-8?Q?hello?=");

    let raw = rstix::parse_object_with_extras_and_options(
        &wire,
        &ParseOptions::default().decode_email_encoded_words(false),
    )
    .expect("raw")
    .0;
    assert_eq!(subject(raw), NESTED_HEADERS[0]);

    let stored = serde_json::to_string(&decoded).unwrap();
    let reloaded = rstix::parse_object_with_extras_and_options(
        &stored,
        &ParseOptions::default().decode_email_encoded_words(false),
    )
    .expect("reload")
    .0;
    assert_eq!(reloaded, decoded);
}

#[test]
fn encoded_words_that_decode_to_nothing_beside_an_enc_sibling_are_rejected_on_the_wire() {
    let err = rstix::parse_object(&email_wire("=?UTF-8?Q??=", true)).expect_err("empty subject");
    assert!(err.to_string().contains("subject_enc"), "{err}");
}
