//! Data Model + Serialization acceptance tests (streaming, custom types, large bundles).

#![cfg(feature = "serde")]

mod integration {
    use std::io::Cursor;

    use rstix::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
    use rstix::model::BundleObjectCast;
    use rstix::model::{Bundle, StixObject};
    use rstix::{ParseOptions, QueryableContainer, parse_bundle};

    #[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
    struct XMyCustomSdo {
        #[serde(rename = "type")]
        object_type: String,
        id: StixId,
        spec_version: SpecVersion,
        created: StixTimestamp,
        modified: StixTimestamp,
        name: String,
    }

    impl QueryableStixObject for XMyCustomSdo {
        fn id(&self) -> &StixId {
            &self.id
        }

        fn type_name(&self) -> &'static str {
            "x-my-custom-sdo"
        }

        fn spec_version(&self) -> Option<SpecVersion> {
            Some(self.spec_version)
        }

        fn created(&self) -> Option<&StixTimestamp> {
            Some(&self.created)
        }

        fn modified(&self) -> Option<&StixTimestamp> {
            Some(&self.modified)
        }

        fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
            match path {
                ["name"] => Some(QueryValue::Str(&self.name)),
                _ => None,
            }
        }
    }

    impl BundleObjectCast for XMyCustomSdo {
        fn cast_from(object: &StixObject) -> Option<&Self> {
            match object {
                StixObject::Custom(custom) => custom.downcast_typed(),
                _ => None,
            }
        }
    }

    fn custom_object_json() -> String {
        r#"{
          "type": "bundle",
          "id": "bundle--00000000-0000-0000-0000-000000000001",
          "objects": [
            {
              "type": "x-my-custom-sdo",
              "id": "x-my-custom-sdo--00000000-0000-0000-0000-000000000002",
              "spec_version": "2.1",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "name": "custom example"
            }
          ]
        }"#
        .to_owned()
    }

    #[test]
    fn custom_type_round_trips_with_registry() {
        let opts = ParseOptions::new().register_custom_type::<XMyCustomSdo>("x-my-custom-sdo");
        let bundle =
            Bundle::parse_with_options(&custom_object_json(), &opts).expect("parse custom bundle");
        let id = StixId::parse("x-my-custom-sdo--00000000-0000-0000-0000-000000000002").unwrap();
        let custom = bundle.get_typed::<XMyCustomSdo>(&id).expect("typed lookup");
        assert_eq!(custom.name, "custom example");

        let serialized = serde_json::to_string(&bundle).expect("serialize");
        let reparsed = Bundle::parse_with_options(&serialized, &opts).expect("reparse");
        assert_eq!(reparsed.objects().len(), 1);
        assert_eq!(
            reparsed
                .get_typed::<XMyCustomSdo>(&id)
                .map(|value| value.name.as_str()),
            Some("custom example")
        );
    }

    #[test]
    fn custom_type_registry_is_scoped_per_parse_options() {
        let json = custom_object_json();
        let with_registry =
            ParseOptions::new().register_custom_type::<XMyCustomSdo>("x-my-custom-sdo");
        assert!(Bundle::parse_with_options(&json, &with_registry).is_ok());

        let without_registry = ParseOptions::new();
        assert!(Bundle::parse_with_options(&json, &without_registry).is_err());
    }

    fn synthetic_large_bundle(object_count: usize) -> Vec<u8> {
        let mut json = String::from(
            r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000099","objects":["#,
        );
        for index in 0..object_count {
            if index > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                r#"{{"type":"identity","spec_version":"2.1","id":"identity--{index:08x}-0000-4000-8000-{index:012x}","created":"2016-05-12T08:17:27.000Z","modified":"2016-05-12T08:17:27.000Z","name":"org-{index}","identity_class":"organization"}}"#
            ));
        }
        json.push_str("]}");
        json.into_bytes()
    }

    #[test]
    fn attck_streaming_parses_large_bundle_via_reader() {
        const OBJECT_COUNT: usize = 5_000;
        let payload = synthetic_large_bundle(OBJECT_COUNT);
        assert!(
            payload.len() > 1_000_000,
            "synthetic corpus should exceed 1 MiB"
        );

        let bundle = Bundle::parse_reader(Cursor::new(&payload)).expect("stream parse");
        assert_eq!(bundle.object_count(), OBJECT_COUNT);
    }

    #[test]
    fn attck_roundtrip_parse_serialize_reparse() {
        const OBJECT_COUNT: usize = 250;
        let payload = synthetic_large_bundle(OBJECT_COUNT);
        let bundle = parse_bundle(std::str::from_utf8(&payload).expect("utf8")).expect("parse");
        let serialized = serde_json::to_string(&bundle).expect("serialize");
        let reparsed = parse_bundle(&serialized).expect("reparse");
        assert_eq!(reparsed.object_count(), OBJECT_COUNT);
    }

    #[test]
    fn attck_corpus_roundtrip_when_present() {
        let path = std::env::var("RSTIX_ATTCK_BUNDLE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from("tests/fixtures/corpus/enterprise-attack.json")
            });
        if !path.is_file() {
            eprintln!(
                "skip attck_corpus_roundtrip_when_present: set RSTIX_ATTCK_BUNDLE (e.g. enterprise-attack-19.1.json) or place bundle at {}",
                path.display()
            );
            return;
        }

        use std::fs::File;
        use std::io::BufReader;

        let file = File::open(&path).expect("open ATT&CK bundle");
        let bundle = Bundle::parse_reader(BufReader::new(file)).expect("parse ATT&CK bundle");
        assert!(bundle.object_count() > 1_000);
        let serialized = serde_json::to_string(&bundle).expect("serialize");
        let reparsed = parse_bundle(&serialized).expect("reparse");
        assert_eq!(reparsed.object_count(), bundle.object_count());
    }
}
