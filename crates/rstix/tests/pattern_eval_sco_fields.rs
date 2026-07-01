//! Manifest-driven SCO field path evaluation tests.

use std::path::PathBuf;

use rstix::ParseOptions;
use rstix::Pattern;
use rstix::model::Bundle;
use rstix::model::sco::CustomSco;
use serde::Deserialize;

#[path = "support/sco_json.rs"]
mod sco_json;

use sco_json::parse_sco_json;

#[derive(Debug, Deserialize)]
struct ManifestCase {
    id: String,
    pattern: String,
    sco_file: String,
    bundle_file: String,
    expect: bool,
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pattern/sco-fields")
}

fn load_manifest() -> Vec<ManifestCase> {
    let path = fixture_root().join("manifest.json");
    let json = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read manifest `{}`: {e}", path.display()));
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("parse manifest: {e:?}"))
}

#[test]
fn manifest_sco_field_paths_match() {
    let cases = load_manifest();
    assert!(!cases.is_empty(), "manifest must contain at least one case");

    for case in &cases {
        let pattern = Pattern::parse(&case.pattern)
            .unwrap_or_else(|e| panic!("case `{}`: parse failed: {e:?}", case.id));

        let sco_path = fixture_root().join(&case.sco_file);
        let sco_json = std::fs::read_to_string(&sco_path).unwrap_or_else(|e| {
            panic!("case `{}`: read sco `{}`: {e}", case.id, sco_path.display())
        });
        let sco = parse_sco_json(&sco_json);

        let bundle_path = fixture_root().join(&case.bundle_file);
        let bundle_json = std::fs::read_to_string(&bundle_path).unwrap_or_else(|e| {
            panic!(
                "case `{}`: read bundle `{}`: {e}",
                case.id,
                bundle_path.display()
            )
        });
        let bundle = Bundle::parse_with_options(
            &bundle_json,
            &ParseOptions::new().register_custom_type::<CustomSco>("x-usb-device"),
        )
        .unwrap_or_else(|e| panic!("case `{}`: bundle parse: {e:?}", case.id));

        let got = pattern
            .matches_single_with_bundle(&sco, Some(&bundle))
            .unwrap_or_else(|e| panic!("case `{}`: eval failed: {e:?}", case.id));

        assert_eq!(got, case.expect, "case `{}`", case.id);
    }
}
