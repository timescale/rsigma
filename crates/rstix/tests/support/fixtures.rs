//! Load committed STIX spec fixture files from `tests/fixtures/spec/`.

use std::fs;
use std::path::Path;

/// Read a fixture relative to `tests/fixtures/spec/`.
pub fn load_spec_fixture(relative_path: &str) -> String {
    load_fixture_from_dir("spec", relative_path)
}

/// Read a fixture relative to `tests/fixtures/` (for example `validation/bundle-bad-capec.json`).
#[allow(dead_code)]
pub fn load_fixture(relative_path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
        .trim_end()
        .to_owned()
}

fn load_fixture_from_dir(dir: &str, relative_path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(dir)
        .join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
        .trim_end()
        .to_owned()
}
