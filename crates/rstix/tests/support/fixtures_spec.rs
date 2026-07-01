//! Load STIX spec fixtures from `tests/fixtures/spec/`.

use std::fs;
use std::path::Path;

/// Read a fixture relative to `tests/fixtures/spec/`.
pub fn load_spec_fixture(relative_path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/spec")
        .join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
        .trim_end()
        .to_owned()
}
